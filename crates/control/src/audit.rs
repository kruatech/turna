//! Tamper-evident audit log for privileged management operations.
//!
//! Every privileged gRPC admin RPC — `add_user`, `remove_user`,
//! `delete_allocation`, `update_config`, `set_draining`, `shutdown` — appends
//! exactly one entry (on success *and* on failure). Entries form a keyed hash
//! chain:
//!
//! ```text
//! entry_mac = HMAC-SHA256(key, seq ‖ ts_ms ‖ actor ‖ action ‖ detail ‖ outcome ‖ prev_mac)
//! ```
//!
//! When an HMAC key is configured (supplied out-of-band — e.g. a secret / env
//! var — and never written to the log), the chain is *tamper-evident against an
//! attacker with write access to the files*: without the key they cannot
//! recompute a consistent chain after altering an entry. Without a key the
//! chain degrades to a plain SHA-256 integrity log (detects accidental
//! corruption, NOT a privileged attacker) and a warning is emitted at startup.
//!
//! On [`open`](AuditLog::open) the full on-disk chain (all rotated segments plus
//! the live file) is verified; any break or malformed line fails the open
//! (fail-closed) instead of silently trusting altered history. Each entry is
//! also emitted on the `audit` tracing target, so an external collector holds
//! the chain independently.
//!
//! Security note: `detail` MUST NOT contain secrets (passwords, keys).

use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use turna_crypto::{hmac_sha256, sha256};
use turna_state_backend::now_ms;

/// Field separator folded into the hashed pre-image for domain separation.
const SEP: u8 = 0x1f;

/// All-zero hash that precedes the first entry (chain genesis).
const GENESIS: [u8; 32] = [0u8; 32];

/// Default rotation threshold for a persistent audit file (64 MiB).
const AUDIT_FILE_MAX_BYTES: u64 = 64 * 1024 * 1024;

/// Default number of rotated audit segments to retain (older are pruned).
const AUDIT_MAX_SEGMENTS: usize = 10;

/// One immutable audit record.
#[derive(Clone, Debug)]
pub struct AuditEntry {
    /// 1-based, strictly increasing sequence number.
    pub seq: u64,
    /// Wall-clock time (ms since the UNIX epoch) the entry was recorded.
    pub ts_ms: u64,
    /// Who invoked the operation (mTLS cert fingerprint or peer address).
    pub actor: String,
    /// The privileged operation (e.g. `"add_user"`).
    pub action: String,
    /// Non-secret parameters / identifiers for the operation.
    pub detail: String,
    /// `true` if the operation succeeded, `false` if it was rejected/failed.
    pub outcome: bool,
    /// Chain hash of the previous entry.
    pub prev_hash: [u8; 32],
    /// Chain hash of this entry (keyed HMAC or plain SHA-256).
    pub entry_hash: [u8; 32],
}

/// Lowercase-hex rendering of a 32-byte hash.
pub fn hex32(b: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for byte in b {
        s.push_str(&format!("{byte:02x}"));
    }
    s
}

/// Parse exactly 64 hex chars into a 32-byte hash. `None` on malformed input.
fn hex_to_32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

/// Decode a hex string into bytes (audit HMAC key from config/env). `None` on
/// empty, odd-length, or non-hex input.
pub fn parse_hex_key(s: &str) -> Option<Vec<u8>> {
    if s.is_empty() || !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// Chain hash over the domain-separated pre-image: keyed HMAC-SHA256 when a key
/// is configured, otherwise plain SHA-256.
#[allow(clippy::too_many_arguments)]
fn compute_chain(
    key: Option<&[u8]>,
    seq: u64,
    ts_ms: u64,
    actor: &str,
    action: &str,
    detail: &str,
    outcome: bool,
    prev: &[u8; 32],
) -> [u8; 32] {
    let mut buf = Vec::with_capacity(8 + 8 + actor.len() + action.len() + detail.len() + 32 + 8);
    buf.extend_from_slice(&seq.to_be_bytes());
    buf.extend_from_slice(&ts_ms.to_be_bytes());
    buf.push(SEP);
    buf.extend_from_slice(actor.as_bytes());
    buf.push(SEP);
    buf.extend_from_slice(action.as_bytes());
    buf.push(SEP);
    buf.extend_from_slice(detail.as_bytes());
    buf.push(SEP);
    buf.push(outcome as u8);
    buf.push(SEP);
    buf.extend_from_slice(prev);
    match key {
        Some(k) => hmac_sha256(k, &buf),
        None => sha256(&buf),
    }
}

/// Append-only file sink with size-based rotation and segment retention. The
/// in-memory chain head (`seq` / `last_hash`) is independent of the file, so
/// entries written after a rotation still link to the previous segment's last
/// entry. Rotated segments are named by the last seq they contain, which is
/// globally unique and monotonic across restarts (no name collision, no
/// overwrite).
struct Persist {
    file: File,
    path: PathBuf,
    bytes: u64,
    max_bytes: u64,
    /// Keep at most this many rotated segments (0 = keep all).
    max_segments: usize,
}

impl Persist {
    /// Durably append one JSON line (rotating if oversized). Returns `false` if
    /// the write, the fsync, OR a rotation reopen failed — the caller marks the
    /// log unhealthy (fail-closed). An ignored fsync would let a crash lose an
    /// entry the caller believed durable, so its result is checked too.
    fn append(&mut self, line: &str, seq: u64) -> bool {
        if writeln!(self.file, "{line}").is_err() {
            tracing::error!(target: "audit", "failed to persist audit entry");
            return false;
        }
        if let Err(e) = self.file.sync_data() {
            tracing::error!(target: "audit", error = %e, "audit fsync failed");
            return false;
        }
        self.bytes += line.len() as u64 + 1;
        // A rotation that cannot reopen the live file leaves the sink unable to
        // durably append going forward: propagate as failure so it is marked
        // unhealthy (the just-written entry is already fsynced, so it is safe).
        self.maybe_rotate(seq)
    }

    /// Returns `false` only if rotation was attempted but the live file could not
    /// be reopened (future appends would be lost). A skipped or rename-failed
    /// rotation still leaves the current file writable, so it returns `true`.
    fn maybe_rotate(&mut self, seq: u64) -> bool {
        if self.bytes < self.max_bytes {
            return true;
        }
        // Name the closed segment by its last seq: unique and monotonic even
        // across restarts, so no segment is ever overwritten.
        let rotated = format!("{}.{:020}", self.path.display(), seq);
        if std::fs::rename(&self.path, &rotated).is_err() {
            // Live file is intact and still writable — skip rotation this round.
            tracing::error!(target: "audit", "audit rotation: rename failed");
            return true;
        }
        match OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
        {
            Ok(nf) => {
                self.file = nf;
                self.bytes = 0;
                tracing::info!(target: "audit", rotated = %rotated, "audit log rotated");
                self.prune_segments();
                true
            }
            Err(e) => {
                // Old file renamed away, cannot open a new one: the sink can no
                // longer durably append — fail closed.
                tracing::error!(target: "audit", error = %e, "audit rotation: reopen failed");
                false
            }
        }
    }

    /// Delete the oldest rotated segments (lowest seq) beyond `max_segments`.
    fn prune_segments(&self) {
        if self.max_segments == 0 {
            return;
        }
        let (Some(dir), Some(fname)) = (
            self.path.parent(),
            self.path.file_name().and_then(|s| s.to_str()),
        ) else {
            return;
        };
        let prefix = format!("{fname}.");
        let mut segs: Vec<(u128, PathBuf)> = Vec::new();
        if let Ok(rd) = std::fs::read_dir(dir) {
            for e in rd.flatten() {
                let name = e.file_name();
                let Some(name) = name.to_str() else {
                    continue;
                };
                if let Some(suffix) = name.strip_prefix(&prefix) {
                    segs.push((seg_key(suffix), e.path()));
                }
            }
        }
        if segs.len() <= self.max_segments {
            return;
        }
        segs.sort_by_key(|(k, _)| *k);
        let remove = segs.len() - self.max_segments;
        for (_, p) in segs.into_iter().take(remove) {
            let _ = std::fs::remove_file(&p);
        }
    }
}

struct Inner {
    seq: u64,
    last_hash: [u8; 32],
    ring: VecDeque<AuditEntry>,
    cap: usize,
    persist: Option<Persist>,
    /// HMAC key for the chain; `None` = plain SHA-256 (integrity-only).
    mac_key: Option<Vec<u8>>,
}

/// Append-only, hash-chained audit log with a bounded in-memory tail and
/// optional keyed (tamper-evident) persistence.
pub struct AuditLog {
    inner: Mutex<Inner>,
    /// Set when a persistent write fails; privileged callers can consult
    /// [`is_healthy`](AuditLog::is_healthy) to fail closed.
    degraded: AtomicBool,
}

/// Why opening a persistent audit log failed.
#[derive(Debug)]
pub enum AuditOpenError {
    /// Filesystem error creating/reading the log.
    Io(String),
    /// The existing on-disk chain failed verification (fail-closed).
    Corrupt(AuditVerifyError),
}

/// Summary of a successful on-disk chain verification.
#[derive(Debug, Clone)]
pub struct PersistedAudit {
    /// Segment files read (rotated segments + the live file).
    pub segments: usize,
    /// Total entries verified across all segments.
    pub entries: u64,
    /// First seq present (may be > 1 if early segments were pruned).
    pub first_seq: u64,
    /// Last seq present.
    pub last_seq: u64,
}

/// Why an on-disk verification failed.
#[derive(Debug)]
pub enum AuditVerifyError {
    /// Filesystem error while reading a segment.
    Io(String),
    /// A line could not be parsed as an audit entry.
    Malformed { file: String, line: usize },
    /// The chain is broken at this seq: hash mismatch (tampering or wrong key),
    /// a removed entry, or a seq discontinuity within the retained range.
    ChainBreak { seq: u64 },
}

/// Result of replaying + verifying a set of segment files.
struct Replayed {
    seq: u64,
    last_hash: [u8; 32],
    ring: VecDeque<AuditEntry>,
    entries: u64,
    first_seq: u64,
    last_seq: u64,
}

impl AuditLog {
    /// In-memory log (no persistence, plain SHA-256 chain). For dev / tests.
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Mutex::new(Inner {
                seq: 0,
                last_hash: GENESIS,
                ring: VecDeque::with_capacity(capacity.min(1024)),
                cap: capacity.max(1),
                persist: None,
                mac_key: None,
            }),
            degraded: AtomicBool::new(false),
        }
    }

    /// Attach an HMAC key to an in-memory log (keyed chain). Mainly for tests;
    /// persistent logs take the key via [`open`](AuditLog::open).
    pub fn with_hmac_key(self, key: Vec<u8>) -> Self {
        {
            let mut g = self
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            g.mac_key = Some(key);
        }
        self
    }

    /// Open a persistent log with default rotation (64 MiB / 10 segments). See
    /// [`open_with_rotation`](AuditLog::open_with_rotation).
    pub fn open(
        capacity: usize,
        path: impl AsRef<Path>,
        key: Option<Vec<u8>>,
    ) -> Result<Self, AuditOpenError> {
        Self::open_with_rotation(
            capacity,
            path,
            AUDIT_FILE_MAX_BYTES,
            AUDIT_MAX_SEGMENTS,
            key,
        )
    }

    /// Open a persistent, keyed, hash-chained log with explicit rotation size
    /// and segment retention. The full existing on-disk chain (all rotated
    /// segments + live file) is replayed and **verified**; any break or
    /// malformed line returns [`AuditOpenError::Corrupt`] (fail-closed). State
    /// (`seq` / `last_hash`) resumes from the true on-disk tail across segments,
    /// so a restart right after a rotation (empty live file) does not reset the
    /// chain. `key = None` yields a plain SHA-256 (integrity-only) chain.
    pub fn open_with_rotation(
        capacity: usize,
        path: impl AsRef<Path>,
        max_bytes: u64,
        max_segments: usize,
        key: Option<Vec<u8>>,
    ) -> Result<Self, AuditOpenError> {
        let path = path.as_ref();
        let cap = capacity.max(1);
        let files = collect_segments(path).map_err(|e| AuditOpenError::Io(e.to_string()))?;
        let replayed = replay(&files, key.as_deref(), cap).map_err(AuditOpenError::Corrupt)?;
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| AuditOpenError::Io(e.to_string()))?;
        let bytes = file.metadata().map(|m| m.len()).unwrap_or(0);
        Ok(Self {
            inner: Mutex::new(Inner {
                seq: replayed.seq,
                last_hash: replayed.last_hash,
                ring: replayed.ring,
                cap,
                persist: Some(Persist {
                    file,
                    path: path.to_path_buf(),
                    bytes,
                    max_bytes: max_bytes.max(1),
                    max_segments,
                }),
                mac_key: key,
            }),
            degraded: AtomicBool::new(false),
        })
    }

    /// Record one privileged operation (best-effort persistence). `detail` must
    /// not contain secrets.
    pub fn record(&self, actor: &str, action: &str, detail: impl Into<String>, ok: bool) {
        let _ = self.record_inner(actor, action, detail.into(), ok);
    }

    /// Record an entry and report whether it was made durable. Returns `true`
    /// when there is no persistent sink (in-memory only) or the on-disk append +
    /// fsync succeeded; `false` when a configured sink failed to persist it (the
    /// log is also marked degraded). Privileged callers record a durable *intent*
    /// with this BEFORE performing an effect and refuse the effect on `false`,
    /// closing the window where an action runs but its audit record is lost.
    pub fn record_checked(&self, actor: &str, action: &str, detail: &str, ok: bool) -> bool {
        self.record_inner(actor, action, detail.to_string(), ok)
    }

    fn record_inner(&self, actor: &str, action: &str, detail: String, ok: bool) -> bool {
        let mut g = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let seq = g.seq + 1;
        let ts_ms = now_ms();
        let prev = g.last_hash;
        let entry_hash = compute_chain(
            g.mac_key.as_deref(),
            seq,
            ts_ms,
            actor,
            action,
            &detail,
            ok,
            &prev,
        );

        tracing::info!(
            target: "audit",
            seq,
            ts_ms,
            actor,
            action,
            detail = %detail,
            outcome = ok,
            prev = %hex32(&prev),
            hash = %hex32(&entry_hash),
            "management audit"
        );

        let entry = AuditEntry {
            seq,
            ts_ms,
            actor: actor.to_string(),
            action: action.to_string(),
            detail,
            outcome: ok,
            prev_hash: prev,
            entry_hash,
        };
        let mut persisted = true;
        if let Some(p) = g.persist.as_mut() {
            let line = serde_json::json!({
                "seq": entry.seq,
                "ts_ms": entry.ts_ms,
                "actor": entry.actor,
                "action": entry.action,
                "detail": entry.detail,
                "outcome": entry.outcome,
                "prev": hex32(&entry.prev_hash),
                "hash": hex32(&entry.entry_hash),
            })
            .to_string();
            if !p.append(&line, seq) {
                // Persistence broke: mark unhealthy so privileged callers can
                // fail closed rather than proceed with an incomplete disk chain.
                self.degraded.store(true, Ordering::SeqCst);
                persisted = false;
            }
        }
        g.seq = seq;
        g.last_hash = entry_hash;
        if g.ring.len() == g.cap {
            g.ring.pop_front();
        }
        g.ring.push_back(entry);
        persisted
    }

    /// Re-verify the retained in-memory tail (keyed). Returns entries checked, or
    /// the `seq` of the first broken entry.
    pub fn verify(&self) -> Result<usize, u64> {
        let g = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let key = g.mac_key.as_deref();
        let mut prev = g.ring.front().map(|e| e.prev_hash).unwrap_or(GENESIS);
        for e in &g.ring {
            if e.prev_hash != prev {
                return Err(e.seq);
            }
            let recomputed = compute_chain(
                key,
                e.seq,
                e.ts_ms,
                &e.actor,
                &e.action,
                &e.detail,
                e.outcome,
                &e.prev_hash,
            );
            if recomputed != e.entry_hash {
                return Err(e.seq);
            }
            prev = e.entry_hash;
        }
        Ok(g.ring.len())
    }

    /// `false` after a persistent write has failed; callers may fail closed.
    pub fn is_healthy(&self) -> bool {
        !self.degraded.load(Ordering::SeqCst)
    }

    /// Entries currently retained in memory.
    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .ring
            .len()
    }

    /// `true` if no entries are retained in memory.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Total entries ever recorded (chain head seq), regardless of retention.
    pub fn total_recorded(&self) -> u64 {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .seq
    }

    /// Snapshot of the retained tail, oldest first.
    pub fn snapshot(&self) -> Vec<AuditEntry> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .ring
            .iter()
            .cloned()
            .collect()
    }

    /// Path of the backing file when persistence is enabled (else `None`).
    pub fn persisted_path(&self) -> Option<PathBuf> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .persist
            .as_ref()
            .map(|p| p.path.clone())
    }

    /// Verify the complete on-disk chain (all rotated segments + live file) with
    /// the given key. See [`open_with_rotation`](AuditLog::open_with_rotation)
    /// for the guarantees. Usable offline (no running instance).
    pub fn verify_persisted(
        path: impl AsRef<Path>,
        key: Option<&[u8]>,
    ) -> Result<PersistedAudit, AuditVerifyError> {
        let path = path.as_ref();
        let files = collect_segments(path).map_err(|e| AuditVerifyError::Io(e.to_string()))?;
        let r = replay(&files, key, 0)?;
        Ok(PersistedAudit {
            segments: files.len(),
            entries: r.entries,
            first_seq: r.first_seq,
            last_seq: r.last_seq,
        })
    }

    /// Verify this log's own on-disk chain using its configured key. `None` when
    /// persistence is disabled.
    pub fn verify_persisted_self(&self) -> Option<Result<PersistedAudit, AuditVerifyError>> {
        let (path, key) = {
            let g = self
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let path = g.persist.as_ref().map(|p| p.path.clone())?;
            (path, g.mac_key.clone())
        };
        Some(Self::verify_persisted(&path, key.as_deref()))
    }
}

/// Order key for a rotated-segment suffix (the zero-padded last seq).
fn seg_key(suffix: &str) -> u128 {
    suffix.parse::<u128>().unwrap_or(0)
}

/// All segment files for `path`, oldest first (by seq), with the live file last.
fn collect_segments(path: &Path) -> std::io::Result<Vec<PathBuf>> {
    let dir = path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let fname = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or_default();
    let prefix = format!("{fname}.");
    let mut rotated: Vec<(u128, PathBuf)> = Vec::new();
    if dir.exists() {
        for e in std::fs::read_dir(&dir)? {
            let e = e?;
            let name = e.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if let Some(suffix) = name.strip_prefix(&prefix) {
                rotated.push((seg_key(suffix), e.path()));
            }
        }
    }
    rotated.sort_by_key(|(k, _)| *k);
    let mut files: Vec<PathBuf> = rotated.into_iter().map(|(_, p)| p).collect();
    if path.exists() {
        files.push(path.to_path_buf());
    }
    Ok(files)
}

/// Read + verify the chain across `files` (in order). Fail-closed: any malformed
/// line or chain break returns an error. Retains the last `cap` entries in a
/// ring (`cap = 0` retains none). Verification starts from the earliest
/// *retained* entry, so a legitimately pruned prefix is not a break.
fn replay(files: &[PathBuf], key: Option<&[u8]>, cap: usize) -> Result<Replayed, AuditVerifyError> {
    let mut prev = GENESIS;
    let mut expected: Option<u64> = None;
    let mut resume_seq = 0u64;
    let mut last_hash = GENESIS;
    let mut entries = 0u64;
    let mut first_seq = 0u64;
    let mut last_seq = 0u64;
    let mut ring: VecDeque<AuditEntry> = VecDeque::new();
    for f in files {
        let file = File::open(f).map_err(|e| AuditVerifyError::Io(e.to_string()))?;
        for (idx, line) in BufReader::new(file).lines().enumerate() {
            let line = line.map_err(|e| AuditVerifyError::Io(e.to_string()))?;
            if line.trim().is_empty() {
                continue;
            }
            let malformed = || AuditVerifyError::Malformed {
                file: f.display().to_string(),
                line: idx + 1,
            };
            let v: serde_json::Value = serde_json::from_str(&line).map_err(|_| malformed())?;
            let (
                Some(seq),
                Some(ts_ms),
                Some(actor),
                Some(action),
                Some(detail),
                Some(outcome),
                Some(prev_s),
                Some(hash_s),
            ) = (
                v.get("seq").and_then(serde_json::Value::as_u64),
                v.get("ts_ms").and_then(serde_json::Value::as_u64),
                v.get("actor").and_then(serde_json::Value::as_str),
                v.get("action").and_then(serde_json::Value::as_str),
                v.get("detail").and_then(serde_json::Value::as_str),
                v.get("outcome").and_then(serde_json::Value::as_bool),
                v.get("prev").and_then(serde_json::Value::as_str),
                v.get("hash").and_then(serde_json::Value::as_str),
            )
            else {
                return Err(malformed());
            };
            let (Some(prev_hash), Some(entry_hash)) = (hex_to_32(prev_s), hex_to_32(hash_s)) else {
                return Err(malformed());
            };
            if let Some(exp) = expected {
                if seq != exp {
                    return Err(AuditVerifyError::ChainBreak { seq });
                }
            } else {
                first_seq = seq;
            }
            if entries > 0 && prev_hash != prev {
                return Err(AuditVerifyError::ChainBreak { seq });
            }
            let recomputed =
                compute_chain(key, seq, ts_ms, actor, action, detail, outcome, &prev_hash);
            if recomputed != entry_hash {
                return Err(AuditVerifyError::ChainBreak { seq });
            }
            prev = entry_hash;
            expected = Some(seq + 1);
            last_seq = seq;
            resume_seq = seq;
            last_hash = entry_hash;
            entries += 1;
            if cap > 0 {
                let entry = AuditEntry {
                    seq,
                    ts_ms,
                    actor: actor.to_string(),
                    action: action.to_string(),
                    detail: detail.to_string(),
                    outcome,
                    prev_hash,
                    entry_hash,
                };
                if ring.len() == cap {
                    ring.pop_front();
                }
                ring.push_back(entry);
            }
        }
    }
    Ok(Replayed {
        seq: resume_seq,
        last_hash,
        ring,
        entries,
        first_seq,
        last_seq,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!("turna_audit_{tag}_{}.log", std::process::id()))
    }

    fn cleanup(path: &Path) {
        let stem = path.file_name().unwrap().to_string_lossy().to_string();
        if let Ok(rd) = std::fs::read_dir(path.parent().unwrap()) {
            for e in rd.flatten() {
                if e.file_name().to_string_lossy().starts_with(&stem) {
                    let _ = std::fs::remove_file(e.path());
                }
            }
        }
    }

    #[test]
    fn intact_chain_verifies() {
        let log = AuditLog::new(16);
        log.record("10.0.0.1:5000", "add_user", "user=alice realm=x", true);
        log.record(
            "10.0.0.1:5000",
            "delete_allocation",
            "id=42 reason=cleanup",
            true,
        );
        log.record("10.0.0.2:6000", "shutdown", "node=n1 graceful=true", false);
        assert_eq!(log.verify(), Ok(3));
        assert_eq!(log.total_recorded(), 3);
    }

    #[test]
    fn tampering_with_an_entry_is_detected() {
        let log = AuditLog::new(16);
        log.record("a:1", "add_user", "user=alice", true);
        log.record("a:1", "add_user", "user=bob", true);
        log.record("a:1", "remove_user", "user=alice force=false", true);
        {
            let mut g = log.inner.lock().unwrap();
            g.ring[1].detail = "user=mallory".to_string();
        }
        assert_eq!(log.verify(), Err(2));
    }

    #[test]
    fn dropping_an_entry_breaks_the_link() {
        let log = AuditLog::new(16);
        log.record("a:1", "add_user", "user=alice", true);
        log.record("a:1", "add_user", "user=bob", true);
        log.record("a:1", "add_user", "user=carol", true);
        {
            let mut g = log.inner.lock().unwrap();
            g.ring.remove(1);
        }
        assert_eq!(log.verify(), Err(3));
    }

    #[test]
    fn eviction_keeps_the_tail_verifiable() {
        let log = AuditLog::new(2);
        for i in 0..5 {
            log.record("a:1", "add_user", format!("user=u{i}"), true);
        }
        assert_eq!(log.len(), 2);
        assert_eq!(log.verify(), Ok(2));
        assert_eq!(log.total_recorded(), 5);
    }

    #[test]
    fn persistence_resumes_chain_across_restart() {
        let path = temp_path("resume");
        cleanup(&path);
        {
            let log = AuditLog::open(16, &path, None).expect("open");
            log.record("a:1", "add_user", "user=alice", true);
            log.record("a:1", "add_user", "user=bob", true);
            assert_eq!(log.total_recorded(), 2);
        }
        {
            let log = AuditLog::open(16, &path, None).expect("reopen");
            assert_eq!(log.total_recorded(), 2);
            assert_eq!(log.verify(), Ok(2));
            log.record("a:1", "shutdown", "node=n1", true);
            assert_eq!(log.total_recorded(), 3);
            assert_eq!(log.verify(), Ok(3));
        }
        cleanup(&path);
    }

    #[test]
    fn rotation_preserves_chain_continuity() {
        let path = temp_path("rot");
        cleanup(&path);
        let log = AuditLog::open_with_rotation(64, &path, 200, 10, None).expect("open");
        for i in 0..20 {
            log.record("10.0.0.1:5000", "add_user", format!("user=u{i}"), true);
        }
        assert_eq!(log.total_recorded(), 20);
        assert!(log.verify().is_ok());
        let prefix = format!("{}.", path.file_name().unwrap().to_string_lossy());
        let segments = std::fs::read_dir(path.parent().unwrap())
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with(&prefix))
            .count();
        assert!(
            segments >= 1,
            "expected >=1 rotated segment, got {segments}"
        );
        cleanup(&path);
    }

    #[test]
    fn rotation_retains_only_recent_segments() {
        let path = temp_path("ret");
        let prefix = format!("{}.", path.file_name().unwrap().to_string_lossy());
        let count_segments = || {
            std::fs::read_dir(path.parent().unwrap())
                .map(|rd| {
                    rd.flatten()
                        .filter(|e| e.file_name().to_string_lossy().starts_with(&prefix))
                        .count()
                })
                .unwrap_or(0)
        };
        cleanup(&path);
        let log = AuditLog::open_with_rotation(64, &path, 150, 2, None).expect("open");
        for i in 0..60 {
            log.record("a:1", "add_user", format!("user=u{i}"), true);
        }
        assert!(
            count_segments() <= 2,
            "retention cap exceeded: {}",
            count_segments()
        );
        assert_eq!(log.total_recorded(), 60);
        assert!(log.verify().is_ok());
        cleanup(&path);
    }

    #[test]
    fn verify_persisted_checks_whole_chain_and_detects_tampering() {
        let path = temp_path("vp");
        let stem = path.file_name().unwrap().to_string_lossy().to_string();
        cleanup(&path);
        {
            let log = AuditLog::open_with_rotation(8, &path, 150, 0, None).expect("open");
            for i in 0..30 {
                log.record("a:1", "add_user", format!("user=u{i}"), true);
            }
        }
        let v = AuditLog::verify_persisted(&path, None).expect("intact chain");
        assert_eq!(v.entries, 30);
        assert_eq!(v.first_seq, 1);
        assert_eq!(v.last_seq, 30);
        assert!(
            v.segments >= 2,
            "expected multiple segments, got {}",
            v.segments
        );

        // Flip one entry's outcome in whichever segment holds it.
        let mut tampered = false;
        if let Ok(rd) = std::fs::read_dir(path.parent().unwrap()) {
            let mut paths: Vec<_> = rd
                .flatten()
                .map(|e| e.path())
                .filter(|p| {
                    p.file_name()
                        .map(|n| n.to_string_lossy().starts_with(&stem))
                        .unwrap_or(false)
                })
                .collect();
            paths.sort();
            for p in paths {
                let content = std::fs::read_to_string(&p).unwrap_or_default();
                if content.contains("\"outcome\":true") {
                    let fixed = content.replacen("\"outcome\":true", "\"outcome\":false", 1);
                    std::fs::write(&p, fixed).unwrap();
                    tampered = true;
                    break;
                }
            }
        }
        assert!(tampered, "found no entry to tamper");
        assert!(matches!(
            AuditLog::verify_persisted(&path, None),
            Err(AuditVerifyError::ChainBreak { .. })
        ));
        cleanup(&path);
    }

    #[test]
    fn open_resumes_across_rotation_boundary() {
        // Regression: a restart right after a rotation (empty live file) must
        // resume from the on-disk segments, not reset seq to 0.
        let path = temp_path("boundary");
        cleanup(&path);
        {
            let log = AuditLog::open_with_rotation(16, &path, 120, 0, None).expect("open");
            for i in 0..10 {
                log.record("a:1", "add_user", format!("user=u{i}"), true);
            }
        }
        let log = AuditLog::open_with_rotation(16, &path, 120, 0, None).expect("reopen");
        assert_eq!(
            log.total_recorded(),
            10,
            "must resume across rotation, not reset"
        );
        assert!(AuditLog::verify_persisted(&path, None).is_ok());
        log.record("a:1", "shutdown", "node=n1", true);
        assert_eq!(log.total_recorded(), 11);
        assert!(AuditLog::verify_persisted(&path, None).is_ok());
        cleanup(&path);
    }

    #[test]
    fn open_fails_closed_on_tampered_history() {
        let path = temp_path("tampered");
        cleanup(&path);
        {
            let log = AuditLog::open_with_rotation(16, &path, 10_000_000, 0, None).expect("open");
            for i in 0..5 {
                log.record("a:1", "add_user", format!("u{i}"), true);
            }
        }
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("\"outcome\":true"));
        std::fs::write(
            &path,
            content.replacen("\"outcome\":true", "\"outcome\":false", 1),
        )
        .unwrap();
        assert!(matches!(
            AuditLog::open_with_rotation(16, &path, 10_000_000, 0, None),
            Err(AuditOpenError::Corrupt(_))
        ));
        cleanup(&path);
    }

    #[test]
    fn keyed_chain_requires_the_key_to_verify() {
        let path = temp_path("keyed");
        cleanup(&path);
        let key = b"super-secret-audit-key".to_vec();
        {
            let log = AuditLog::open_with_rotation(16, &path, 10_000_000, 0, Some(key.clone()))
                .expect("open");
            for i in 0..4 {
                log.record("a:1", "add_user", format!("u{i}"), true);
            }
        }
        // Correct key verifies; wrong key and no key both fail.
        assert!(AuditLog::verify_persisted(&path, Some(&key)).is_ok());
        assert!(AuditLog::verify_persisted(&path, Some(b"wrong-key")).is_err());
        assert!(AuditLog::verify_persisted(&path, None).is_err());
        cleanup(&path);
    }

    #[test]
    fn record_checked_true_without_persistence() {
        // In-memory audit (no TURNA_AUDIT_LOG_PATH): there is nothing to persist,
        // so a durable-intent record must succeed — otherwise every privileged op
        // would fail closed in the default configuration.
        let log = AuditLog::new(16);
        assert!(log.record_checked("a:1", "delete_allocation.intent", "id=x", true));
        assert!(log.is_healthy());
    }

    #[test]
    fn record_checked_true_when_persistence_ok() {
        let path = temp_path("checked_ok");
        cleanup(&path);
        let log = AuditLog::open_with_rotation(16, &path, 10_000_000, 0, None).expect("open");
        assert!(log.record_checked("a:1", "set_draining.intent", "node=n1 draining=true", true));
        assert!(log.is_healthy());
        cleanup(&path);
    }
}
