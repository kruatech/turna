//! Log file sink with rotation, for hosts that do not ship stdout anywhere.
//!
//! # Why not `tracing-appender`
//!
//! It was the obvious candidate and it does not fit. Its `rolling` appender
//! rotates by time only — there is no size limit, so one noisy hour can fill a
//! disk — and it has no way to reopen its file, which is what `logrotate`
//! expects of a daemon it has just moved a file out from under. Both are what an
//! operator asks for first. What is left is a mutex, a `File` and two renames,
//! which is less code than adapting a crate around the parts it lacks, and adds
//! nothing to the dependency graph or to `deny.toml`'s licence review.
//!
//! # Modes
//!
//! - `size`: rotate when the next line would take the file past
//!   `max_size_bytes`. `turna.log` → `turna.log.1` → … → `turna.log.N`.
//! - `daily` / `hourly`: rotate at the first line of a new UTC period. The old
//!   file becomes `turna.log.2026-09-24` (or `…T13` for hourly).
//! - `external`: never rotate. `logrotate` (or anything else) moves the file and
//!   sends SIGHUP; the node reopens the path. The same reopen also works in the
//!   other modes, so a stray SIGHUP is harmless.
//!
//! In every rotating mode `max_files` rotated files are kept and older ones
//! deleted. The active file is not counted.
//!
//! # What it costs on the logging path
//!
//! One uncontended mutex and one `write(2)` per line — the `fmt` layer formats a
//! whole event into a buffer and hands it over in a single `write_all`, so a
//! line is never split and never interleaved with another thread's. The same
//! cost the stdout layer already has, which is also a blocking write. A write
//! error is counted (`turna_log_file_write_errors_total`) and the line dropped;
//! it is not reported on stderr per line, which would turn a full disk into a
//! flood on the one channel still working.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// When the file is rotated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rotation {
    /// Rotate when the file would exceed this many bytes.
    Size(u64),
    /// Rotate at the first write of a new UTC day.
    Daily,
    /// Rotate at the first write of a new UTC hour.
    Hourly,
    /// Never rotate here; reopen on [`reopen`] (SIGHUP) after an external tool
    /// has moved the file.
    External,
}

impl Rotation {
    /// Parse the config spelling. `max_size_bytes` is only read for `size`.
    pub fn parse(mode: &str, max_size_bytes: u64) -> Option<Self> {
        match mode {
            "size" => Some(Rotation::Size(max_size_bytes)),
            "daily" => Some(Rotation::Daily),
            "hourly" => Some(Rotation::Hourly),
            "external" => Some(Rotation::External),
            _ => None,
        }
    }

    /// Period index for time-based rotation: whole days or hours since the
    /// epoch. `None` for the modes that do not rotate by time.
    fn period_of(self, unix_secs: u64) -> Option<u64> {
        match self {
            Rotation::Daily => Some(unix_secs / 86_400),
            Rotation::Hourly => Some(unix_secs / 3_600),
            Rotation::Size(_) | Rotation::External => None,
        }
    }

    /// Suffix a time-rotated file carries: the period it holds, not the moment
    /// it was rotated, so `turna.log.2026-09-23` holds the 23rd.
    fn suffix_for(self, period: u64) -> String {
        match self {
            Rotation::Hourly => {
                let (y, m, d) = crate::syslog::civil_from_days((period / 24) as i64);
                format!("{y:04}-{m:02}-{d:02}T{:02}", period % 24)
            }
            _ => {
                let (y, m, d) = crate::syslog::civil_from_days(period as i64);
                format!("{y:04}-{m:02}-{d:02}")
            }
        }
    }
}

/// Where and how to write.
#[derive(Debug, Clone)]
pub struct LogFileConfig {
    pub path: PathBuf,
    pub rotation: Rotation,
    /// Rotated files kept. At least 1; the config validator enforces it.
    pub max_files: usize,
}

struct State {
    file: Option<File>,
    /// Bytes in the active file, for size rotation. Seeded from the file's
    /// length on open, so a restart does not reset the budget.
    size: u64,
    /// Period the active file belongs to, for time rotation. Seeded from the
    /// file's mtime, so a node restarted the next morning rotates yesterday's
    /// file on its first line rather than appending today to it.
    period: Option<u64>,
    /// After a failed rotation, no new attempt before this. Without it a
    /// rotation that cannot succeed (a directory in the way, a read-only
    /// directory) would be retried — and fail — on every single line.
    retry_after: Option<std::time::Instant>,
}

/// An open, rotating log file. Shared by the `fmt` layer (through
/// [`LogFileWriter`]) and the SIGHUP handler (through [`reopen`]).
pub struct LogFile {
    config: LogFileConfig,
    state: Mutex<State>,
    reopen_requested: AtomicBool,
    /// Rotations performed. Exported as `turna_log_file_rotations_total`.
    pub rotations: AtomicU64,
    /// Lines lost to a write error. Exported as
    /// `turna_log_file_write_errors_total`.
    pub write_errors: AtomicU64,
    /// Rotations (or pruning of old files) that failed. The line that
    /// triggered it is still written, to the active file. Exported as
    /// `turna_log_file_rotation_errors_total`.
    pub rotation_errors: AtomicU64,
    /// Wait after a failed rotation before trying again.
    retry_backoff: std::time::Duration,
}

/// How long a failed rotation waits before it is tried again.
const ROTATION_RETRY_BACKOFF: std::time::Duration = std::time::Duration::from_secs(60);

impl LogFile {
    /// Open (or create) the file. Fails if it cannot be opened, so that a
    /// configured log file that cannot be written is a startup error and not a
    /// silent absence.
    pub fn open(config: LogFileConfig) -> io::Result<Arc<Self>> {
        let file = open_append(&config.path)?;
        let meta = file.metadata()?;
        let period = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .and_then(|d| config.rotation.period_of(d.as_secs()))
            .or_else(|| config.rotation.period_of(now_secs()));
        Ok(Arc::new(Self {
            state: Mutex::new(State {
                file: Some(file),
                size: meta.len(),
                period,
                retry_after: None,
            }),
            config,
            reopen_requested: AtomicBool::new(false),
            rotations: AtomicU64::new(0),
            write_errors: AtomicU64::new(0),
            rotation_errors: AtomicU64::new(0),
            retry_backoff: ROTATION_RETRY_BACKOFF,
        }))
    }

    pub fn path(&self) -> &Path {
        &self.config.path
    }

    /// Ask for the file to be reopened before the next line. Only sets a flag,
    /// so it is safe to call from anywhere, including a signal-handling task
    /// that must not block on the log mutex.
    pub fn request_reopen(&self) {
        self.reopen_requested.store(true, Ordering::Release);
    }

    /// Write one formatted line, rotating first if it is due. Errors are
    /// counted, never returned: see the module docs for why.
    pub fn write_line(&self, buf: &[u8]) {
        if let Err(_e) = self.try_write_line(buf) {
            self.write_errors.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn try_write_line(&self, buf: &[u8]) -> io::Result<()> {
        // A poisoned lock means a panic while writing a log line. The state is a
        // file handle and two counters, all still valid, so carry on rather than
        // lose every later line to a panic that has already been reported.
        let mut st = self.state.lock().unwrap_or_else(|p| p.into_inner());

        if self.reopen_requested.swap(false, Ordering::AcqRel) {
            st.file = None;
            let f = open_append(&self.config.path)?;
            st.size = f.metadata().map(|m| m.len()).unwrap_or(0);
            st.file = Some(f);
        }

        let now_period = self.config.rotation.period_of(now_secs());
        let due = match self.config.rotation {
            Rotation::Size(max) => st.size > 0 && st.size + buf.len() as u64 > max,
            Rotation::Daily | Rotation::Hourly => now_period != st.period,
            Rotation::External => false,
        };
        let backing_off = st
            .retry_after
            .is_some_and(|t| std::time::Instant::now() < t);
        if due && !backing_off && self.rotate(&mut st) {
            st.period = now_period;
        }

        if st.file.is_none() {
            // A previous rotation failed after closing the file. Try again now
            // rather than stay closed until the next SIGHUP.
            let f = open_append(&self.config.path)?;
            st.size = f.metadata().map(|m| m.len()).unwrap_or(0);
            st.file = Some(f);
        }
        let file = st.file.as_mut().expect("opened above");
        file.write_all(buf)?;
        st.size += buf.len() as u64;
        Ok(())
    }

    /// Rotate, then always reopen the configured path, whatever happened.
    ///
    /// Returns whether the active file was moved aside. On failure the line
    /// that triggered it still goes to the active file (reopened at the same
    /// path, so it is the old file if the rename never happened), the failure is
    /// counted, and the next attempt waits `retry_backoff` — a rotation that
    /// cannot succeed must not cost a failed rename per line, nor drop lines.
    fn rotate(&self, st: &mut State) -> bool {
        // Close before renaming. Not required on Linux, but it keeps the handle
        // from outliving the name it was opened under.
        st.file = None;
        let moved = self.move_active_aside(st);
        let moved_ok = moved.is_ok();
        if moved_ok {
            self.rotations.fetch_add(1, Ordering::Relaxed);
            st.retry_after = None;
            // Pruning is housekeeping: the rotation itself has happened, so a
            // failure here is counted but does not make the rotation retry.
            if matches!(self.config.rotation, Rotation::Daily | Rotation::Hourly)
                && prune_dated(&self.config.path, self.config.max_files).is_err()
            {
                self.rotation_errors.fetch_add(1, Ordering::Relaxed);
            }
        } else {
            self.rotation_errors.fetch_add(1, Ordering::Relaxed);
            st.retry_after = Some(std::time::Instant::now() + self.retry_backoff);
        }
        // Reopen here rather than leaving it to the caller: the handle must
        // never stay closed because a rename failed.
        if let Ok(f) = open_append(&self.config.path) {
            st.size = f.metadata().map(|m| m.len()).unwrap_or(0);
            st.file = Some(f);
        }
        moved_ok
    }

    /// The renames. Size: shift .N-1 → .N … .1 → .2, then active → .1 (the file
    /// that would become .max_files+1 is overwritten, which is the retention).
    /// Time: active → `<file>.<period>`.
    fn move_active_aside(&self, st: &State) -> io::Result<()> {
        let path = &self.config.path;
        match self.config.rotation {
            Rotation::Size(_) => {
                for i in (1..self.config.max_files).rev() {
                    let from = numbered(path, i);
                    if from.exists() {
                        std::fs::rename(&from, numbered(path, i + 1))?;
                    }
                }
                if path.exists() {
                    std::fs::rename(path, numbered(path, 1))?;
                }
            }
            Rotation::Daily | Rotation::Hourly => {
                let period = st
                    .period
                    .or_else(|| self.config.rotation.period_of(now_secs()))
                    .unwrap_or(0);
                let target = free_name(path, &self.config.rotation.suffix_for(period));
                if path.exists() {
                    std::fs::rename(path, target)?;
                }
            }
            Rotation::External => {}
        }
        Ok(())
    }
}

/// `turna.log` + `.N`.
fn numbered(path: &Path, n: usize) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(format!(".{n}"));
    PathBuf::from(s)
}

/// `turna.log.<suffix>`, or `turna.log.<suffix>.<n>` if that name is taken — a
/// node restarted twice in one day rotates twice into the same date, and a plain
/// rename would overwrite the first file with no error at all.
fn free_name(path: &Path, suffix: &str) -> PathBuf {
    let mut base = path.as_os_str().to_owned();
    base.push(format!(".{suffix}"));
    let base = PathBuf::from(base);
    if !base.exists() {
        return base;
    }
    let mut n = 1;
    loop {
        let candidate = numbered(&base, n);
        if !candidate.exists() {
            return candidate;
        }
        n += 1;
    }
}

/// Keep the newest `keep` date-suffixed siblings of `path`, delete the rest.
///
/// Only names of the form `<file>.<YYYY-MM-DD…>` are touched: the suffix must
/// start with a digit, so an operator's `turna.log.bak` or a numbered file from
/// an earlier `size` configuration is left alone.
fn prune_dated(path: &Path, keep: usize) -> io::Result<()> {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return Ok(());
    };
    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let prefix = format!("{name}.");
    let mut dated: Vec<PathBuf> = std::fs::read_dir(&dir)?
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let n = e.file_name().into_string().ok()?;
            let rest = n.strip_prefix(&prefix)?;
            // YYYY-MM-DD at least: four digits then a dash.
            let b = rest.as_bytes();
            (b.len() >= 10 && b[..4].iter().all(u8::is_ascii_digit) && b[4] == b'-')
                .then(|| e.path())
        })
        .collect();
    if dated.len() <= keep {
        return Ok(());
    }
    // Lexicographic order is chronological for this suffix, and `.N`
    // disambiguators sort after their date.
    dated.sort();
    let excess = dated.len() - keep;
    for old in dated.into_iter().take(excess) {
        std::fs::remove_file(old)?;
    }
    Ok(())
}

fn open_append(path: &Path) -> io::Result<File> {
    let mut o = OpenOptions::new();
    o.create(true).append(true);
    // 0640: the log carries usernames and, unless redacted, client addresses.
    // Group-readable so a log shipper in the service's group can read it,
    // nothing for others.
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o640);
    }
    o.open(path)
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// `MakeWriter` for the `fmt` layer.
#[derive(Clone)]
pub struct LogFileMakeWriter(pub Arc<LogFile>);

/// One event's writer. Holds a reference, not the lock: the lock is taken for
/// the single `write` the `fmt` layer makes per event.
pub struct LogFileWriter<'a>(&'a LogFile);

impl Write for LogFileWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write_line(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogFileMakeWriter {
    type Writer = LogFileWriter<'a>;

    fn make_writer(&'a self) -> Self::Writer {
        LogFileWriter(&self.0)
    }
}

/// The process's log file, once telemetry has opened one.
static ACTIVE: OnceLock<Arc<LogFile>> = OnceLock::new();

pub(crate) fn set_active(f: Arc<LogFile>) {
    let _ = ACTIVE.set(f);
}

/// The active log file, if one is configured.
pub fn active() -> Option<&'static Arc<LogFile>> {
    ACTIVE.get()
}

/// Reopen the log file before its next line. What the node's SIGHUP handler
/// calls; returns false when no file is configured.
pub fn reopen() -> bool {
    match ACTIVE.get() {
        Some(f) => {
            f.request_reopen();
            true
        }
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "turna-logfile-{tag}-{}-{}",
            std::process::id(),
            now_secs()
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn size_rotation_shifts_and_keeps_max_files() {
        let d = tmpdir("size");
        let path = d.join("turna.log");
        let f = LogFile::open(LogFileConfig {
            path: path.clone(),
            rotation: Rotation::Size(100),
            max_files: 2,
        })
        .unwrap();
        let line = [b'x'; 60];
        // 60 → rotate before the 2nd (120 > 100), and again before the 3rd and 4th.
        for _ in 0..4 {
            f.write_line(&line);
        }
        assert_eq!(f.rotations.load(Ordering::Relaxed), 3);
        assert_eq!(f.write_errors.load(Ordering::Relaxed), 0);
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 60);
        assert!(numbered(&path, 1).exists());
        assert!(numbered(&path, 2).exists());
        assert!(
            !numbered(&path, 3).exists(),
            "max_files = 2 must cap retention"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A single line longer than the limit is written, not dropped and not
    /// rotated into an empty file forever.
    #[test]
    fn oversized_line_into_empty_file_is_written() {
        let d = tmpdir("big");
        let path = d.join("turna.log");
        let f = LogFile::open(LogFileConfig {
            path: path.clone(),
            rotation: Rotation::Size(10),
            max_files: 1,
        })
        .unwrap();
        f.write_line(&[b'y'; 50]);
        assert_eq!(f.rotations.load(Ordering::Relaxed), 0);
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 50);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// The logrotate contract: the file is moved away, SIGHUP, and the next
    /// line lands in a fresh file at the original path — not in the moved one.
    #[test]
    fn reopen_after_external_move_writes_to_the_path_again() {
        let d = tmpdir("reopen");
        let path = d.join("turna.log");
        let f = LogFile::open(LogFileConfig {
            path: path.clone(),
            rotation: Rotation::External,
            max_files: 1,
        })
        .unwrap();
        f.write_line(b"before\n");
        let moved = d.join("turna.log.1");
        std::fs::rename(&path, &moved).unwrap();
        f.request_reopen();
        f.write_line(b"after\n");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "after\n");
        assert_eq!(std::fs::read_to_string(&moved).unwrap(), "before\n");
        assert_eq!(f.rotations.load(Ordering::Relaxed), 0);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn time_rotation_renames_to_the_period_and_prunes() {
        let d = tmpdir("daily");
        let path = d.join("turna.log");
        let f = LogFile::open(LogFileConfig {
            path: path.clone(),
            rotation: Rotation::Daily,
            max_files: 2,
        })
        .unwrap();
        // Pretend the active file belongs to an old day, three times over.
        for back in [5u64, 4, 3] {
            f.state.lock().unwrap().period = Some(now_secs() / 86_400 - back);
            f.write_line(b"line\n");
        }
        assert_eq!(f.rotations.load(Ordering::Relaxed), 3);
        let mut rotated: Vec<String> = std::fs::read_dir(&d)
            .unwrap()
            .filter_map(|e| e.ok()?.file_name().into_string().ok())
            .filter(|n| n != "turna.log")
            .collect();
        rotated.sort();
        assert_eq!(rotated.len(), 2, "max_files = 2: {rotated:?}");
        // The oldest period (5 days back) is the one pruned.
        let kept_4 = Rotation::Daily.suffix_for(now_secs() / 86_400 - 4);
        assert!(rotated.iter().any(|n| n.ends_with(&kept_4)), "{rotated:?}");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn prune_leaves_files_it_did_not_name() {
        let d = tmpdir("prune");
        let path = d.join("turna.log");
        std::fs::write(d.join("turna.log.bak"), b"keep").unwrap();
        std::fs::write(d.join("turna.log.1"), b"keep").unwrap();
        std::fs::write(d.join("turna.log.2026-01-01"), b"old").unwrap();
        std::fs::write(d.join("turna.log.2026-01-02"), b"new").unwrap();
        prune_dated(&path, 1).unwrap();
        assert!(d.join("turna.log.bak").exists());
        assert!(d.join("turna.log.1").exists());
        assert!(!d.join("turna.log.2026-01-01").exists());
        assert!(d.join("turna.log.2026-01-02").exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn same_period_twice_does_not_overwrite() {
        let d = tmpdir("collide");
        let path = d.join("turna.log");
        std::fs::write(d.join("turna.log.2026-01-01"), b"first").unwrap();
        let next = free_name(&path, "2026-01-01");
        assert_eq!(next, d.join("turna.log.2026-01-01.1"));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A rename that cannot succeed — a directory where `.1` should go — must
    /// not drop lines and must not be retried on every line.
    #[test]
    fn failed_rotation_keeps_writing_and_backs_off() {
        let d = tmpdir("rotfail");
        let path = d.join("turna.log");
        let blocker = numbered(&path, 1);
        std::fs::create_dir_all(blocker.join("occupied")).unwrap();
        let f = LogFile::open(LogFileConfig {
            path: path.clone(),
            rotation: Rotation::Size(10),
            max_files: 1,
        })
        .unwrap();
        for _ in 0..20 {
            f.write_line(b"0123456789\n");
        }
        assert_eq!(f.write_errors.load(Ordering::Relaxed), 0, "no line lost");
        assert_eq!(f.rotations.load(Ordering::Relaxed), 0);
        assert_eq!(
            f.rotation_errors.load(Ordering::Relaxed),
            1,
            "one failed attempt, then back off instead of retrying per line"
        );
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 20 * 11);

        // Once the obstacle is gone and the backoff has passed, rotation works.
        std::fs::remove_dir_all(&blocker).unwrap();
        f.state.lock().unwrap().retry_after = Some(std::time::Instant::now());
        f.write_line(b"after\n");
        assert_eq!(f.rotations.load(Ordering::Relaxed), 1);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "after\n");
        assert_eq!(std::fs::metadata(&blocker).unwrap().len(), 20 * 11);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn hourly_suffix_names_the_hour() {
        // 2024-01-01T13 = day 19723, hour 13.
        assert_eq!(
            Rotation::Hourly.suffix_for(19_723 * 24 + 13),
            "2024-01-01T13"
        );
        assert_eq!(Rotation::Daily.suffix_for(19_723), "2024-01-01");
    }

    #[test]
    fn parse_accepts_the_documented_modes_only() {
        assert_eq!(Rotation::parse("size", 5), Some(Rotation::Size(5)));
        assert_eq!(Rotation::parse("daily", 0), Some(Rotation::Daily));
        assert_eq!(Rotation::parse("hourly", 0), Some(Rotation::Hourly));
        assert_eq!(Rotation::parse("external", 0), Some(Rotation::External));
        assert_eq!(Rotation::parse("weekly", 0), None);
    }

    #[cfg(unix)]
    #[test]
    fn file_is_created_0640() {
        use std::os::unix::fs::PermissionsExt;
        let d = tmpdir("mode");
        let path = d.join("turna.log");
        let _f = LogFile::open(LogFileConfig {
            path: path.clone(),
            rotation: Rotation::External,
            max_files: 1,
        })
        .unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        // umask can only remove bits, never add them.
        assert_eq!(mode & !0o640, 0, "mode {mode:o} grants more than 0640");
        let _ = std::fs::remove_dir_all(&d);
    }
}
