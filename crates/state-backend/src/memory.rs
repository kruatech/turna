//! In-memory state backend — standalone mode, no external dependencies.

use crate::*;
use dashmap::DashMap;
use std::time::Duration;

pub struct InMemoryBackend {
    allocations: DashMap<u16, StoredAllocation>,
    nodes: DashMap<String, NodeHeartbeat>,
    rooms: DashMap<String, StoredRoom>,
    /// (username, realm) -> user. Process-local; see `Backend::store_user`.
    users: DashMap<(String, String), StoredUser>,
    /// request_id -> command (P0 #4 command log). Process-local; only the
    /// Tarantool backend shares this across a real cluster.
    commands: DashMap<String, PendingCommand>,
    /// idempotency_key -> durable record (P0.3 + command-log GC). A retry with a
    /// key already present resolves to the original outcome; reuse with a
    /// different payload is a conflict. Retained independently of the command
    /// (see `gc_command_log`) so a post-prune replay still returns the prior
    /// result.
    command_idempotency: DashMap<String, IdempotencyRecord>,
    /// node_id -> durable desired/observed runtime snapshot.
    runtime_states: DashMap<String, NodeRuntimeState>,
    /// (node_id, normalized subject key) -> desired/observed limits override.
    user_limits_states: DashMap<(String, String), UserLimitsState>,
    /// Test-only fault injection for idempotency journal reads/writes. Compiled
    /// in unconditionally (cross-crate tests link this crate as a normal
    /// dependency, so `cfg(test)` here would not apply to those tests), but only
    /// ever flipped by tests via `set_idempotency_fault`; production never
    /// touches it and the load is a single relaxed atomic on the hot path.
    idempotency_fault: std::sync::atomic::AtomicBool,
}

impl InMemoryBackend {
    pub fn new() -> Self {
        Self {
            allocations: DashMap::new(),
            nodes: DashMap::new(),
            rooms: DashMap::new(),
            users: DashMap::new(),
            commands: DashMap::new(),
            command_idempotency: DashMap::new(),
            runtime_states: DashMap::new(),
            user_limits_states: DashMap::new(),
            idempotency_fault: std::sync::atomic::AtomicBool::new(false),
        }
    }

    pub async fn store_allocation(&self, alloc: &StoredAllocation) -> Result<()> {
        self.allocations.insert(alloc.relay_port, alloc.clone());
        Ok(())
    }

    pub async fn get_allocation(&self, relay_port: u16) -> Result<Option<StoredAllocation>> {
        Ok(self.allocations.get(&relay_port).map(|v| v.clone()))
    }

    pub async fn remove_allocation(&self, relay_port: u16) -> Result<()> {
        self.allocations.remove(&relay_port);
        Ok(())
    }

    pub async fn find_by_user(&self, user_id: &str) -> Result<Vec<StoredAllocation>> {
        Ok(self
            .allocations
            .iter()
            .filter(|e| e.value().user_id == user_id)
            .map(|e| e.value().clone())
            .collect())
    }

    pub async fn find_by_node(&self, node_id: &str) -> Result<Vec<StoredAllocation>> {
        Ok(self
            .allocations
            .iter()
            .filter(|e| e.value().node_id == node_id)
            .map(|e| e.value().clone())
            .collect())
    }

    pub async fn find_expired(&self, before_ms: u64) -> Result<Vec<StoredAllocation>> {
        Ok(self
            .allocations
            .iter()
            .filter(|e| e.value().expires_at_ms < before_ms)
            .map(|e| e.value().clone())
            .collect())
    }

    pub async fn list_allocations(
        &self,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<StoredAllocation>> {
        Ok(self
            .allocations
            .iter()
            .skip(offset)
            .take(limit)
            .map(|e| e.value().clone())
            .collect())
    }

    pub async fn count_allocations(&self) -> Result<u64> {
        Ok(self.allocations.len() as u64)
    }

    pub async fn update_bandwidth(
        &self,
        relay_port: u16,
        bytes_in: u64,
        bytes_out: u64,
        packets_in: u64,
        packets_out: u64,
    ) -> Result<()> {
        if let Some(mut alloc) = self.allocations.get_mut(&relay_port) {
            alloc.bytes_in += bytes_in;
            alloc.bytes_out += bytes_out;
            alloc.packets_in += packets_in;
            alloc.packets_out += packets_out;
        }
        Ok(())
    }

    pub async fn heartbeat(&self, hb: &NodeHeartbeat) -> Result<()> {
        self.nodes.insert(hb.node_id.clone(), hb.clone());
        Ok(())
    }

    pub async fn get_live_nodes(&self, max_age: Duration) -> Result<Vec<NodeHeartbeat>> {
        // saturating_sub: PR5's failover code calls this with a deliberately
        // huge `max_age` (≈100 years) to enumerate every node ever seen.
        // Without saturation, that would underflow `u64` and return nothing.
        let cutoff = now_ms().saturating_sub(max_age.as_millis() as u64);
        Ok(self
            .nodes
            .iter()
            .filter(|e| e.value().last_seen_ms > cutoff)
            .map(|e| e.value().clone())
            .collect())
    }

    /// Atomic compare-and-swap of `node_id`. See `Backend::claim_allocation`
    /// in `lib.rs` for the contract.
    ///
    /// Atomicity here relies on `DashMap::get_mut`, which holds a write
    /// lock on the relevant shard for the duration of the closure. Any
    /// concurrent reader or writer on the same key blocks until we
    /// release the lock at the end of the function.
    pub async fn claim_allocation(
        &self,
        relay_port: u16,
        expected_node_id: &str,
        new_node_id: &str,
    ) -> Result<bool> {
        if let Some(mut entry) = self.allocations.get_mut(&relay_port) {
            if entry.node_id == expected_node_id {
                entry.node_id = new_node_id.to_string();
                return Ok(true);
            }
            // Mismatch — someone else owns it now (raced and won, or the
            // dead node is alive again, or the orphan was already claimed).
            return Ok(false);
        }
        // No such record — already removed (TTL sweep, manual cleanup).
        Ok(false)
    }

    pub async fn store_room(&self, room: &StoredRoom) -> Result<()> {
        self.rooms.insert(room.room_id.clone(), room.clone());
        Ok(())
    }

    pub async fn get_room(&self, room_id: &str) -> Result<Option<StoredRoom>> {
        Ok(self.rooms.get(room_id).map(|v| v.clone()))
    }

    pub async fn remove_room(&self, room_id: &str) -> Result<()> {
        self.rooms.remove(room_id);
        Ok(())
    }

    pub async fn ping(&self) -> Result<()> {
        Ok(())
    }

    pub async fn store_user(&self, user: &StoredUser) -> Result<()> {
        self.users
            .insert((user.username.clone(), user.realm.clone()), user.clone());
        Ok(())
    }

    pub async fn get_user(&self, username: &str, realm: &str) -> Result<Option<StoredUser>> {
        Ok(self
            .users
            .get(&(username.to_string(), realm.to_string()))
            .map(|v| v.clone()))
    }

    pub async fn remove_user(&self, username: &str, realm: &str) -> Result<bool> {
        Ok(self
            .users
            .remove(&(username.to_string(), realm.to_string()))
            .is_some())
    }

    pub async fn list_users(&self) -> Result<Vec<StoredUser>> {
        Ok(self.users.iter().map(|e| e.value().clone()).collect())
    }

    // ── Durable runtime configuration / limits ───────────────────────────

    pub async fn get_runtime_state(&self, node_id: &str) -> Result<Option<NodeRuntimeState>> {
        Ok(self.runtime_states.get(node_id).map(|v| v.clone()))
    }

    pub async fn adopt_node_incarnation(&self, node_id: &str, incarnation: &str) -> Result<()> {
        if let Some(mut state) = self.runtime_states.get_mut(node_id) {
            state.incarnation = incarnation.to_string();
            state.updated_at_ms = now_ms();
        }
        for mut entry in self.user_limits_states.iter_mut() {
            if entry.key().0 == node_id {
                entry.incarnation = incarnation.to_string();
                entry.updated_at_ms = now_ms();
            }
        }
        Ok(())
    }

    pub async fn cas_runtime_desired(
        &self,
        node_id: &str,
        expected_observed_version: u64,
        incarnation: &str,
        desired: &RuntimeConfigSnapshot,
    ) -> Result<bool> {
        use dashmap::mapref::entry::Entry;
        match self.runtime_states.entry(node_id.to_string()) {
            Entry::Occupied(mut e) => {
                let state = e.get_mut();
                if state.observed_version != expected_observed_version
                    || (!state.incarnation.is_empty() && state.incarnation != incarnation)
                {
                    return Ok(false);
                }
                state.incarnation = incarnation.to_string();
                state.desired_version = desired.version;
                state.desired_snapshot = desired.clone();
                state.status = "applying".into();
                state.last_error.clear();
                state.updated_at_ms = now_ms();
                Ok(true)
            }
            Entry::Vacant(e) => {
                if expected_observed_version != 0 || desired.version != 0 {
                    return Ok(false);
                }
                e.insert(NodeRuntimeState {
                    node_id: node_id.to_string(),
                    incarnation: incarnation.to_string(),
                    desired_version: 0,
                    observed_version: 0,
                    desired_snapshot: desired.clone(),
                    observed_snapshot: desired.clone(),
                    status: "applying".into(),
                    last_error: String::new(),
                    updated_at_ms: now_ms(),
                    last_applied: None,
                });
                Ok(true)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    /// #3: mirror a terminal operation's outcome into the durable idempotency
    /// journal at confirm time — atomically with the observed-version bump and
    /// BEFORE `complete_command` runs. Recovery (`get_idempotency`) then returns
    /// the original result even if the completion write was lost AND the single
    /// `last_applied` slot has since been overwritten by a later operation. Only
    /// touches an existing (enqueue-created) record and never downgrades an
    /// already-terminal one, so it is idempotent with `complete_command`.
    fn journal_applied_outcome(&self, op: &AppliedOperation) {
        if op.idempotency_key.is_empty() {
            return;
        }
        if let Some(mut r) = self.command_idempotency.get_mut(&op.idempotency_key) {
            if r.final_status.is_empty() {
                r.final_status = "done".to_string();
                r.result = op.terminal_result.clone();
                r.completed_at_ms = op.applied_at_ms;
            }
        }
    }

    /// #4: durably persist a terminal business outcome for a command that did
    /// NOT mutate observed state (`no_op` / `conflict` / `failed`), keyed by the
    /// idempotency key, BEFORE `complete_command` runs. This mirrors the
    /// `applied` path (`journal_applied_outcome`, atomic in `confirm_*`) so that
    /// EVERY terminal business outcome — not only applied — recovers verbatim
    /// after a lost completion, even once the command row is GC'd.
    ///
    /// Semantics (§4.4): only an existing canonical (enqueue-created) record is
    /// touched; `request_id` and `payload_hash` must match; an already-terminal
    /// record is never downgraded — a repeat of the SAME outcome is a success, a
    /// DIFFERENT one is an invariant conflict. An empty key has no keyed journal
    /// (request_id/last_applied still cover replay) → `Ok(false)`.
    pub async fn record_command_outcome(
        &self,
        request_id: &str,
        idempotency_key: &str,
        payload_hash: &str,
        final_status: &str,
        result: &str,
        completed_at_ms: u64,
    ) -> Result<bool> {
        self.fail_idempotency_if_injected("record_command_outcome")?;
        if idempotency_key.is_empty() {
            return Ok(false);
        }
        let Some(mut r) = self.command_idempotency.get_mut(idempotency_key) else {
            return Err(BackendError::Conflict(format!(
                "record_command_outcome: no canonical idempotency record for key {idempotency_key}"
            )));
        };
        if r.request_id != request_id {
            return Err(BackendError::Conflict(format!(
                "record_command_outcome: request_id {request_id} does not own key {idempotency_key}"
            )));
        }
        if r.payload_hash != payload_hash {
            return Err(BackendError::Conflict(format!(
                "record_command_outcome: payload hash mismatch for key {idempotency_key}"
            )));
        }
        if !r.final_status.is_empty() {
            // Already terminal: idempotent iff the stored outcome is identical;
            // a different terminal result is an invariant violation.
            if r.result == result {
                return Ok(true);
            }
            return Err(BackendError::Conflict(format!(
                "record_command_outcome: different terminal outcome for key {idempotency_key}"
            )));
        }
        r.final_status = if final_status.is_empty() {
            "done"
        } else {
            final_status
        }
        .to_string();
        r.result = result.to_string();
        r.completed_at_ms = completed_at_ms;
        Ok(true)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn confirm_runtime_observed(
        &self,
        node_id: &str,
        desired_version: u64,
        incarnation: &str,
        observed: &RuntimeConfigSnapshot,
        status: &str,
        error: &str,
        applied: Option<&AppliedOperation>,
    ) -> Result<bool> {
        let Some(mut state) = self.runtime_states.get_mut(node_id) else {
            return Ok(false);
        };
        if state.desired_version != desired_version || state.incarnation != incarnation {
            return Ok(false);
        }
        if status == "observed" {
            state.observed_version = observed.version;
            state.observed_snapshot = observed.clone();
            if let Some(op) = applied {
                state.last_applied = Some(op.clone());
                self.journal_applied_outcome(op);
            }
        }
        state.status = status.to_string();
        state.last_error = error.to_string();
        state.updated_at_ms = now_ms();
        Ok(true)
    }

    pub async fn get_user_limits_state(
        &self,
        node_id: &str,
        subject_key: &str,
    ) -> Result<Option<UserLimitsState>> {
        Ok(self
            .user_limits_states
            .get(&(node_id.to_string(), subject_key.to_string()))
            .map(|v| v.clone()))
    }

    pub async fn list_user_limits_states(&self, node_id: &str) -> Result<Vec<UserLimitsState>> {
        Ok(self
            .user_limits_states
            .iter()
            .filter(|e| e.key().0 == node_id)
            .map(|e| e.value().clone())
            .collect())
    }

    pub async fn cas_user_limits_desired(
        &self,
        node_id: &str,
        subject_key: &str,
        expected_observed_version: u64,
        incarnation: &str,
        target: &UserLimitTarget,
        desired: &UserLimitsPatch,
    ) -> Result<bool> {
        use dashmap::mapref::entry::Entry;
        let key = (node_id.to_string(), subject_key.to_string());
        match self.user_limits_states.entry(key) {
            Entry::Occupied(mut e) => {
                let state = e.get_mut();
                if state.observed_version != expected_observed_version
                    || (!state.incarnation.is_empty() && state.incarnation != incarnation)
                {
                    return Ok(false);
                }
                let Some(next_version) = expected_observed_version.checked_add(1) else {
                    return Err(BackendError::Other(
                        "user limits desired version counter overflow".into(),
                    ));
                };
                state.incarnation = incarnation.to_string();
                state.desired_version = next_version;
                state.desired_patch = desired.clone();
                state.status = "applying".into();
                state.last_error.clear();
                state.updated_at_ms = now_ms();
                Ok(true)
            }
            Entry::Vacant(e) => {
                if expected_observed_version != 0 {
                    return Ok(false);
                }
                e.insert(UserLimitsState {
                    schema_version: 1,
                    node_id: node_id.to_string(),
                    subject_key: subject_key.to_string(),
                    target: target.clone(),
                    incarnation: incarnation.to_string(),
                    desired_version: 1,
                    observed_version: 0,
                    desired_patch: desired.clone(),
                    observed_patch: UserLimitsPatch::default(),
                    status: "applying".into(),
                    last_error: String::new(),
                    updated_at_ms: now_ms(),
                    last_applied: None,
                });
                Ok(true)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn confirm_user_limits_observed(
        &self,
        node_id: &str,
        subject_key: &str,
        desired_version: u64,
        incarnation: &str,
        observed: &UserLimitsPatch,
        outcome: ObservationOutcome<'_>,
        applied: Option<&AppliedOperation>,
    ) -> Result<bool> {
        let key = (node_id.to_string(), subject_key.to_string());
        let Some(mut state) = self.user_limits_states.get_mut(&key) else {
            return Ok(false);
        };
        if state.desired_version != desired_version || state.incarnation != incarnation {
            return Ok(false);
        }
        if outcome.status == "observed" {
            state.observed_version = desired_version;
            state.observed_patch = observed.clone();
            if let Some(op) = applied {
                state.last_applied = Some(op.clone());
                self.journal_applied_outcome(op);
            }
        }
        state.status = outcome.status.to_string();
        state.last_error = outcome.error.to_string();
        state.updated_at_ms = now_ms();
        Ok(true)
    }

    // ── Command log (P0 #4) ────────────────────────────────────

    pub async fn enqueue_command(&self, cmd: &PendingCommand) -> Result<String> {
        // P0.3 cross-retry idempotency. When a key is supplied, atomically claim
        // it: the first caller's request_id wins and becomes canonical. A later
        // retry (different generated request_id, same key) resolves to the winner
        // and does NOT insert a second command — so the operation runs at most
        // once. The loser returns the winner's id and polls that command; the
        // winner falls through and inserts its command below.
        if !cmd.idempotency_key.is_empty() {
            use dashmap::mapref::entry::Entry;
            let hash = crate::command_payload_hash(&cmd.op, &cmd.args, &cmd.payload_json);
            match self.command_idempotency.entry(cmd.idempotency_key.clone()) {
                Entry::Occupied(e) => {
                    let rec = e.get();
                    if rec.payload_hash != hash {
                        // Same key, different payload: the key was reused for a
                        // different operation. Reject rather than silently
                        // returning the unrelated prior result.
                        return Err(BackendError::Conflict(format!(
                            "idempotency key {:?} reused with a different payload",
                            cmd.idempotency_key
                        )));
                    }
                    // Genuine retry: return the canonical request_id (any status).
                    return Ok(rec.request_id.clone());
                }
                Entry::Vacant(v) => {
                    v.insert(IdempotencyRecord {
                        request_id: cmd.request_id.clone(),
                        payload_hash: hash,
                        final_status: String::new(),
                        result: String::new(),
                        created_at_ms: crate::now_ms(),
                        completed_at_ms: 0,
                    });
                }
            }
        }
        self.commands
            .entry(cmd.request_id.clone())
            .or_insert_with(|| cmd.clone());
        Ok(cmd.request_id.clone())
    }

    pub async fn claim_commands(
        &self,
        node_id: &str,
        incarnation: &str,
        max: usize,
        lease_ms: u64,
    ) -> Result<Vec<PendingCommand>> {
        let now = crate::now_ms();
        let mut claimed = Vec::new();
        for mut e in self.commands.iter_mut() {
            if claimed.len() >= max {
                break;
            }
            let c = e.value_mut();
            if c.target_node_id != node_id
                || (!c.target_incarnation.is_empty() && c.target_incarnation != incarnation)
            {
                continue;
            }
            // Claim fresh `pending` commands, and reclaim `in_progress` commands
            // whose lease has expired — the previous claimant died before
            // completing (P0.2: lease + reaper folded into claim, no stuck rows).
            let claimable =
                c.status == "pending" || (c.status == "in_progress" && c.lease_until_ms <= now);
            if !claimable {
                continue;
            }
            // P0.2 bound: stop reclaiming after too many attempts — dead-letter
            // to a terminal `failed` so a repeatedly-failing command never loops.
            if c.attempts >= crate::MAX_COMMAND_ATTEMPTS {
                let result = format!(
                    "dead_letter: exceeded {} claim attempts",
                    crate::MAX_COMMAND_ATTEMPTS
                );
                c.status = "failed".to_string();
                c.result = result.clone();
                c.updated_at_ms = now;
                let idem_key = c.idempotency_key.clone();
                tracing::warn!(
                    request_id = %c.request_id,
                    attempts = c.attempts,
                    "command dead-lettered after exceeding max claim attempts"
                );
                // Record the terminal outcome on the idempotency record so a
                // replay after the command is GC'd still sees `failed`.
                if !idem_key.is_empty() {
                    if let Some(mut r) = self.command_idempotency.get_mut(&idem_key) {
                        // #3.7: never downgrade an already-terminal outcome — an
                        // applied command whose completion was lost keeps its
                        // journaled result rather than being dead-lettered.
                        if r.final_status.is_empty() {
                            r.final_status = "failed".to_string();
                            r.result = result;
                            r.completed_at_ms = now;
                        }
                    }
                }
                continue;
            }
            // Mint a fresh per-claim token so a later completion can prove it
            // belongs to *this* claim, not a superseded one (P0.4 fencing).
            c.status = "in_progress".to_string();
            c.claimed_by = node_id.to_string();
            c.claim_token = crate::new_claim_token(node_id);
            c.lease_until_ms = now.saturating_add(lease_ms);
            c.attempts = c.attempts.saturating_add(1);
            c.updated_at_ms = now;
            claimed.push(c.clone());
        }
        Ok(claimed)
    }

    pub async fn complete_command(
        &self,
        request_id: &str,
        claimed_by: &str,
        claim_token: &str,
        status: &str,
        result: &str,
    ) -> Result<bool> {
        // Capture the terminal outcome while holding the command borrow, then
        // mirror it onto the idempotency record AFTER releasing that borrow.
        let mut idem_outcome: Option<(String, String, String, u64)> = None;
        let mut applied = false;
        if let Some(mut e) = self.commands.get_mut(request_id) {
            // Fenced completion (P0.4): apply only from `in_progress` and only
            // when BOTH the claimant id AND the per-claim token match. A stale
            // claimant (reclaimed after its lease expired) holds an old token and
            // is rejected even if it shares the same node id. A mismatch is
            // ignored (returns false) rather than silently marking the command
            // done, so the caller learns the completion did not take effect.
            if e.status == "in_progress"
                && e.claimed_by == claimed_by
                && e.claim_token == claim_token
            {
                let now = crate::now_ms();
                e.status = status.to_string();
                e.result = result.to_string();
                e.updated_at_ms = now;
                if !e.idempotency_key.is_empty() {
                    idem_outcome = Some((
                        e.idempotency_key.clone(),
                        e.status.clone(),
                        e.result.clone(),
                        now,
                    ));
                }
                applied = true;
            }
        }
        if let Some((key, final_status, result, now)) = idem_outcome {
            if let Some(mut r) = self.command_idempotency.get_mut(&key) {
                // #3.7: the durable outcome persisted at confirm-observed is
                // authoritative; a later completion writes the same terminal
                // result and must never downgrade an already-terminal record.
                if r.final_status.is_empty() {
                    r.final_status = final_status;
                    r.result = result;
                    r.completed_at_ms = now;
                }
            }
        }
        Ok(applied)
    }

    pub async fn finalize_stale_command(
        &self,
        request_id: &str,
        current_incarnation: &str,
        result: &str,
    ) -> Result<bool> {
        let mut idem_outcome: Option<(String, String, u64)> = None;
        let mut done = false;
        if let Some(mut e) = self.commands.get_mut(request_id) {
            let c = e.value_mut();
            let terminal = c.status == "done" || c.status == "failed";
            let stale =
                !c.target_incarnation.is_empty() && c.target_incarnation != current_incarnation;
            if !terminal && stale {
                let now = crate::now_ms();
                c.status = "done".to_string();
                c.result = result.to_string();
                c.updated_at_ms = now;
                if !c.idempotency_key.is_empty() {
                    idem_outcome = Some((c.idempotency_key.clone(), c.result.clone(), now));
                }
                done = true;
            }
        }
        if let Some((key, result, now)) = idem_outcome {
            if let Some(mut r) = self.command_idempotency.get_mut(&key) {
                // #3.7: never downgrade an already-terminal outcome — an applied
                // command whose completion was lost keeps its journaled result
                // rather than being overwritten by a superseding finalize.
                if r.final_status.is_empty() {
                    r.final_status = "done".to_string();
                    r.result = result;
                    r.completed_at_ms = now;
                }
            }
        }
        Ok(done)
    }

    pub async fn list_stale_commands(
        &self,
        node_id: &str,
        current_incarnation: &str,
        max: usize,
    ) -> Result<Vec<PendingCommand>> {
        let mut stale = Vec::new();
        for e in self.commands.iter() {
            if stale.len() >= max {
                break;
            }
            let c = e.value();
            let terminal = c.status == "done" || c.status == "failed";
            let is_stale =
                !c.target_incarnation.is_empty() && c.target_incarnation != current_incarnation;
            if c.target_node_id == node_id && !terminal && is_stale {
                stale.push(c.clone());
            }
        }
        Ok(stale)
    }

    pub async fn get_command(&self, request_id: &str) -> Result<Option<PendingCommand>> {
        Ok(self.commands.get(request_id).map(|e| e.value().clone()))
    }

    /// Test hook: force idempotency journal reads/writes to fail, to exercise
    /// the fail-closed recovery paths (a backend outage where neither the write
    /// nor the read-back succeeds). No effect unless a test enables it.
    pub fn set_idempotency_fault(&self, on: bool) {
        self.idempotency_fault
            .store(on, std::sync::atomic::Ordering::SeqCst);
    }

    fn fail_idempotency_if_injected(&self, op: &str) -> Result<()> {
        if self
            .idempotency_fault
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err(BackendError::Other(format!(
                "injected idempotency fault in {op}"
            )));
        }
        Ok(())
    }

    pub async fn get_idempotency(&self, key: &str) -> Result<Option<IdempotencyRecord>> {
        self.fail_idempotency_if_injected("get_idempotency")?;
        Ok(self.command_idempotency.get(key).map(|e| e.value().clone()))
    }

    pub async fn migrate_command_log_batch(
        &self,
        _batch_size: usize,
        _owner: &str,
    ) -> Result<CommandLogMigrationProgress> {
        // The process-local backend has no legacy on-disk rows to migrate.
        Ok(CommandLogMigrationProgress {
            completed: true,
            phase: "complete".to_string(),
            ..CommandLogMigrationProgress::default()
        })
    }

    /// Prune terminal commands past their per-status retention and
    /// idempotency records past their own (longer) retention. The number of
    /// DELETES per call is bounded by `batch * max_batches`; the scan itself is
    /// `O(rows)` (both maps are walked). That is intentional for the
    /// process-local memory backend — its row count is bounded by node capacity
    /// and a full walk is cheap — and it is why the metric contract is honest:
    /// deletions are bounded, scan work is not. The Tarantool backend uses the
    /// `by_status` / `by_completed` indexes to avoid a full-space scan.
    /// `oldest_unfinished_age_ms` is the age since enqueue (`created_at_ms`) of
    /// the oldest not-yet-terminal command — the same semantics the Tarantool
    /// backend reports. Non-terminal commands are never pruned; an idempotency
    /// record is pruned only after its guarded command has completed and aged
    /// out, so a record never disappears before the command it guards.
    pub async fn gc_command_log(&self, r: CommandLogRetention, now_ms: u64) -> GcStats {
        let cap = r.batch.saturating_mul(r.max_batches as usize).max(1);
        let mut stats = GcStats::default();
        let mut terminal_total: u64 = 0;
        let mut oldest_unfinished: u64 = 0;
        let mut to_remove: Vec<String> = Vec::new();
        for e in self.commands.iter() {
            let c = e.value();
            let ttl = match c.status.as_str() {
                "done" => r.done_ms,
                "failed" => r.failed_ms,
                "superseded" => r.superseded_ms,
                "expired" => r.expired_ms,
                _ => {
                    // Non-terminal (pending / in_progress / unknown): never GC'd;
                    // just track the oldest for backlog alerting.
                    let age = now_ms.saturating_sub(c.created_at_ms);
                    if age > oldest_unfinished {
                        oldest_unfinished = age;
                    }
                    continue;
                }
            };
            terminal_total += 1;
            if now_ms.saturating_sub(c.updated_at_ms) > ttl && to_remove.len() < cap {
                to_remove.push(c.request_id.clone());
            }
        }
        for id in &to_remove {
            self.commands.remove(id);
        }
        stats.deleted_commands = to_remove.len() as u64;
        stats.terminal_remaining = terminal_total.saturating_sub(stats.deleted_commands);
        stats.oldest_unfinished_age_ms = oldest_unfinished;

        // Idempotency records: prune only once completed and aged past the
        // (>= failed) idempotency window. Since retain_idempotency >= any command
        // retention (config-validated), the guarded command is already gone.
        let mut idem_remove: Vec<String> = Vec::new();
        for e in self.command_idempotency.iter() {
            let rec = e.value();
            if rec.completed_at_ms > 0
                && now_ms.saturating_sub(rec.completed_at_ms) > r.idempotency_ms
                && idem_remove.len() < cap
            {
                idem_remove.push(e.key().clone());
            }
        }
        for k in &idem_remove {
            self.command_idempotency.remove(k);
        }
        stats.deleted_idempotency = idem_remove.len() as u64;
        stats
    }
}

impl Default for InMemoryBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_alloc(port: u16) -> StoredAllocation {
        StoredAllocation {
            id: format!("alloc-{port}"),
            relay_port: port,
            client_addr: "10.0.0.1:5000".into(),
            relay_addr: format!("10.0.0.1:{port}"),
            user_id: "alice".into(),
            realm: "turna".into(),
            node_id: "node-1".into(),
            allocation_id: format!("alloc-id-{port}"),
            migration_epoch: 0,
            created_at_ms: now_ms(),
            expires_at_ms: now_ms() + 86_400_000,
            bytes_in: 0,
            bytes_out: 0,
            packets_in: 0,
            packets_out: 0,
            permissions: vec!["10.0.0.2".into()],
            channels: vec![],
        }
    }

    #[tokio::test]
    async fn crud() {
        let b = InMemoryBackend::new();
        b.store_allocation(&test_alloc(50000)).await.unwrap();
        assert!(b.get_allocation(50000).await.unwrap().is_some());
        assert!(b.get_allocation(50001).await.unwrap().is_none());
        b.remove_allocation(50000).await.unwrap();
        assert!(b.get_allocation(50000).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn find_by_user() {
        let b = InMemoryBackend::new();
        b.store_allocation(&test_alloc(50000)).await.unwrap();
        b.store_allocation(&test_alloc(50001)).await.unwrap();
        let found = b.find_by_user("alice").await.unwrap();
        assert_eq!(found.len(), 2);
        assert!(b.find_by_user("bob").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn bandwidth_update() {
        let b = InMemoryBackend::new();
        b.store_allocation(&test_alloc(50000)).await.unwrap();
        b.update_bandwidth(50000, 100, 200, 1, 2).await.unwrap();
        let a = b.get_allocation(50000).await.unwrap().unwrap();
        assert_eq!(a.bytes_in, 100);
        assert_eq!(a.packets_out, 2);
    }

    #[tokio::test]
    async fn heartbeat_and_nodes() {
        let b = InMemoryBackend::new();
        b.heartbeat(&NodeHeartbeat {
            node_id: "n1".into(),
            incarnation: "test-incarnation".into(),
            addr: "10.0.0.1:3478".into(),
            active_allocations: 5,
            total_bandwidth_bps: 1000,
            cpu_usage_pct: 10.0,
            memory_usage_pct: 20.0,
            uptime_secs: 60,
            version: "0.1.0".into(),
            last_seen_ms: now_ms(),
            draining: false,
        })
        .await
        .unwrap();
        let nodes = b.get_live_nodes(Duration::from_secs(10)).await.unwrap();
        assert_eq!(nodes.len(), 1);
    }

    /// PR5: claim CAS — happy path.
    #[tokio::test]
    async fn claim_allocation_succeeds_on_match() {
        let b = InMemoryBackend::new();
        b.store_allocation(&test_alloc(50000)).await.unwrap();
        let ok = b.claim_allocation(50000, "node-1", "node-2").await.unwrap();
        assert!(ok);
        let a = b.get_allocation(50000).await.unwrap().unwrap();
        assert_eq!(a.node_id, "node-2");
    }

    /// PR5: claim CAS — mismatch leaves the record alone.
    #[tokio::test]
    async fn claim_allocation_fails_on_mismatch() {
        let b = InMemoryBackend::new();
        b.store_allocation(&test_alloc(50001)).await.unwrap();
        // alloc's node_id is "node-1" — try to claim from a wrong expected.
        let ok = b
            .claim_allocation(50001, "node-XYZ", "node-2")
            .await
            .unwrap();
        assert!(!ok);
        let a = b.get_allocation(50001).await.unwrap().unwrap();
        assert_eq!(a.node_id, "node-1", "owner must not change on CAS mismatch");
    }

    /// PR5: claim CAS — missing record is `false`, not an error.
    #[tokio::test]
    async fn claim_allocation_missing_returns_false() {
        let b = InMemoryBackend::new();
        let ok = b.claim_allocation(50002, "node-1", "node-2").await.unwrap();
        assert!(!ok);
    }

    /// PR5: `get_live_nodes` with a huge `max_age` must not underflow.
    #[tokio::test]
    async fn get_live_nodes_saturates_on_huge_max_age() {
        let b = InMemoryBackend::new();
        b.heartbeat(&NodeHeartbeat {
            node_id: "n1".into(),
            incarnation: "test-incarnation".into(),
            addr: "1.2.3.4:1".into(),
            active_allocations: 0,
            total_bandwidth_bps: 0,
            cpu_usage_pct: 0.0,
            memory_usage_pct: 0.0,
            uptime_secs: 0,
            version: "v".into(),
            last_seen_ms: now_ms(),
            draining: false,
        })
        .await
        .unwrap();
        // 100 years — would underflow without saturating_sub.
        let huge = Duration::from_secs(60 * 60 * 24 * 365 * 100);
        let n = b.get_live_nodes(huge).await.unwrap();
        assert_eq!(n.len(), 1, "huge max_age must include all records");
    }

    fn runtime_snapshot(version: u64, max_allocations: usize) -> RuntimeConfigSnapshot {
        RuntimeConfigSnapshot {
            schema_version: RuntimeConfigSnapshot::SCHEMA_VERSION,
            version,
            max_allocations,
            max_allocations_per_user: 4,
            max_bytes_per_sec_per_allocation: 1_000,
        }
    }

    fn user_target(realm: &str, tenant: &str, username: &str) -> UserLimitTarget {
        UserLimitTarget {
            scope: UserLimitScope::User,
            realm: realm.into(),
            tenant: tenant.into(),
            username: username.into(),
        }
    }

    #[test]
    fn user_limit_subject_keys_are_unambiguous() {
        let left = user_target("a:b", "c", "d").subject_key();
        let right = user_target("a", "b:c", "d").subject_key();
        assert_ne!(left, right);

        let tenant = UserLimitTarget {
            scope: UserLimitScope::Tenant,
            realm: "a:b".into(),
            tenant: "c".into(),
            username: String::new(),
        };
        assert_ne!(left, tenant.subject_key());
    }

    #[tokio::test]
    async fn runtime_state_cas_confirm_restore_and_incarnation_fencing() {
        let backend = InMemoryBackend::new();
        let initial = runtime_snapshot(0, 10);
        assert!(backend
            .cas_runtime_desired("node-a", 0, "inc-1", &initial)
            .await
            .unwrap());
        assert!(backend
            .confirm_runtime_observed("node-a", 0, "inc-1", &initial, "observed", "", None,)
            .await
            .unwrap());

        let desired = runtime_snapshot(1, 20);
        assert!(backend
            .cas_runtime_desired("node-a", 0, "inc-1", &desired)
            .await
            .unwrap());
        assert!(!backend
            .confirm_runtime_observed("node-a", 1, "inc-old", &desired, "observed", "", None,)
            .await
            .unwrap());
        assert!(backend
            .confirm_runtime_observed(
                "node-a",
                1,
                "inc-1",
                &initial,
                "failed",
                "publish rollback",
                None,
            )
            .await
            .unwrap());

        let failed = backend.get_runtime_state("node-a").await.unwrap().unwrap();
        assert_eq!(failed.desired_version, 1);
        assert_eq!(failed.observed_version, 0);
        assert_eq!(failed.observed_snapshot, initial);
        assert_eq!(failed.status, "failed");

        backend
            .adopt_node_incarnation("node-a", "inc-2")
            .await
            .unwrap();
        assert!(!backend
            .cas_runtime_desired("node-a", 0, "inc-1", &desired)
            .await
            .unwrap());
        assert!(backend
            .cas_runtime_desired("node-a", 0, "inc-2", &desired)
            .await
            .unwrap());
        assert!(backend
            .confirm_runtime_observed("node-a", 1, "inc-2", &desired, "observed", "", None,)
            .await
            .unwrap());
        let restored = backend.get_runtime_state("node-a").await.unwrap().unwrap();
        assert_eq!(restored.observed_version, 1);
        assert_eq!(restored.observed_snapshot, desired);
        assert_eq!(restored.status, "observed");
    }

    #[tokio::test]
    async fn confirm_observed_journals_outcome_before_completion() {
        // #3: the durable outcome is persisted at confirm_runtime_observed —
        // atomically with the observed bump and BEFORE complete_command — so a
        // crash after the observed write but before completion still recovers the
        // original result by idempotency key, even when a later operation has
        // overwritten the single `last_applied` slot.
        let b = InMemoryBackend::new();

        // A keyed command → enqueue creates its pending idempotency record.
        let mut cmd_a = mk_cmd("req-A", "node-a");
        cmd_a.op = "update_config".into();
        cmd_a.idempotency_key = "key-A".into();
        b.enqueue_command(&cmd_a).await.unwrap();

        // Seed runtime state, then confirm A's observed bump WITH its applied op —
        // but never call complete_command (the lost-completion window).
        let snap_a = runtime_snapshot(0, 10);
        assert!(b
            .cas_runtime_desired("node-a", 0, "inc-1", &snap_a)
            .await
            .unwrap());
        let ao_a = AppliedOperation {
            request_id: "req-A".into(),
            op: "update_config".into(),
            idempotency_key: "key-A".into(),
            payload_hash: crate::command_payload_hash(&cmd_a.op, &cmd_a.args, &cmd_a.payload_json),
            applied_version: 0,
            terminal_result: r#"{"terminal_status":"applied","tag":"A"}"#.into(),
            applied_at_ms: now_ms(),
        };
        assert!(b
            .confirm_runtime_observed("node-a", 0, "inc-1", &snap_a, "observed", "", Some(&ao_a))
            .await
            .unwrap());

        // Interleave a second keyed operation B that overwrites `last_applied`.
        let mut cmd_b = mk_cmd("req-B", "node-a");
        cmd_b.op = "update_config".into();
        cmd_b.idempotency_key = "key-B".into();
        b.enqueue_command(&cmd_b).await.unwrap();
        let snap_b = runtime_snapshot(1, 20);
        assert!(b
            .cas_runtime_desired("node-a", 0, "inc-1", &snap_b)
            .await
            .unwrap());
        let ao_b = AppliedOperation {
            request_id: "req-B".into(),
            op: "update_config".into(),
            idempotency_key: "key-B".into(),
            payload_hash: crate::command_payload_hash(&cmd_b.op, &cmd_b.args, &cmd_b.payload_json),
            applied_version: 1,
            terminal_result: r#"{"terminal_status":"applied","tag":"B"}"#.into(),
            applied_at_ms: now_ms(),
        };
        assert!(b
            .confirm_runtime_observed("node-a", 1, "inc-1", &snap_b, "observed", "", Some(&ao_b))
            .await
            .unwrap());

        // A's completion was NEVER written and `last_applied` now holds B, yet the
        // durable journal still returns A's original result by its key.
        let rec_a = b.get_idempotency("key-A").await.unwrap().expect("record A");
        assert!(
            !rec_a.final_status.is_empty(),
            "A's outcome must be durable"
        );
        assert_eq!(rec_a.result, r#"{"terminal_status":"applied","tag":"A"}"#);
        assert!(rec_a.completed_at_ms > 0);

        // The single last-applied slot reflects B (proving A relies on the journal).
        let st = b.get_runtime_state("node-a").await.unwrap().unwrap();
        assert_eq!(st.last_applied.as_ref().unwrap().request_id, "req-B");
    }

    #[tokio::test]
    async fn terminal_outcome_is_never_downgraded_by_completion() {
        // #3.7/#8: once confirm-observed persists the durable terminal outcome,
        // a later completion (or dead-letter re-claim) must NOT overwrite it —
        // every journal-write path guards on an empty final_status.
        let b = InMemoryBackend::new();
        let mut cmd = mk_cmd("req-A", "node-a");
        cmd.op = "update_config".into();
        cmd.idempotency_key = "key-A".into();
        b.enqueue_command(&cmd).await.unwrap();
        let claimed = b
            .claim_commands("node-a", "inc-1", 8, 30_000)
            .await
            .unwrap();
        let tok = claimed
            .iter()
            .find(|c| c.request_id == "req-A")
            .expect("A claimed")
            .claim_token
            .clone();

        let snap = runtime_snapshot(0, 10);
        assert!(b
            .cas_runtime_desired("node-a", 0, "inc-1", &snap)
            .await
            .unwrap());
        let ao = AppliedOperation {
            request_id: "req-A".into(),
            op: "update_config".into(),
            idempotency_key: "key-A".into(),
            payload_hash: crate::command_payload_hash(&cmd.op, &cmd.args, &cmd.payload_json),
            applied_version: 0,
            terminal_result: r#"{"terminal_status":"applied"}"#.into(),
            applied_at_ms: now_ms(),
        };
        assert!(b
            .confirm_runtime_observed("node-a", 0, "inc-1", &snap, "observed", "", Some(&ao))
            .await
            .unwrap());

        // A conflicting completion must not downgrade the durable applied outcome.
        b.complete_command(
            "req-A",
            "node-a",
            &tok,
            "failed",
            r#"{"terminal_status":"failed"}"#,
        )
        .await
        .unwrap();

        let rec = b.get_idempotency("key-A").await.unwrap().expect("record A");
        assert_eq!(rec.final_status, "done");
        assert_eq!(rec.result, r#"{"terminal_status":"applied"}"#);
    }

    #[tokio::test]
    async fn user_limits_state_uses_cas_and_preserves_confirmed_patch() {
        let backend = InMemoryBackend::new();
        let target = user_target("realm-a", "tenant-a", "alice");
        let subject = target.subject_key();
        let first = UserLimitsPatch {
            max_allocations: Some(LimitU32 {
                mode: LimitMode::Value,
                value: 2,
            }),
            ..UserLimitsPatch::default()
        };
        assert!(backend
            .cas_user_limits_desired("node-a", &subject, 0, "inc-1", &target, &first,)
            .await
            .unwrap());
        assert!(backend
            .confirm_user_limits_observed(
                "node-a",
                &subject,
                1,
                "inc-1",
                &first,
                ObservationOutcome {
                    status: "observed",
                    error: "",
                },
                None,
            )
            .await
            .unwrap());

        let second = UserLimitsPatch {
            max_allocations: Some(LimitU32 {
                mode: LimitMode::Value,
                value: 1,
            }),
            ..UserLimitsPatch::default()
        };
        assert!(!backend
            .cas_user_limits_desired("node-a", &subject, 0, "inc-1", &target, &second,)
            .await
            .unwrap());
        assert!(backend
            .cas_user_limits_desired("node-a", &subject, 1, "inc-1", &target, &second,)
            .await
            .unwrap());
        assert!(backend
            .confirm_user_limits_observed(
                "node-a",
                &subject,
                2,
                "inc-1",
                &first,
                ObservationOutcome {
                    status: "failed",
                    error: "cache rollback",
                },
                None,
            )
            .await
            .unwrap());

        let failed = backend
            .get_user_limits_state("node-a", &subject)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(failed.desired_version, 2);
        assert_eq!(failed.observed_version, 1);
        assert_eq!(failed.observed_patch, first);
        assert_eq!(failed.status, "failed");

        backend
            .adopt_node_incarnation("node-a", "inc-2")
            .await
            .unwrap();
        assert!(!backend
            .confirm_user_limits_observed(
                "node-a",
                &subject,
                2,
                "inc-1",
                &second,
                ObservationOutcome {
                    status: "observed",
                    error: "",
                },
                None,
            )
            .await
            .unwrap());
        assert!(backend
            .cas_user_limits_desired("node-a", &subject, 1, "inc-2", &target, &second,)
            .await
            .unwrap());
        assert!(backend
            .confirm_user_limits_observed(
                "node-a",
                &subject,
                2,
                "inc-2",
                &second,
                ObservationOutcome {
                    status: "observed",
                    error: "",
                },
                None,
            )
            .await
            .unwrap());
    }

    /// RFC 8016: `allocation_id` and `migration_epoch` survive a store→get
    /// round-trip, and a CAS claim (failover adoption) preserves them.
    #[tokio::test]
    async fn migration_fields_round_trip_and_survive_claim() {
        let b = InMemoryBackend::new();
        let mut a = test_alloc(50100);
        a.allocation_id = "alloc-abc".into();
        a.migration_epoch = 7;
        b.store_allocation(&a).await.unwrap();

        let got = b.get_allocation(50100).await.unwrap().unwrap();
        assert_eq!(got.allocation_id, "alloc-abc");
        assert_eq!(got.migration_epoch, 7);

        // Adoption by another node must not disturb migration identity.
        assert!(b.claim_allocation(50100, "node-1", "node-2").await.unwrap());
        let after = b.get_allocation(50100).await.unwrap().unwrap();
        assert_eq!(after.node_id, "node-2");
        assert_eq!(after.allocation_id, "alloc-abc", "id must survive claim");
        assert_eq!(after.migration_epoch, 7, "epoch must survive claim");
    }

    fn mk_cmd(request_id: &str, node: &str) -> PendingCommand {
        let now = now_ms();
        PendingCommand {
            request_id: request_id.into(),
            target_node_id: node.into(),
            op: "delete_allocation".into(),
            args: vec![],
            payload_json: String::new(),
            target_incarnation: String::new(),
            status: "pending".into(),
            result: String::new(),
            created_at_ms: now,
            updated_at_ms: now,
            claimed_by: String::new(),
            lease_until_ms: 0,
            attempts: 0,
            claim_token: String::new(),
            idempotency_key: String::new(),
        }
    }

    #[tokio::test]
    async fn command_log_enqueue_claim_complete() {
        let b = InMemoryBackend::new();
        b.enqueue_command(&mk_cmd("req-1", "node-a")).await.unwrap();
        // Dedup: re-enqueuing the same request_id is a no-op.
        b.enqueue_command(&mk_cmd("req-1", "node-a")).await.unwrap();

        // Fencing: a different (non-target) node must not claim it.
        assert!(b
            .claim_commands("node-b", "inc-test", 10, 60_000)
            .await
            .unwrap()
            .is_empty());

        // Owner claims exactly once; a second claim sees it in_progress (fresh lease).
        let claimed = b
            .claim_commands("node-a", "inc-test", 10, 60_000)
            .await
            .unwrap();
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].request_id, "req-1");
        assert_eq!(claimed[0].claimed_by, "node-a");
        assert_eq!(claimed[0].attempts, 1);
        assert!(b
            .claim_commands("node-a", "inc-test", 10, 60_000)
            .await
            .unwrap()
            .is_empty());

        // Completion by the claimant (with its claim token) is visible to a poller.
        assert!(b
            .complete_command("req-1", "node-a", &claimed[0].claim_token, "done", "")
            .await
            .unwrap());
        let got = b.get_command("req-1").await.unwrap().unwrap();
        assert_eq!(got.status, "done");
    }

    #[tokio::test]
    async fn command_target_incarnation_is_enforced_at_claim() {
        let b = InMemoryBackend::new();
        let mut command = mk_cmd("req-incarnation", "node-a");
        command.target_incarnation = "inc-new".into();
        b.enqueue_command(&command).await.unwrap();

        assert!(b
            .claim_commands("node-a", "inc-old", 10, 60_000)
            .await
            .unwrap()
            .is_empty());
        assert_eq!(
            b.get_command("req-incarnation")
                .await
                .unwrap()
                .unwrap()
                .status,
            "pending",
            "a stale process must not consume a command for a newer incarnation"
        );

        let claimed = b
            .claim_commands("node-a", "inc-new", 10, 60_000)
            .await
            .unwrap();
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].target_incarnation, "inc-new");
    }

    #[tokio::test]
    async fn command_lease_expiry_allows_reclaim() {
        // P0.2: an in_progress command whose lease has expired (claimant died
        // before completing) must be reclaimable rather than stuck forever.
        let b = InMemoryBackend::new();
        b.enqueue_command(&mk_cmd("req-lease", "node-a"))
            .await
            .unwrap();

        // Claim with a zero-length lease → immediately expired.
        let c1 = b.claim_commands("node-a", "inc-test", 10, 0).await.unwrap();
        assert_eq!(c1.len(), 1);
        assert_eq!(c1[0].attempts, 1);

        // Lease already expired → the (restarted) node re-claims it; attempts++.
        let c2 = b
            .claim_commands("node-a", "inc-test", 10, 60_000)
            .await
            .unwrap();
        assert_eq!(c2.len(), 1, "expired-lease in_progress must be reclaimable");
        assert_eq!(c2[0].attempts, 2);

        // Fresh 60s lease now → not reclaimable.
        assert!(b
            .claim_commands("node-a", "inc-test", 10, 60_000)
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn command_complete_is_fenced_to_claimant_and_token() {
        // P0.4: completion requires the current claimant id AND the claim token.
        let b = InMemoryBackend::new();
        b.enqueue_command(&mk_cmd("req-f", "node-a")).await.unwrap();
        let claimed = b
            .claim_commands("node-a", "inc-test", 10, 60_000)
            .await
            .unwrap();
        assert_eq!(claimed.len(), 1);
        let token = claimed[0].claim_token.clone();
        assert!(!token.is_empty(), "claim must mint a token");

        // Foreign claimant id → rejected.
        assert!(!b
            .complete_command("req-f", "node-b", &token, "done", "x")
            .await
            .unwrap());
        // Right id, wrong token → rejected.
        assert!(!b
            .complete_command("req-f", "node-a", "bogus", "done", "x")
            .await
            .unwrap());
        assert_eq!(
            b.get_command("req-f").await.unwrap().unwrap().status,
            "in_progress"
        );

        // Correct id + token → applied.
        assert!(b
            .complete_command("req-f", "node-a", &token, "done", "res")
            .await
            .unwrap());
        let got = b.get_command("req-f").await.unwrap().unwrap();
        assert_eq!(got.status, "done");
        assert_eq!(got.result, "res");
    }

    #[tokio::test]
    async fn stale_claimant_cannot_complete_after_reclaim() {
        // The P0.4 scenario: A claims and hangs; its lease expires; a worker on
        // the SAME node reclaims (fresh token); revived A completes with its old
        // token and is rejected.
        let b = InMemoryBackend::new();
        b.enqueue_command(&mk_cmd("req-s", "node-a")).await.unwrap();
        let first = b.claim_commands("node-a", "inc-test", 10, 0).await.unwrap(); // 0ms lease → expired
        let old_token = first[0].claim_token.clone();
        let second = b
            .claim_commands("node-a", "inc-test", 10, 60_000)
            .await
            .unwrap();
        assert_eq!(second.len(), 1, "expired lease must be reclaimable");
        let new_token = second[0].claim_token.clone();
        assert_ne!(old_token, new_token, "each claim mints a fresh token");

        // Revived A with the OLD token → rejected; current claimant → applied.
        assert!(!b
            .complete_command("req-s", "node-a", &old_token, "done", "x")
            .await
            .unwrap());
        assert_eq!(
            b.get_command("req-s").await.unwrap().unwrap().status,
            "in_progress"
        );
        assert!(b
            .complete_command("req-s", "node-a", &new_token, "done", "ok")
            .await
            .unwrap());
        assert_eq!(
            b.get_command("req-s").await.unwrap().unwrap().status,
            "done"
        );
    }

    #[tokio::test]
    async fn command_dead_letters_after_max_attempts() {
        let b = InMemoryBackend::new();
        b.enqueue_command(&mk_cmd("req-d", "node-a")).await.unwrap();
        // 0ms lease → each claim is immediately reclaimable by the next.
        for _ in 0..crate::MAX_COMMAND_ATTEMPTS {
            assert_eq!(
                b.claim_commands("node-a", "inc-test", 10, 0)
                    .await
                    .unwrap()
                    .len(),
                1
            );
        }
        // The next attempt dead-letters instead of reclaiming.
        assert!(b
            .claim_commands("node-a", "inc-test", 10, 0)
            .await
            .unwrap()
            .is_empty());
        let got = b.get_command("req-d").await.unwrap().unwrap();
        assert_eq!(got.status, "failed");
        assert!(got.result.contains("dead_letter"));
    }

    #[tokio::test]
    async fn enqueue_is_idempotent_on_key() {
        let b = InMemoryBackend::new();
        let mut c1 = mk_cmd("req-1", "node-a");
        c1.idempotency_key = "idem-xyz".into();
        // First enqueue → canonical is its own request_id.
        assert_eq!(b.enqueue_command(&c1).await.unwrap(), "req-1");

        // Retry: a fresh generated request_id but the SAME key → resolves to the
        // original and does NOT create a second command.
        let mut c2 = mk_cmd("req-2", "node-a");
        c2.idempotency_key = "idem-xyz".into();
        assert_eq!(
            b.enqueue_command(&c2).await.unwrap(),
            "req-1",
            "retry with same key must resolve to the original command"
        );
        assert!(
            b.get_command("req-2").await.unwrap().is_none(),
            "the retry must not insert a duplicate command"
        );

        // Dedup holds even after the original has completed (same key → same
        // outcome, full idempotency).
        let claimed = b
            .claim_commands("node-a", "inc-test", 10, 60_000)
            .await
            .unwrap();
        assert_eq!(claimed.len(), 1, "only one command should be claimable");
        assert!(b
            .complete_command("req-1", "node-a", &claimed[0].claim_token, "done", "ok")
            .await
            .unwrap());
        let mut c3 = mk_cmd("req-3", "node-a");
        c3.idempotency_key = "idem-xyz".into();
        assert_eq!(b.enqueue_command(&c3).await.unwrap(), "req-1");
        assert_eq!(
            b.get_command("req-1").await.unwrap().unwrap().status,
            "done"
        );

        // A different key is independent; no key = its own id (legacy behaviour).
        let mut c4 = mk_cmd("req-4", "node-a");
        c4.idempotency_key = "idem-other".into();
        assert_eq!(b.enqueue_command(&c4).await.unwrap(), "req-4");
        let c5 = mk_cmd("req-5", "node-a");
        assert_eq!(b.enqueue_command(&c5).await.unwrap(), "req-5");
    }

    fn retention(done_ms: u64, failed_ms: u64, idem_ms: u64) -> CommandLogRetention {
        CommandLogRetention {
            done_ms,
            failed_ms,
            superseded_ms: done_ms,
            expired_ms: done_ms,
            idempotency_ms: idem_ms,
            batch: 1000,
            max_batches: 10,
        }
    }

    #[tokio::test]
    async fn command_idempotency_conflict_on_different_payload() {
        let b = InMemoryBackend::new();
        let mut c1 = mk_cmd("req-1", "node-a");
        c1.idempotency_key = "idem-k".into();
        c1.op = "update_config".into();
        c1.args = vec!["a=1".into()];
        assert_eq!(b.enqueue_command(&c1).await.unwrap(), "req-1");

        // Same key, DIFFERENT payload → conflict, not a silent dedup.
        let mut c2 = mk_cmd("req-2", "node-a");
        c2.idempotency_key = "idem-k".into();
        c2.op = "update_config".into();
        c2.args = vec!["a=2".into()];
        assert!(matches!(
            b.enqueue_command(&c2).await,
            Err(BackendError::Conflict(_))
        ));
        assert!(b.get_command("req-2").await.unwrap().is_none());

        // Same key, SAME payload → genuine retry, resolves to the original.
        let mut c3 = mk_cmd("req-3", "node-a");
        c3.idempotency_key = "idem-k".into();
        c3.op = "update_config".into();
        c3.args = vec!["a=1".into()];
        assert_eq!(b.enqueue_command(&c3).await.unwrap(), "req-1");
    }

    #[tokio::test]
    async fn command_gc_prunes_terminal_keeps_idempotency_then_replay() {
        let b = InMemoryBackend::new();
        let mut c = mk_cmd("req-1", "node-a");
        c.idempotency_key = "idem-k".into();
        assert_eq!(b.enqueue_command(&c).await.unwrap(), "req-1");
        let claimed = b
            .claim_commands("node-a", "inc-test", 10, 60_000)
            .await
            .unwrap();
        assert!(b
            .complete_command("req-1", "node-a", &claimed[0].claim_token, "done", "ok")
            .await
            .unwrap());

        let now = now_ms();
        let day = 24 * 3600 * 1000u64;
        // done retained 7d, idempotency 30d. Sweep 10 days out.
        let r = retention(7 * day, 30 * day, 30 * day);
        let s = b.gc_command_log(r, now + 10 * day).await;
        assert_eq!(s.deleted_commands, 1, "done command past 7d must be pruned");
        assert_eq!(s.deleted_idempotency, 0, "idempotency (30d) must survive");
        assert!(
            b.get_command("req-1").await.unwrap().is_none(),
            "command row gone after GC"
        );

        // Post-prune replay: same key + same payload still resolves to the
        // original request_id — idempotency outlived the command.
        let mut retry = mk_cmd("req-2", "node-a");
        retry.idempotency_key = "idem-k".into();
        assert_eq!(
            b.enqueue_command(&retry).await.unwrap(),
            "req-1",
            "idempotency must survive command GC"
        );
        assert!(b.get_command("req-2").await.unwrap().is_none());

        // The whole point of the durable record: after the command row is gone,
        // the terminal OUTCOME is still reachable (this is what `enqueue_and_await`
        // falls back to on a post-GC replay, instead of timing out).
        let rec = b
            .get_idempotency("idem-k")
            .await
            .unwrap()
            .expect("idempotency record must survive command GC");
        assert_eq!(rec.request_id, "req-1");
        assert_eq!(
            rec.final_status, "done",
            "terminal status recoverable post-GC"
        );
        assert_eq!(rec.result, "ok", "terminal result recoverable post-GC");

        // A later sweep past the 30d idempotency window prunes the record too.
        let s2 = b.gc_command_log(r, now + 40 * day).await;
        assert_eq!(
            s2.deleted_idempotency, 1,
            "idempotency pruned past its window"
        );
    }

    #[tokio::test]
    async fn command_gc_never_prunes_unfinished() {
        let b = InMemoryBackend::new();
        b.enqueue_command(&mk_cmd("req-1", "node-a")).await.unwrap(); // pending
        let day = 24 * 3600 * 1000u64;
        // Aggressive zero TTLs, far-future sweep: still must not touch pending.
        let s = b
            .gc_command_log(retention(0, 0, 0), now_ms() + 365 * day)
            .await;
        assert_eq!(s.deleted_commands, 0, "pending command must never be GC'd");
        assert!(b.get_command("req-1").await.unwrap().is_some());
        assert!(s.oldest_unfinished_age_ms > 0, "backlog age is tracked");
    }

    // ===== §2 command-recovery regressions =====

    #[tokio::test]
    async fn finalize_stale_command_supersedes_and_mirrors_idempotency() {
        let b = InMemoryBackend::new();
        let mut c = mk_cmd("req-stale", "node-a");
        c.target_incarnation = "inc-old".into();
        c.idempotency_key = "idem-stale".into();
        b.enqueue_command(&c).await.unwrap();

        // Never claimed by the current (inc-new) incarnation; the sweeper finalizes
        // it with a caller-built typed result.
        let result = r#"{"terminal_status":"superseded"}"#;
        assert!(b
            .finalize_stale_command("req-stale", "inc-new", result)
            .await
            .unwrap());

        let got = b.get_command("req-stale").await.unwrap().unwrap();
        assert_eq!(got.status, "done");
        assert_eq!(got.result, result);

        // The terminal outcome is mirrored onto the idempotency record so a
        // post-prune replay (old key) still returns superseded.
        let idem = b.get_idempotency("idem-stale").await.unwrap().unwrap();
        assert_eq!(idem.final_status, "done");
        assert_eq!(idem.result, result);
    }

    #[tokio::test]
    async fn finalize_stale_command_is_fenced() {
        let b = InMemoryBackend::new();

        // (a) live: target_incarnation == current → not stale, untouched.
        let mut live = mk_cmd("req-live", "node-a");
        live.target_incarnation = "inc-cur".into();
        b.enqueue_command(&live).await.unwrap();
        assert!(!b
            .finalize_stale_command("req-live", "inc-cur", "x")
            .await
            .unwrap());
        assert_eq!(
            b.get_command("req-live").await.unwrap().unwrap().status,
            "pending"
        );

        // (b) legacy: empty target_incarnation → never stale.
        b.enqueue_command(&mk_cmd("req-legacy", "node-a"))
            .await
            .unwrap();
        assert!(!b
            .finalize_stale_command("req-legacy", "inc-cur", "x")
            .await
            .unwrap());
        assert_eq!(
            b.get_command("req-legacy").await.unwrap().unwrap().status,
            "pending"
        );

        // (c) already terminal: a second finalize is a no-op (result unchanged).
        let mut done = mk_cmd("req-done", "node-a");
        done.target_incarnation = "inc-old".into();
        b.enqueue_command(&done).await.unwrap();
        assert!(b
            .finalize_stale_command("req-done", "inc-new", "first")
            .await
            .unwrap());
        assert!(!b
            .finalize_stale_command("req-done", "inc-new", "second")
            .await
            .unwrap());
        assert_eq!(
            b.get_command("req-done").await.unwrap().unwrap().result,
            "first"
        );

        // (d) missing request_id → false.
        assert!(!b
            .finalize_stale_command("nope", "inc-new", "x")
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn list_stale_commands_selects_only_nonterminal_stale() {
        let b = InMemoryBackend::new();

        let mut stale = mk_cmd("req-stale", "node-a");
        stale.target_incarnation = "inc-old".into();
        b.enqueue_command(&stale).await.unwrap();

        let mut live = mk_cmd("req-live", "node-a");
        live.target_incarnation = "inc-cur".into();
        b.enqueue_command(&live).await.unwrap();

        b.enqueue_command(&mk_cmd("req-legacy", "node-a"))
            .await
            .unwrap(); // empty incarnation

        let mut stale_done = mk_cmd("req-stale-done", "node-a");
        stale_done.target_incarnation = "inc-old".into();
        b.enqueue_command(&stale_done).await.unwrap();
        assert!(b
            .finalize_stale_command("req-stale-done", "inc-cur", "done")
            .await
            .unwrap()); // now terminal

        let mut other = mk_cmd("req-other", "node-b"); // different node
        other.target_incarnation = "inc-old".into();
        b.enqueue_command(&other).await.unwrap();

        let listed = b
            .list_stale_commands("node-a", "inc-cur", 10)
            .await
            .unwrap();
        assert_eq!(
            listed.len(),
            1,
            "only the non-terminal stale command for this node"
        );
        assert_eq!(listed[0].request_id, "req-stale");

        // max bound is respected.
        assert!(b
            .list_stale_commands("node-a", "inc-cur", 0)
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn finalized_stale_command_is_not_reclaimed_or_dead_lettered() {
        let b = InMemoryBackend::new();
        let mut c = mk_cmd("req-x", "node-a");
        c.target_incarnation = "inc-old".into();
        b.enqueue_command(&c).await.unwrap();
        assert!(b
            .finalize_stale_command("req-x", "inc-new", "superseded-result")
            .await
            .unwrap());

        // The current incarnation's claim loop never touches a terminal command,
        // so it is never re-attempted and never dead-lettered.
        for _ in 0..(crate::MAX_COMMAND_ATTEMPTS + 2) {
            assert!(b
                .claim_commands("node-a", "inc-new", 10, 0)
                .await
                .unwrap()
                .is_empty());
        }
        let got = b.get_command("req-x").await.unwrap().unwrap();
        assert_eq!(
            got.status, "done",
            "a finalized stale command is never dead-lettered"
        );
        assert_eq!(got.result, "superseded-result");
    }

    #[tokio::test]
    async fn fresh_key_enqueues_and_claims_after_superseded() {
        let b = InMemoryBackend::new();
        let mut c = mk_cmd("req-super", "node-a");
        c.target_incarnation = "inc-old".into();
        c.idempotency_key = "idem-super".into();
        b.enqueue_command(&c).await.unwrap();
        assert!(b
            .finalize_stale_command("req-super", "inc-new", "superseded")
            .await
            .unwrap());

        // A resubmission under a NEW key + current incarnation is independent of
        // the superseded outcome: it enqueues and is claimable.
        let mut fresh = mk_cmd("req-fresh", "node-a");
        fresh.target_incarnation = "inc-new".into();
        fresh.idempotency_key = "idem-fresh".into();
        assert_eq!(b.enqueue_command(&fresh).await.unwrap(), "req-fresh");

        let claimed = b
            .claim_commands("node-a", "inc-new", 10, 60_000)
            .await
            .unwrap();
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].request_id, "req-fresh");
    }

    // ── #4: durable outcome for all terminal business results ────────────────

    async fn enqueue_keyed(b: &InMemoryBackend, req: &str, key: &str) -> String {
        let mut c = mk_cmd(req, "node-a");
        c.idempotency_key = key.into();
        c.op = "update_config".into();
        c.args = vec!["a=1".into()];
        b.enqueue_command(&c).await.unwrap();
        crate::command_payload_hash(&c.op, &c.args, &c.payload_json)
    }

    #[tokio::test]
    async fn record_command_outcome_persists_and_is_idempotent() {
        let b = InMemoryBackend::new();
        let hash = enqueue_keyed(&b, "req-1", "idem-k").await;

        // Pending until recorded.
        assert!(b
            .get_idempotency("idem-k")
            .await
            .unwrap()
            .unwrap()
            .final_status
            .is_empty());

        // Record a no_op outcome BEFORE any completion.
        let body = r#"{"terminal_status":"no_op"}"#;
        assert!(b
            .record_command_outcome("req-1", "idem-k", &hash, "done", body, 111)
            .await
            .unwrap());
        let rec = b.get_idempotency("idem-k").await.unwrap().unwrap();
        assert_eq!(rec.final_status, "done");
        assert_eq!(rec.result, body);
        assert_eq!(rec.completed_at_ms, 111);

        // Repeating the SAME outcome is a success and does not overwrite it.
        assert!(b
            .record_command_outcome("req-1", "idem-k", &hash, "done", body, 999)
            .await
            .unwrap());
        assert_eq!(
            b.get_idempotency("idem-k")
                .await
                .unwrap()
                .unwrap()
                .completed_at_ms,
            111,
            "a terminal record must never be overwritten"
        );

        // A DIFFERENT terminal outcome for the same request is rejected.
        assert!(matches!(
            b.record_command_outcome(
                "req-1",
                "idem-k",
                &hash,
                "done",
                r#"{"terminal_status":"conflict"}"#,
                222
            )
            .await,
            Err(BackendError::Conflict(_))
        ));
    }

    #[tokio::test]
    async fn record_command_outcome_rejects_wrong_identity() {
        let b = InMemoryBackend::new();
        let hash = enqueue_keyed(&b, "req-1", "idem-k").await;

        // Wrong request_id for the key.
        assert!(matches!(
            b.record_command_outcome("req-OTHER", "idem-k", &hash, "done", "{}", 1)
                .await,
            Err(BackendError::Conflict(_))
        ));
        // Wrong payload hash for the key.
        assert!(matches!(
            b.record_command_outcome("req-1", "idem-k", "0000000000000000", "done", "{}", 1)
                .await,
            Err(BackendError::Conflict(_))
        ));
        // No canonical record for an unknown key.
        assert!(matches!(
            b.record_command_outcome("req-1", "unknown", &hash, "done", "{}", 1)
                .await,
            Err(BackendError::Conflict(_))
        ));
        // Empty key: no keyed journal to write → Ok(false), not an error.
        assert!(!b
            .record_command_outcome("req-1", "", &hash, "done", "{}", 1)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn record_command_outcome_never_downgrades_applied() {
        let b = InMemoryBackend::new();
        let hash = enqueue_keyed(&b, "req-1", "idem-k").await;

        // Simulate the `applied` journal (what confirm_* writes atomically).
        assert!(b
            .record_command_outcome(
                "req-1",
                "idem-k",
                &hash,
                "done",
                r#"{"terminal_status":"applied"}"#,
                100
            )
            .await
            .unwrap());
        // A stale replay computing a different outcome must be rejected.
        assert!(matches!(
            b.record_command_outcome(
                "req-1",
                "idem-k",
                &hash,
                "done",
                r#"{"terminal_status":"no_op"}"#,
                200
            )
            .await,
            Err(BackendError::Conflict(_))
        ));
        assert_eq!(
            b.get_idempotency("idem-k").await.unwrap().unwrap().result,
            r#"{"terminal_status":"applied"}"#
        );
    }

    #[tokio::test]
    async fn recorded_outcome_survives_command_row_removal() {
        let b = InMemoryBackend::new();
        let hash = enqueue_keyed(&b, "req-1", "idem-k").await;
        b.record_command_outcome(
            "req-1",
            "idem-k",
            &hash,
            "done",
            r#"{"terminal_status":"conflict"}"#,
            100,
        )
        .await
        .unwrap();

        // Drop the command row (as GC would once terminal); the keyed journal
        // outlives it, so a post-GC replay still recovers the stored outcome.
        b.commands.remove("req-1");
        assert!(b.get_command("req-1").await.unwrap().is_none());
        let rec = b.get_idempotency("idem-k").await.unwrap().unwrap();
        assert_eq!(rec.final_status, "done");
        assert_eq!(rec.result, r#"{"terminal_status":"conflict"}"#);
    }

    // ── #6: exact-u64 boundary coverage (memory reference) ───────────────────
    //
    // The memory backend stores versions as native Rust `u64`, so precision is
    // exact by construction; these tests pin the CAS SEMANTICS at the boundaries
    // (equality is exact above 2^53, stale is rejected, the +1 counter refuses to
    // wrap at u64::MAX) so the memory backend is the reference the Tarantool /
    // Lua parser path (`turna_parse_u64_exact`, see u64_parser_test.lua) must
    // match across the whole range.

    async fn rt_advance(b: &InMemoryBackend, from: u64, to: u64) {
        assert!(
            b.cas_runtime_desired("node-a", from, "inc-1", &runtime_snapshot(to, 10))
                .await
                .unwrap(),
            "cas expected={from} → desired={to} should apply"
        );
        assert!(b
            .confirm_runtime_observed(
                "node-a",
                to,
                "inc-1",
                &runtime_snapshot(to, 10),
                "observed",
                "",
                None
            )
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn runtime_cas_is_exact_across_u64_boundaries() {
        let b = InMemoryBackend::new();
        assert!(b
            .cas_runtime_desired("node-a", 0, "inc-1", &runtime_snapshot(0, 10))
            .await
            .unwrap());
        assert!(b
            .confirm_runtime_observed(
                "node-a",
                0,
                "inc-1",
                &runtime_snapshot(0, 10),
                "observed",
                "",
                None
            )
            .await
            .unwrap());

        let p53 = 1u64 << 53;
        rt_advance(&b, 0, p53 + 1).await; // observed = 2^53 + 1

        // Exactness: 2^53 must NOT be treated as equal to 2^53 + 1 (the classic
        // f64 collapse) — a CAS with the wrong expected version is rejected.
        assert!(
            !b.cas_runtime_desired("node-a", p53, "inc-1", &runtime_snapshot(p53 + 9, 10))
                .await
                .unwrap(),
            "2^53 must not collapse onto 2^53+1"
        );
        assert!(
            !b.cas_runtime_desired("node-a", p53 + 2, "inc-1", &runtime_snapshot(p53 + 9, 10))
                .await
                .unwrap(),
            "a stale (off-by-one high) expected is rejected too"
        );

        rt_advance(&b, p53 + 1, u64::MAX - 1).await; // observed = MAX-1
        rt_advance(&b, u64::MAX - 1, u64::MAX).await; // observed = MAX

        assert!(
            !b.cas_runtime_desired(
                "node-a",
                u64::MAX - 1,
                "inc-1",
                &runtime_snapshot(u64::MAX, 10)
            )
            .await
            .unwrap(),
            "MAX-1 must be distinct from MAX"
        );
        let state = b.get_runtime_state("node-a").await.unwrap().unwrap();
        assert_eq!(
            state.observed_version,
            u64::MAX,
            "the full-range value round-trips exactly"
        );
    }

    fn seed_limits(b: &InMemoryBackend, subject: &str, version: u64) {
        b.user_limits_states.insert(
            ("node-a".to_string(), subject.to_string()),
            UserLimitsState {
                schema_version: 1,
                node_id: "node-a".into(),
                subject_key: subject.into(),
                target: user_target("realm-a", "tenant-a", "alice"),
                incarnation: "inc-1".into(),
                desired_version: version,
                observed_version: version,
                desired_patch: UserLimitsPatch::default(),
                observed_patch: UserLimitsPatch::default(),
                status: "observed".into(),
                last_error: String::new(),
                updated_at_ms: now_ms(),
                last_applied: None,
            },
        );
    }

    #[tokio::test]
    async fn user_limits_counter_is_exact_and_refuses_overflow() {
        let b = InMemoryBackend::new();
        let target = user_target("realm-a", "tenant-a", "alice");
        let patch = UserLimitsPatch::default();

        // MAX-1 increments EXACTLY to MAX (no rounding, no wrap).
        seed_limits(&b, "s-below", u64::MAX - 1);
        assert!(b
            .cas_user_limits_desired("node-a", "s-below", u64::MAX - 1, "inc-1", &target, &patch)
            .await
            .unwrap());
        assert_eq!(
            b.get_user_limits_state("node-a", "s-below")
                .await
                .unwrap()
                .unwrap()
                .desired_version,
            u64::MAX,
            "MAX-1 increments exactly to MAX"
        );

        // At the ceiling, the +1 counter refuses to overflow — an error, not a
        // silent wrap to 0, and the state is left unchanged.
        seed_limits(&b, "s-max", u64::MAX);
        let outcome = b
            .cas_user_limits_desired("node-a", "s-max", u64::MAX, "inc-1", &target, &patch)
            .await;
        assert!(
            matches!(outcome, Err(BackendError::Other(_))),
            "overflow at u64::MAX must be refused, got {outcome:?}"
        );
        assert_eq!(
            b.get_user_limits_state("node-a", "s-max")
                .await
                .unwrap()
                .unwrap()
                .desired_version,
            u64::MAX,
            "state unchanged after a refused overflow (no wrap to 0)"
        );
    }
}
