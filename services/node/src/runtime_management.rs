//! Durable runtime configuration and user-limit management for a TURN node.
//!
//! The management plane only appends typed commands. This module is the sole
//! node-local apply point: it serializes mutations, validates optimistic
//! versions under the apply lock, prepares durable desired state, publishes one
//! immutable dataplane snapshot, and confirms durable observed state.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;

use tokio::sync::Mutex;
use tracing::{error, info, warn};

use turna_config::{
    ConfigUpdateError, DynamicLimits, DynamicLimitsPatch, RuntimeSnapshot as ConfigRuntimeSnapshot,
    RuntimeValidationCtx,
};
use turna_health::Metrics;
use turna_session::{
    AllocationStore, EffectiveUserLimits as SessionEffectiveUserLimits,
    LimitMode as SessionLimitMode, LimitU32 as SessionLimitU32, LimitU64 as SessionLimitU64,
    RuntimeLimits, UserLimitsOverride,
};
use turna_state_backend::{
    command_payload_hash, now_ms, AppliedOperation, Backend, EffectiveUserLimits, LimitMode,
    LimitU32, LimitU64, ObservationOutcome, PendingCommand, RuntimeConfigSnapshot,
    SetUserLimitsCommand, SetUserLimitsResult, UpdateConfigCommand, UpdateConfigResult,
    UserLimitScope, UserLimitTarget, UserLimitsPatch,
};

const COMMAND_SCHEMA_VERSION: u32 = 1;
const APPLY_HISTOGRAM: &str = "turna_runtime_config_apply_duration_seconds";
const MAX_STALE_SWEEP: usize = 64;
const STALE_SUPERSEDED_MSG: &str =
    "target incarnation is no longer active; resubmit against the current node incarnation";

/// #4: transport status returned by `apply_*` when a terminal business outcome
/// could NOT be made durable. The command loop treats it specially: it does not
/// call `complete_command`, leaving the command claimed so lease expiry reclaims
/// and re-applies it — rather than completing with an un-journaled outcome that a
/// lost completion could later re-validate into a different result.
pub const RETRY_LATER_STATUS: &str = "__retry_later";

/// #4: result of trying to durably record a terminal business outcome.
enum RecordedOutcome {
    /// The outcome is durable (freshly recorded, already-identical, or an
    /// existing durable outcome that wins) — complete the command with this body.
    Durable(String),
    /// Recording failed against an EXISTING (still-pending) canonical record and
    /// no durable outcome exists — do not complete; leave the command for reclaim.
    RetryLater,
}

#[derive(Clone)]
pub struct RuntimeManagement {
    node_id: String,
    incarnation: String,
    store: Arc<AllocationStore>,
    backend: Arc<Backend>,
    metrics: Arc<Metrics>,
    validation_ctx: RuntimeValidationCtx,
    apply_lock: Arc<Mutex<()>>,
}

impl RuntimeManagement {
    pub fn new(
        node_id: String,
        incarnation: String,
        store: Arc<AllocationStore>,
        backend: Arc<Backend>,
        metrics: Arc<Metrics>,
        validation_ctx: RuntimeValidationCtx,
    ) -> Self {
        Self {
            node_id,
            incarnation,
            store,
            backend,
            metrics,
            validation_ctx,
            apply_lock: Arc::new(Mutex::new(())),
        }
    }

    /// Restore the last confirmed runtime state before allocation rehydration
    /// and before readiness. Interrupted desired/applying state is never treated
    /// as observed; the last confirmed snapshot wins deterministically.
    pub async fn restore(&self, bootstrap: &ConfigRuntimeSnapshot) -> Result<(), String> {
        self.backend
            .adopt_node_incarnation(&self.node_id, &self.incarnation)
            .await
            .map_err(|error| format!("adopt node incarnation failed: {error}"))?;

        match self
            .backend
            .get_runtime_state(&self.node_id)
            .await
            .map_err(|error| format!("load runtime state failed: {error}"))?
        {
            None => {
                let persisted = backend_snapshot(bootstrap);
                let prepared = self
                    .backend
                    .cas_runtime_desired(&self.node_id, 0, &self.incarnation, &persisted)
                    .await
                    .map_err(|error| format!("initialize runtime desired state failed: {error}"))?;
                if !prepared {
                    return Err("initialize runtime desired state lost CAS".into());
                }
                let confirmed = self
                    .backend
                    .confirm_runtime_observed(
                        &self.node_id,
                        persisted.version,
                        &self.incarnation,
                        &persisted,
                        "observed",
                        "",
                        None,
                    )
                    .await
                    .map_err(|error| {
                        format!("initialize runtime observed state failed: {error}")
                    })?;
                if !confirmed {
                    return Err("initialize runtime observed state was fenced".into());
                }
                self.store.publish_runtime(session_runtime(bootstrap));
                self.metrics
                    .config_observed_version
                    .store(bootstrap.version, Ordering::Release);
                self.metrics
                    .config_desired_observed_mismatch
                    .store(0, Ordering::Release);
            }
            Some(state) => {
                validate_persisted_snapshot(&state.observed_snapshot, &self.validation_ctx)?;
                if state.observed_snapshot.version != state.observed_version {
                    return Err(format!(
                        "runtime state version mismatch: record={} snapshot={}",
                        state.observed_version, state.observed_snapshot.version
                    ));
                }
                let observed = config_snapshot(&state.observed_snapshot);
                self.store.publish_runtime(session_runtime(&observed));
                self.metrics
                    .config_observed_version
                    .store(observed.version, Ordering::Release);

                let mismatch = state.desired_version != state.observed_version
                    || state.desired_snapshot != state.observed_snapshot;
                self.metrics
                    .config_desired_observed_mismatch
                    .store(if mismatch { 1 } else { 0 }, Ordering::Release);
                self.metrics.config_oldest_unapplied_ms.store(
                    if mismatch {
                        turna_session::epoch_ms().saturating_sub(state.updated_at_ms)
                    } else {
                        0
                    },
                    Ordering::Release,
                );

                if state.status != "observed" || mismatch {
                    let message =
                        "startup restored last confirmed observed snapshot; interrupted desired state was not published";
                    let _ = self
                        .backend
                        .confirm_runtime_observed(
                            &self.node_id,
                            state.desired_version,
                            &self.incarnation,
                            &state.observed_snapshot,
                            "failed",
                            message,
                            None,
                        )
                        .await;
                    warn!(
                        desired_version = state.desired_version,
                        observed_version = state.observed_version,
                        status = %state.status,
                        "runtime restore ignored unconfirmed desired state"
                    );
                }
            }
        }

        let states = self
            .backend
            .list_user_limits_states(&self.node_id)
            .await
            .map_err(|error| format!("load user limits state failed: {error}"))?;
        let mut over_limit = 0u64;
        for state in states {
            if state.schema_version != COMMAND_SCHEMA_VERSION {
                return Err(format!(
                    "unsupported user-limits state schema {} for {}",
                    state.schema_version, state.subject_key
                ));
            }
            validate_target(&state.target)?;
            if !state.observed_patch.is_empty() {
                validate_patch(&state.observed_patch)?;
            }
            let next = snapshot_with_patch(&self.store, &state.target, &state.observed_patch)?;
            self.store
                .publish_user_limits(next)
                .map_err(|error| error.to_string())?;

            if state.status != "observed" || state.desired_version != state.observed_version {
                let message =
                    "startup restored last confirmed observed limits; interrupted desired state was not published";
                let _ = self
                    .backend
                    .confirm_user_limits_observed(
                        &self.node_id,
                        &state.subject_key,
                        state.desired_version,
                        &self.incarnation,
                        &state.observed_patch,
                        ObservationOutcome {
                            status: "failed",
                            error: message,
                        },
                        None,
                    )
                    .await;
                warn!(subject = %state.subject_key, "ignored unconfirmed desired user limits");
            }

            let effective = effective_for_target(&self.store, &state.target);
            let usage = max_user_usage_for_target(&self.store, &state.target);
            if is_over_limit(&effective, usage) {
                over_limit = over_limit.saturating_add(1);
            }
        }
        self.metrics
            .user_limits_over_limit_subjects
            .store(over_limit, Ordering::Release);
        Ok(())
    }

    pub async fn apply_update_config(&self, pending: &PendingCommand) -> (&'static str, String) {
        let started = Instant::now();
        let result = self.apply_update_config_inner(pending).await;
        self.metrics
            .histograms
            .observe(APPLY_HISTOGRAM, started.elapsed());
        let fresh = serialize_result(&result);
        match self
            .record_terminal_outcome(pending, &result.terminal_status, "done", &fresh)
            .await
        {
            RecordedOutcome::Durable(body) => ("done", body),
            RecordedOutcome::RetryLater => (RETRY_LATER_STATUS, String::new()),
        }
    }

    /// #4: journal every NON-`applied` terminal business outcome into the durable
    /// idempotency journal BEFORE the command loop calls `complete_command`, so a
    /// lost completion replays the ORIGINAL outcome instead of re-validating
    /// against since-changed state (`no_op` / `conflict` / `failed`). `applied` is
    /// already journaled atomically inside `confirm_*_observed`.
    ///
    /// The failure is never swallowed:
    ///   * a terminal outcome already durable for this key WINS (returned verbatim);
    ///   * a rejected write against an EXISTING (pending) record → `RetryLater`
    ///     (the caller must NOT complete the command — leave it for reclaim);
    ///   * only when there is no canonical record at all (the command never went
    ///     through the idempotency-guarded enqueue — impossible in production,
    ///     where the key is mandatory) is the fresh body returned best-effort,
    ///     since a retry could not create the record anyway.
    async fn record_terminal_outcome(
        &self,
        pending: &PendingCommand,
        business_outcome: &str,
        transport_status: &str,
        fresh_body: &str,
    ) -> RecordedOutcome {
        if business_outcome == "applied" || pending.idempotency_key.is_empty() {
            return RecordedOutcome::Durable(fresh_body.to_string());
        }
        let payload_hash = command_payload_hash(&pending.op, &pending.args, &pending.payload_json);
        match self
            .backend
            .record_command_outcome(
                &pending.request_id,
                &pending.idempotency_key,
                &payload_hash,
                transport_status,
                fresh_body,
                now_ms(),
            )
            .await
        {
            Ok(_) => RecordedOutcome::Durable(fresh_body.to_string()),
            Err(record_err) => match self.backend.get_idempotency(&pending.idempotency_key).await {
                // A terminal outcome is already durable → it wins (idempotency).
                Ok(Some(rec))
                    if !rec.final_status.is_empty() && rec.payload_hash == payload_hash =>
                {
                    warn!(
                        request_id = %pending.request_id,
                        error = %record_err,
                        "record_command_outcome rejected the fresh outcome; \
                         returning the durable one"
                    );
                    RecordedOutcome::Durable(rec.result)
                }
                // The canonical record exists but is still non-terminal: the
                // durable write genuinely failed. Do NOT complete the command.
                Ok(Some(_)) => {
                    error!(
                        request_id = %pending.request_id,
                        error = %record_err,
                        "failed to persist command outcome to its canonical record; \
                         leaving the command for reclaim rather than completing it"
                    );
                    RecordedOutcome::RetryLater
                }
                // No canonical record at all. Every production command is
                // enqueued through the idempotency-guarded path, so this record
                // MUST exist; its absence is an invariant violation, not a
                // license to complete. Completing here would drop the
                // exactly-once journal entry, so fail closed and leave the
                // command for reclaim (it eventually dead-letters, which is
                // observable) rather than silently completing without a durable
                // outcome.
                Ok(None) => {
                    error!(
                        request_id = %pending.request_id,
                        error = %record_err,
                        "no canonical idempotency record for this command; \
                         leaving it for reclaim rather than completing without a \
                         durable journal entry"
                    );
                    RecordedOutcome::RetryLater
                }
                // The write failed AND the read-back also failed (e.g. a backend
                // outage), so we cannot prove the outcome is durable. Never
                // complete on an unproven outcome — reclaim retries once the
                // backend recovers.
                Err(read_err) => {
                    error!(
                        request_id = %pending.request_id,
                        write_error = %record_err,
                        read_error = %read_err,
                        "failed to persist the command outcome and could not read \
                         it back; leaving the command for reclaim"
                    );
                    RecordedOutcome::RetryLater
                }
            },
        }
    }

    /// #4: exact-replay fast path. Consults the durable idempotency journal by
    /// identity (`idempotency_key` + `payload_hash`) and returns the recorded
    /// terminal result — BEFORE any payload parse, schema/target/incarnation
    /// validation, or current-state load — so a replay after a crash returns the
    /// original outcome even if the incarnation, validation rules, or observed
    /// state have since changed, and even if current state cannot be loaded.
    async fn durable_replay<T: serde::de::DeserializeOwned>(
        &self,
        pending: &PendingCommand,
        payload_hash: &str,
    ) -> Option<T> {
        if pending.idempotency_key.is_empty() {
            return None;
        }
        match self.backend.get_idempotency(&pending.idempotency_key).await {
            Ok(Some(rec)) if !rec.final_status.is_empty() && rec.payload_hash == payload_hash => {
                serde_json::from_str::<T>(&rec.result).ok()
            }
            _ => None,
        }
    }

    async fn apply_update_config_inner(&self, pending: &PendingCommand) -> UpdateConfigResult {
        // #4: exact-replay fast path FIRST — before parse, validation, incarnation
        // check, or state load — so a recorded outcome is returned verbatim even
        // if any of those inputs have since changed.
        let payload_hash = command_payload_hash(&pending.op, &pending.args, &pending.payload_json);
        if let Some(stored) = self
            .durable_replay::<UpdateConfigResult>(pending, &payload_hash)
            .await
        {
            info!(
                request_id = %pending.request_id,
                "update_config replayed from durable journal"
            );
            return stored;
        }

        let current = self.store.runtime_snapshot();
        let current_backend = backend_snapshot_from_session(&current);
        let command: UpdateConfigCommand = match serde_json::from_str(&pending.payload_json) {
            Ok(value) => value,
            Err(error) => {
                return update_failure(
                    &current_backend,
                    "failed",
                    format!("invalid update_config payload: {error}"),
                    false,
                )
            }
        };
        if command.schema_version != COMMAND_SCHEMA_VERSION {
            return update_failure(
                &current_backend,
                "failed",
                format!(
                    "unsupported update_config payload schema {}",
                    command.schema_version
                ),
                false,
            );
        }
        if let Err(error) = self.check_command_target(pending) {
            return update_failure(&current_backend, "failed", error, false);
        }

        let _guard = self.apply_lock.lock().await;
        // §2.2/§2.3: if this exact operation already applied durably (matched by
        // request_id, or idempotency_key + payload_hash), return the stored typed
        // result instead of re-applying — closes the "apply succeeded →
        // complete_command lost → reclaim" window without a spurious conflict.
        let payload_hash = command_payload_hash(&pending.op, &pending.args, &pending.payload_json);
        let durable_state = match self.backend.get_runtime_state(&self.node_id).await {
            Ok(value) => value,
            Err(error) => {
                self.metrics
                    .config_update_failures_total
                    .fetch_add(1, Ordering::Relaxed);
                return update_failure(
                    &current_backend,
                    "failed",
                    format!("load runtime state for idempotency check failed: {error}"),
                    false,
                );
            }
        };
        if let Some(stored) = self
            .stored_terminal_result(
                durable_state.as_ref().and_then(|s| s.last_applied.as_ref()),
                pending,
                &payload_hash,
            )
            .await
        {
            match serde_json::from_str::<UpdateConfigResult>(&stored) {
                Ok(result) => {
                    info!(
                        request_id = %pending.request_id,
                        "update_config already applied durably; returning stored result"
                    );
                    return result;
                }
                Err(error) => {
                    warn!(
                        request_id = %pending.request_id,
                        %error,
                        "stored update_config result undecodable; re-evaluating command"
                    );
                }
            }
        }
        let previous = self.store.runtime_snapshot();
        let previous_backend = backend_snapshot_from_session(&previous);
        let config_current = ConfigRuntimeSnapshot {
            version: previous.version,
            limits: DynamicLimits {
                max_bytes_per_sec_per_allocation: previous.max_bytes_per_sec_per_allocation,
                max_per_user: previous.max_per_user,
                max_allocations: previous.max_allocations,
            },
        };
        let patch = DynamicLimitsPatch {
            max_bytes_per_sec_per_allocation: command.max_bytes_per_sec_per_allocation,
            max_per_user: command.max_allocations_per_user,
            max_allocations: command.max_allocations,
        };
        if patch.is_empty() {
            return update_failure(
                &previous_backend,
                "failed",
                "update_config patch is empty".into(),
                false,
            );
        }

        let applied =
            match config_current.apply(&patch, command.expected_version, &self.validation_ctx) {
                Ok(value) => value,
                Err(ConfigUpdateError::VersionMismatch { expected, actual }) => {
                    self.metrics
                        .config_update_conflicts_total
                        .fetch_add(1, Ordering::Relaxed);
                    return update_failure(
                        &previous_backend,
                        "conflict",
                        format!("version mismatch: expected {expected}, observed {actual}"),
                        false,
                    );
                }
                Err(error) => {
                    self.metrics
                        .config_update_failures_total
                        .fetch_add(1, Ordering::Relaxed);
                    return update_failure(&previous_backend, "failed", error.to_string(), false);
                }
            };

        if !applied.changed {
            self.metrics
                .config_update_noop_total
                .fetch_add(1, Ordering::Relaxed);
            return UpdateConfigResult {
                request_id: String::new(),
                previous_version: previous.version,
                observed_version: previous.version,
                changed: false,
                applied: previous_backend,
                terminal_status: "no_op".into(),
                error: String::new(),
                rolled_back: false,
            };
        }

        let desired = backend_snapshot(&applied.snapshot);
        let prepared = match self
            .backend
            .cas_runtime_desired(&self.node_id, previous.version, &self.incarnation, &desired)
            .await
        {
            Ok(value) => value,
            Err(error) => {
                self.metrics
                    .config_update_failures_total
                    .fetch_add(1, Ordering::Relaxed);
                return update_failure(
                    &previous_backend,
                    "failed",
                    format!("persist desired runtime state failed: {error}"),
                    false,
                );
            }
        };
        if !prepared {
            self.metrics
                .config_update_conflicts_total
                .fetch_add(1, Ordering::Relaxed);
            return update_failure(
                &previous_backend,
                "conflict",
                "runtime desired-state CAS conflict".into(),
                false,
            );
        }

        self.metrics
            .config_desired_observed_mismatch
            .store(1, Ordering::Release);
        self.store
            .publish_runtime(session_runtime(&applied.snapshot));

        // §2.1/§2.3: build the success result up front so it is persisted as
        // durable operation metadata ATOMICALLY with the observed-version bump.
        let success_result = UpdateConfigResult {
            request_id: pending.request_id.clone(),
            previous_version: previous.version,
            observed_version: desired.version,
            changed: true,
            applied: desired.clone(),
            terminal_status: "applied".into(),
            error: String::new(),
            rolled_back: false,
        };
        let applied_op = AppliedOperation {
            request_id: pending.request_id.clone(),
            op: pending.op.clone(),
            idempotency_key: pending.idempotency_key.clone(),
            payload_hash: payload_hash.clone(),
            applied_version: desired.version,
            terminal_result: serialize_result(&success_result),
            applied_at_ms: now_ms(),
        };

        let confirmation_error = match self
            .backend
            .confirm_runtime_observed(
                &self.node_id,
                desired.version,
                &self.incarnation,
                &desired,
                "observed",
                "",
                Some(&applied_op),
            )
            .await
        {
            Ok(true) => None,
            Ok(false) => Some("runtime observed confirmation was fenced".to_string()),
            Err(error) => Some(format!("persist observed runtime state failed: {error}")),
        };
        if let Some(error) = confirmation_error {
            self.store.publish_runtime((*previous).clone());
            self.metrics
                .config_update_failures_total
                .fetch_add(1, Ordering::Relaxed);
            self.metrics
                .config_update_rollback_total
                .fetch_add(1, Ordering::Relaxed);
            self.metrics
                .config_observed_version
                .store(previous.version, Ordering::Release);
            self.metrics
                .config_desired_observed_mismatch
                .store(1, Ordering::Release);
            let _ = self
                .backend
                .confirm_runtime_observed(
                    &self.node_id,
                    desired.version,
                    &self.incarnation,
                    &previous_backend,
                    "failed",
                    &error,
                    None,
                )
                .await;
            update_failure(&previous_backend, "failed", error, true)
        } else {
            self.metrics
                .config_update_applied_total
                .fetch_add(1, Ordering::Relaxed);
            self.metrics
                .config_observed_version
                .store(desired.version, Ordering::Release);
            self.metrics
                .config_desired_observed_mismatch
                .store(0, Ordering::Release);
            self.metrics
                .config_oldest_unapplied_ms
                .store(0, Ordering::Release);
            info!(version = desired.version, "runtime configuration applied");
            success_result
        }
    }

    pub async fn apply_set_user_limits(&self, pending: &PendingCommand) -> (&'static str, String) {
        let started = Instant::now();
        let result = self.apply_set_user_limits_inner(pending).await;
        self.metrics
            .histograms
            .observe(APPLY_HISTOGRAM, started.elapsed());
        let fresh = serialize_result(&result);
        match self
            .record_terminal_outcome(pending, &result.terminal_status, "done", &fresh)
            .await
        {
            RecordedOutcome::Durable(body) => ("done", body),
            RecordedOutcome::RetryLater => (RETRY_LATER_STATUS, String::new()),
        }
    }

    async fn apply_set_user_limits_inner(&self, pending: &PendingCommand) -> SetUserLimitsResult {
        // #4: exact-replay fast path FIRST — before parse, validation, incarnation
        // check, or current-state load.
        let payload_hash = command_payload_hash(&pending.op, &pending.args, &pending.payload_json);
        if let Some(stored) = self
            .durable_replay::<SetUserLimitsResult>(pending, &payload_hash)
            .await
        {
            info!(
                request_id = %pending.request_id,
                "set_user_limits replayed from durable journal"
            );
            return stored;
        }
        let command: SetUserLimitsCommand = match serde_json::from_str(&pending.payload_json) {
            Ok(value) => value,
            Err(error) => {
                return limits_failure(0, 0, format!("invalid set_user_limits payload: {error}"))
            }
        };
        if command.schema_version != COMMAND_SCHEMA_VERSION {
            return limits_failure(
                0,
                0,
                format!(
                    "unsupported set_user_limits payload schema {}",
                    command.schema_version
                ),
            );
        }
        if let Err(error) = self.check_command_target(pending) {
            return limits_failure(0, 0, error);
        }
        if let Err(error) =
            validate_target(&command.target).and_then(|_| validate_patch(&command.patch))
        {
            return limits_failure(0, 0, error);
        }
        // #8: node-side backstop — reject a finite requested lifetime above the
        // absolute protocol ceiling even if it bypassed control-plane ingress
        // (e.g. an older control-plane enqueued it). Defence-in-depth; the
        // effective value is still capped per node/tenant/user at resolution.
        if let Some(limit) = command.patch.max_lifetime_secs.as_ref() {
            if matches!(limit.mode, LimitMode::Value)
                && limit.value > turna_proto_turn::MAX_LIFETIME
            {
                return limits_failure(
                    0,
                    0,
                    format!(
                        "max_lifetime_secs {} exceeds the absolute lifetime ceiling {}",
                        limit.value,
                        turna_proto_turn::MAX_LIFETIME
                    ),
                );
            }
        }

        let _guard = self.apply_lock.lock().await;
        let subject_key = command.target.subject_key();
        let current_state = match self
            .backend
            .get_user_limits_state(&self.node_id, &subject_key)
            .await
        {
            Ok(value) => value,
            Err(error) => {
                self.metrics
                    .user_limits_failures_total
                    .fetch_add(1, Ordering::Relaxed);
                return limits_failure(0, 0, format!("load current user limits failed: {error}"));
            }
        };
        let payload_hash = command_payload_hash(&pending.op, &pending.args, &pending.payload_json);
        if let Some(stored) = self
            .stored_terminal_result(
                current_state.as_ref().and_then(|s| s.last_applied.as_ref()),
                pending,
                &payload_hash,
            )
            .await
        {
            match serde_json::from_str::<SetUserLimitsResult>(&stored) {
                Ok(result) => {
                    info!(
                        request_id = %pending.request_id,
                        "set_user_limits already applied durably; returning stored result"
                    );
                    return result;
                }
                Err(error) => {
                    warn!(
                        request_id = %pending.request_id,
                        %error,
                        "stored set_user_limits result undecodable; re-evaluating command"
                    );
                }
            }
        }
        let previous_version = current_state
            .as_ref()
            .map(|state| state.observed_version)
            .unwrap_or(0);
        if command.expected_version != previous_version {
            self.metrics
                .user_limits_conflicts_total
                .fetch_add(1, Ordering::Relaxed);
            let effective = effective_for_target(&self.store, &command.target);
            let usage = max_user_usage_for_target(&self.store, &command.target);
            return SetUserLimitsResult {
                request_id: String::new(),
                previous_version,
                observed_version: previous_version,
                effective: backend_effective(effective.clone()),
                max_user_allocations_in_scope: usage_u32(usage),
                max_user_allocations_above_limit: is_over_limit(&effective, usage),
                terminal_status: "conflict".into(),
                error: format!(
                    "version mismatch: expected {}, observed {}",
                    command.expected_version, previous_version
                ),
            };
        }

        let previous_patch = current_state
            .as_ref()
            .map(|state| state.observed_patch.clone())
            .unwrap_or_default();
        let previous_effective = effective_for_target(&self.store, &command.target);
        let previous_usage = max_user_usage_for_target(&self.store, &command.target);
        let previous_above = is_over_limit(&previous_effective, previous_usage);
        let candidate = merge_patch(&previous_patch, &command.patch);
        if candidate == previous_patch {
            self.metrics
                .user_limits_noop_total
                .fetch_add(1, Ordering::Relaxed);
            let effective = effective_for_target(&self.store, &command.target);
            let usage = max_user_usage_for_target(&self.store, &command.target);
            return SetUserLimitsResult {
                request_id: String::new(),
                previous_version,
                observed_version: previous_version,
                effective: backend_effective(effective.clone()),
                max_user_allocations_in_scope: usage_u32(usage),
                max_user_allocations_above_limit: is_over_limit(&effective, usage),
                terminal_status: "no_op".into(),
                error: String::new(),
            };
        }

        let desired_version = match previous_version.checked_add(1) {
            Some(v) => v,
            None => {
                self.metrics
                    .user_limits_failures_total
                    .fetch_add(1, Ordering::Relaxed);
                return limits_failure(
                    previous_version,
                    previous_version,
                    "user limits version counter overflow".into(),
                );
            }
        };
        let prepared = match self
            .backend
            .cas_user_limits_desired(
                &self.node_id,
                &subject_key,
                previous_version,
                &self.incarnation,
                &command.target,
                &candidate,
            )
            .await
        {
            Ok(value) => value,
            Err(error) => {
                self.metrics
                    .user_limits_failures_total
                    .fetch_add(1, Ordering::Relaxed);
                return limits_failure(
                    previous_version,
                    previous_version,
                    format!("persist desired user limits failed: {error}"),
                );
            }
        };
        if !prepared {
            self.metrics
                .user_limits_conflicts_total
                .fetch_add(1, Ordering::Relaxed);
            let effective = effective_for_target(&self.store, &command.target);
            let usage = max_user_usage_for_target(&self.store, &command.target);
            return SetUserLimitsResult {
                request_id: String::new(),
                previous_version,
                observed_version: previous_version,
                effective: backend_effective(effective.clone()),
                max_user_allocations_in_scope: usage_u32(usage),
                max_user_allocations_above_limit: is_over_limit(&effective, usage),
                terminal_status: "conflict".into(),
                error: "user-limits desired-state CAS conflict".into(),
            };
        }

        let previous_cache = self.store.user_limits_snapshot();
        let next_cache = match snapshot_with_patch(&self.store, &command.target, &candidate) {
            Ok(value) => value,
            Err(error) => {
                let _ = self
                    .backend
                    .confirm_user_limits_observed(
                        &self.node_id,
                        &subject_key,
                        desired_version,
                        &self.incarnation,
                        &previous_patch,
                        ObservationOutcome {
                            status: "failed",
                            error: &error,
                        },
                        None,
                    )
                    .await;
                return limits_failure(previous_version, previous_version, error);
            }
        };
        if let Err(error) = self.store.publish_user_limits(next_cache) {
            self.metrics
                .user_limits_failures_total
                .fetch_add(1, Ordering::Relaxed);
            return limits_failure(
                previous_version,
                previous_version,
                format!("publish user limits failed: {error}"),
            );
        }

        // §2.1/§2.3: compute the success result up front (the store already
        // reflects the new cache) so it is persisted as durable operation
        // metadata ATOMICALLY with the observed-version bump.
        let effective = effective_for_target(&self.store, &command.target);
        let usage = max_user_usage_for_target(&self.store, &command.target);
        let above = is_over_limit(&effective, usage);
        let success_result = SetUserLimitsResult {
            request_id: pending.request_id.clone(),
            previous_version,
            observed_version: desired_version,
            effective: backend_effective(effective),
            max_user_allocations_in_scope: usage_u32(usage),
            max_user_allocations_above_limit: above,
            terminal_status: "applied".into(),
            error: String::new(),
        };
        let applied_op = AppliedOperation {
            request_id: pending.request_id.clone(),
            op: pending.op.clone(),
            idempotency_key: pending.idempotency_key.clone(),
            payload_hash: payload_hash.clone(),
            applied_version: desired_version,
            terminal_result: serialize_result(&success_result),
            applied_at_ms: now_ms(),
        };

        let confirmation_error = match self
            .backend
            .confirm_user_limits_observed(
                &self.node_id,
                &subject_key,
                desired_version,
                &self.incarnation,
                &candidate,
                ObservationOutcome {
                    status: "observed",
                    error: "",
                },
                Some(&applied_op),
            )
            .await
        {
            Ok(true) => None,
            Ok(false) => Some("user-limits observed confirmation was fenced".to_string()),
            Err(error) => Some(format!("persist observed user limits failed: {error}")),
        };
        if let Some(error) = confirmation_error {
            let _ = self.store.publish_user_limits((*previous_cache).clone());
            self.metrics
                .user_limits_failures_total
                .fetch_add(1, Ordering::Relaxed);
            let _ = self
                .backend
                .confirm_user_limits_observed(
                    &self.node_id,
                    &subject_key,
                    desired_version,
                    &self.incarnation,
                    &previous_patch,
                    ObservationOutcome {
                        status: "failed",
                        error: &error,
                    },
                    None,
                )
                .await;
            limits_failure(previous_version, previous_version, error)
        } else {
            self.metrics
                .user_limits_applied_total
                .fetch_add(1, Ordering::Relaxed);
            adjust_over_limit_gauge(
                &self.metrics.user_limits_over_limit_subjects,
                previous_above,
                above,
            );
            info!(subject = %subject_key, version = desired_version, "user limits applied");
            success_result
        }
    }

    /// §2.4: finalize stale-incarnation commands targeting this node that a
    /// prior incarnation left non-terminal. Per command: if the durable state
    /// shows it already applied (by request_id, or idempotency_key + payload
    /// hash), finalize with the stored result; otherwise finalize with a typed
    /// `superseded` result. A transient backend read error skips that command so
    /// a later tick retries. Returns the count finalized.
    pub async fn sweep_stale_commands(&self) -> usize {
        let stale = match self
            .backend
            .list_stale_commands(&self.node_id, &self.incarnation, MAX_STALE_SWEEP)
            .await
        {
            Ok(commands) => commands,
            Err(error) => {
                warn!(%error, "sweep: listing stale commands failed");
                return 0;
            }
        };
        let mut finalized = 0usize;
        for cmd in stale {
            let result = match cmd.op.as_str() {
                "update_config" => self.stale_update_config_result(&cmd).await,
                "set_user_limits" => self.stale_set_user_limits_result(&cmd).await,
                // Non-versioned ops never carry a target incarnation and so are
                // never returned by list_stale_commands; ignore defensively.
                _ => continue,
            };
            let result = match result {
                Some(value) => value,
                None => continue,
            };
            match self
                .backend
                .finalize_stale_command(&cmd.request_id, &self.incarnation, &result)
                .await
            {
                Ok(true) => {
                    finalized += 1;
                    info!(request_id = %cmd.request_id, op = %cmd.op,
                          "finalized stale-incarnation command");
                }
                Ok(false) => {}
                Err(error) => {
                    warn!(%error, request_id = %cmd.request_id,
                          "sweep: finalizing stale command failed");
                }
            }
        }
        finalized
    }

    /// Build the finalize result for a stale `update_config`: the stored result
    /// if it already applied durably, else a typed `superseded`. `None` on a
    /// transient backend read error (skip; retry next tick).
    async fn stale_update_config_result(&self, pending: &PendingCommand) -> Option<String> {
        let payload_hash = command_payload_hash(&pending.op, &pending.args, &pending.payload_json);
        let durable = match self.backend.get_runtime_state(&self.node_id).await {
            Ok(value) => value,
            Err(error) => {
                warn!(%error, request_id = %pending.request_id,
                      "sweep: loading runtime state failed; will retry");
                return None;
            }
        };
        if let Some(stored) = self
            .stored_terminal_result(
                durable.as_ref().and_then(|s| s.last_applied.as_ref()),
                pending,
                &payload_hash,
            )
            .await
        {
            return Some(stored);
        }
        let snapshot = self.store.runtime_snapshot();
        let current = backend_snapshot_from_session(&snapshot);
        Some(serialize_result(&update_failure(
            &current,
            "superseded",
            STALE_SUPERSEDED_MSG.into(),
            false,
        )))
    }

    /// Build the finalize result for a stale `set_user_limits`: the stored result
    /// if it already applied durably, else a typed `superseded`.
    async fn stale_set_user_limits_result(&self, pending: &PendingCommand) -> Option<String> {
        let command: SetUserLimitsCommand = match serde_json::from_str(&pending.payload_json) {
            Ok(value) => value,
            Err(error) => {
                // Undecodable payload: subject unknown, so a stored-result match
                // is impossible. The stale command's business outcome is still
                // `superseded`; emit it with a diagnostic error.
                warn!(%error, request_id = %pending.request_id,
                      "sweep: undecodable set_user_limits payload; finalizing as superseded");
                return Some(serialize_result(&limits_terminal(
                    0,
                    0,
                    "superseded",
                    STALE_SUPERSEDED_MSG.into(),
                )));
            }
        };
        let subject_key = command.target.subject_key();
        let payload_hash = command_payload_hash(&pending.op, &pending.args, &pending.payload_json);
        let durable = match self
            .backend
            .get_user_limits_state(&self.node_id, &subject_key)
            .await
        {
            Ok(value) => value,
            Err(error) => {
                warn!(%error, request_id = %pending.request_id,
                      "sweep: loading user-limits state failed; will retry");
                return None;
            }
        };
        if let Some(stored) = self
            .stored_terminal_result(
                durable.as_ref().and_then(|s| s.last_applied.as_ref()),
                pending,
                &payload_hash,
            )
            .await
        {
            return Some(stored);
        }
        let observed = durable.as_ref().map(|s| s.observed_version).unwrap_or(0);
        Some(serialize_result(&limits_terminal(
            observed,
            observed,
            "superseded",
            STALE_SUPERSEDED_MSG.into(),
        )))
    }

    /// #5: durable lost-completion lookup. Returns the stored terminal result
    /// for a command that already reached a terminal outcome, or `None`.
    ///
    /// The node-local `last_applied` slot only remembers the MOST RECENT applied
    /// operation, so a replay/finalize of an older, interleaved command would
    /// miss it and be wrongly re-applied or finalized as `superseded`. The
    /// authoritative source is the durable idempotency journal
    /// (`turna_command_idem`), keyed by `idempotency_key` and retained for
    /// `retain_idempotency_secs` (>= every command retention window). We consult
    /// it on a fast-path miss. The payload hash must match exactly, so a legacy
    /// empty-hash row never yields a false replay.
    async fn stored_terminal_result(
        &self,
        last: Option<&AppliedOperation>,
        pending: &PendingCommand,
        payload_hash: &str,
    ) -> Option<String> {
        if let Some(stored) = already_applied(last, pending, payload_hash) {
            return Some(stored.to_string());
        }
        if pending.idempotency_key.is_empty() {
            return None;
        }
        match self.backend.get_idempotency(&pending.idempotency_key).await {
            Ok(Some(rec)) if !rec.final_status.is_empty() && rec.payload_hash == payload_hash => {
                Some(rec.result)
            }
            _ => None,
        }
    }

    fn check_command_target(&self, pending: &PendingCommand) -> Result<(), String> {
        if pending.target_node_id != self.node_id {
            return Err(format!(
                "command target {} does not match local node {}",
                pending.target_node_id, self.node_id
            ));
        }
        if pending.target_incarnation.is_empty() {
            return Err("versioned command is missing target incarnation".into());
        }
        if pending.target_incarnation != self.incarnation {
            return Err(format!(
                "stale command incarnation {}; local incarnation is {}",
                pending.target_incarnation, self.incarnation
            ));
        }
        Ok(())
    }
}

/// §2.2: has this exact operation already been applied durably? Matched by
/// `request_id`, or (for a retry that minted a new request_id under the same
/// idempotency key) by `idempotency_key` + `payload_hash`. On a hit the caller
/// returns the stored typed result verbatim instead of re-applying.
fn already_applied<'a>(
    last: Option<&'a AppliedOperation>,
    pending: &PendingCommand,
    payload_hash: &str,
) -> Option<&'a str> {
    let op = last?;
    let hit = op.request_id == pending.request_id
        || (!pending.idempotency_key.is_empty()
            && op.idempotency_key == pending.idempotency_key
            && op.payload_hash == payload_hash);
    if hit {
        Some(op.terminal_result.as_str())
    } else {
        None
    }
}

fn validate_persisted_snapshot(
    snapshot: &RuntimeConfigSnapshot,
    ctx: &RuntimeValidationCtx,
) -> Result<(), String> {
    if snapshot.schema_version != RuntimeConfigSnapshot::SCHEMA_VERSION {
        return Err(format!(
            "unsupported runtime snapshot schema {}",
            snapshot.schema_version
        ));
    }
    let errors = DynamicLimits {
        max_bytes_per_sec_per_allocation: snapshot.max_bytes_per_sec_per_allocation,
        max_per_user: snapshot.max_allocations_per_user,
        max_allocations: snapshot.max_allocations,
    }
    .validate(ctx);
    if errors.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "persisted runtime snapshot is invalid: {}",
            errors.join("; ")
        ))
    }
}

fn backend_snapshot(snapshot: &ConfigRuntimeSnapshot) -> RuntimeConfigSnapshot {
    RuntimeConfigSnapshot {
        schema_version: RuntimeConfigSnapshot::SCHEMA_VERSION,
        version: snapshot.version,
        max_allocations: snapshot.limits.max_allocations,
        max_allocations_per_user: snapshot.limits.max_per_user,
        max_bytes_per_sec_per_allocation: snapshot.limits.max_bytes_per_sec_per_allocation,
    }
}

fn backend_snapshot_from_session(snapshot: &RuntimeLimits) -> RuntimeConfigSnapshot {
    RuntimeConfigSnapshot {
        schema_version: RuntimeConfigSnapshot::SCHEMA_VERSION,
        version: snapshot.version,
        max_allocations: snapshot.max_allocations,
        max_allocations_per_user: snapshot.max_per_user,
        max_bytes_per_sec_per_allocation: snapshot.max_bytes_per_sec_per_allocation,
    }
}

fn config_snapshot(snapshot: &RuntimeConfigSnapshot) -> ConfigRuntimeSnapshot {
    ConfigRuntimeSnapshot {
        version: snapshot.version,
        limits: DynamicLimits {
            max_bytes_per_sec_per_allocation: snapshot.max_bytes_per_sec_per_allocation,
            max_per_user: snapshot.max_allocations_per_user,
            max_allocations: snapshot.max_allocations,
        },
    }
}

fn session_runtime(snapshot: &ConfigRuntimeSnapshot) -> RuntimeLimits {
    RuntimeLimits {
        version: snapshot.version,
        max_bytes_per_sec_per_allocation: snapshot.limits.max_bytes_per_sec_per_allocation,
        max_per_user: snapshot.limits.max_per_user,
        max_allocations: snapshot.limits.max_allocations,
    }
}

fn validate_target(target: &UserLimitTarget) -> Result<(), String> {
    match target.scope {
        UserLimitScope::Global => {
            if !target.realm.is_empty() || !target.tenant.is_empty() || !target.username.is_empty()
            {
                return Err(
                    "global limit target must not contain realm, tenant, or username".into(),
                );
            }
        }
        UserLimitScope::Tenant => {
            if target.realm.trim().is_empty() || target.tenant.trim().is_empty() {
                return Err("tenant limit target requires realm and tenant".into());
            }
            if !target.username.is_empty() {
                return Err("tenant limit target must not contain username".into());
            }
        }
        UserLimitScope::User => {
            if target.realm.trim().is_empty() || target.username.trim().is_empty() {
                return Err("user limit target requires realm and username".into());
            }
        }
    }
    Ok(())
}

fn validate_patch(patch: &UserLimitsPatch) -> Result<(), String> {
    if patch.is_empty() {
        return Err("user-limits patch is empty".into());
    }
    if let Some(value) = &patch.max_allocations {
        validate_u32("max_allocations", value)?;
    }
    if let Some(value) = &patch.max_bytes_per_sec_per_allocation {
        validate_u64("max_bytes_per_sec_per_allocation", value)?;
    }
    if let Some(value) = &patch.max_lifetime_secs {
        validate_u32("max_lifetime_secs", value)?;
    }
    Ok(())
}

fn validate_u32(name: &str, value: &LimitU32) -> Result<(), String> {
    match value.mode {
        LimitMode::Value if value.value == 0 => Err(format!(
            "{name}: VALUE requires a non-zero value; use UNLIMITED or DISABLED explicitly"
        )),
        LimitMode::Value => Ok(()),
        _ if value.value != 0 => Err(format!("{name}: non-VALUE mode must carry value=0")),
        _ => Ok(()),
    }
}

fn validate_u64(name: &str, value: &LimitU64) -> Result<(), String> {
    match value.mode {
        LimitMode::Value if value.value == 0 => Err(format!(
            "{name}: VALUE requires a non-zero value; use UNLIMITED or DISABLED explicitly"
        )),
        LimitMode::Value => Ok(()),
        _ if value.value != 0 => Err(format!("{name}: non-VALUE mode must carry value=0")),
        _ => Ok(()),
    }
}

fn merge_patch(current: &UserLimitsPatch, patch: &UserLimitsPatch) -> UserLimitsPatch {
    fn merge_u32(current: &Option<LimitU32>, patch: &Option<LimitU32>) -> Option<LimitU32> {
        match patch {
            None => current.clone(),
            Some(value) if value.mode == LimitMode::Inherit => None,
            Some(value) => Some(value.clone()),
        }
    }

    fn merge_u64(current: &Option<LimitU64>, patch: &Option<LimitU64>) -> Option<LimitU64> {
        match patch {
            None => current.clone(),
            Some(value) if value.mode == LimitMode::Inherit => None,
            Some(value) => Some(value.clone()),
        }
    }

    UserLimitsPatch {
        max_allocations: merge_u32(&current.max_allocations, &patch.max_allocations),
        max_bytes_per_sec_per_allocation: merge_u64(
            &current.max_bytes_per_sec_per_allocation,
            &patch.max_bytes_per_sec_per_allocation,
        ),
        max_lifetime_secs: merge_u32(&current.max_lifetime_secs, &patch.max_lifetime_secs),
    }
}

fn session_mode(mode: LimitMode) -> SessionLimitMode {
    match mode {
        LimitMode::Inherit => SessionLimitMode::Inherit,
        LimitMode::Value => SessionLimitMode::Value,
        LimitMode::Unlimited => SessionLimitMode::Unlimited,
        LimitMode::Disabled => SessionLimitMode::Disabled,
    }
}

fn session_override(patch: &UserLimitsPatch) -> UserLimitsOverride {
    UserLimitsOverride {
        max_allocations: patch.max_allocations.as_ref().map(|value| SessionLimitU32 {
            mode: session_mode(value.mode),
            value: value.value,
        }),
        max_bytes_per_sec_per_allocation: patch.max_bytes_per_sec_per_allocation.as_ref().map(
            |value| SessionLimitU64 {
                mode: session_mode(value.mode),
                value: value.value,
            },
        ),
        max_lifetime_secs: patch
            .max_lifetime_secs
            .as_ref()
            .map(|value| SessionLimitU32 {
                mode: session_mode(value.mode),
                value: value.value,
            }),
    }
}

fn scope_name(scope: UserLimitScope) -> &'static str {
    match scope {
        UserLimitScope::Global => "global",
        UserLimitScope::Tenant => "tenant",
        UserLimitScope::User => "user",
    }
}

fn snapshot_with_patch(
    store: &AllocationStore,
    target: &UserLimitTarget,
    patch: &UserLimitsPatch,
) -> Result<turna_session::UserLimitsSnapshot, String> {
    store
        .limits_snapshot_with_override(
            scope_name(target.scope),
            &target.realm,
            &target.tenant,
            &target.username,
            session_override(patch),
        )
        .map_err(|error| format!("build immutable limits snapshot failed: {error}"))
}

fn effective_for_target(
    store: &AllocationStore,
    target: &UserLimitTarget,
) -> SessionEffectiveUserLimits {
    match target.scope {
        UserLimitScope::Global => store.effective_user_limits("", None, ""),
        UserLimitScope::Tenant => {
            store.effective_user_limits(&target.realm, Some(&target.tenant), "")
        }
        UserLimitScope::User => store.effective_user_limits(
            &target.realm,
            (!target.tenant.is_empty()).then_some(target.tenant.as_str()),
            &target.username,
        ),
    }
}

fn max_user_usage_for_target(store: &AllocationStore, target: &UserLimitTarget) -> usize {
    match target.scope {
        UserLimitScope::Global => store.max_user_usage(),
        UserLimitScope::Tenant => store.max_user_usage_in_tenant(&target.realm, &target.tenant),
        UserLimitScope::User => store.current_user_usage(
            &target.realm,
            (!target.tenant.is_empty()).then_some(target.tenant.as_str()),
            &target.username,
        ),
    }
}

fn usage_u32(usage: usize) -> u32 {
    usage.min(u32::MAX as usize) as u32
}

fn adjust_over_limit_gauge(gauge: &std::sync::atomic::AtomicU64, was_over: bool, is_over: bool) {
    match (was_over, is_over) {
        (false, true) => {
            gauge.fetch_add(1, Ordering::Relaxed);
        }
        (true, false) => {
            let _ = gauge.fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                Some(value.saturating_sub(1))
            });
        }
        _ => {}
    }
}

fn is_over_limit(effective: &SessionEffectiveUserLimits, usage: usize) -> bool {
    (effective.allocations_disabled && usage > 0)
        || (effective.max_allocations > 0 && usage > effective.max_allocations)
}

fn backend_effective(value: SessionEffectiveUserLimits) -> EffectiveUserLimits {
    EffectiveUserLimits {
        max_allocations: value.max_allocations.min(u32::MAX as usize) as u32,
        allocations_disabled: value.allocations_disabled,
        max_bytes_per_sec_per_allocation: value.max_bytes_per_sec_per_allocation,
        bandwidth_disabled: value.bandwidth_disabled,
        max_lifetime_secs: value.max_lifetime_secs,
        lifetime_disabled: value.lifetime_disabled,
        inherited_fields: value.inherited_fields,
        capped_fields: value.capped_fields,
    }
}

fn update_failure(
    snapshot: &RuntimeConfigSnapshot,
    status: &str,
    error: String,
    rolled_back: bool,
) -> UpdateConfigResult {
    UpdateConfigResult {
        request_id: String::new(),
        previous_version: snapshot.version,
        observed_version: snapshot.version,
        changed: false,
        applied: snapshot.clone(),
        terminal_status: status.into(),
        error,
        rolled_back,
    }
}

fn limits_failure(
    previous_version: u64,
    observed_version: u64,
    error: String,
) -> SetUserLimitsResult {
    limits_terminal(previous_version, observed_version, "failed", error)
}

fn limits_terminal(
    previous_version: u64,
    observed_version: u64,
    status: &str,
    error: String,
) -> SetUserLimitsResult {
    SetUserLimitsResult {
        request_id: String::new(),
        previous_version,
        observed_version,
        effective: EffectiveUserLimits::default(),
        max_user_allocations_in_scope: 0,
        max_user_allocations_above_limit: false,
        terminal_status: status.into(),
        error,
    }
}

fn serialize_result<T: serde::Serialize>(result: &T) -> String {
    serde_json::to_string(result).unwrap_or_else(|error| {
        format!(
            "{{\"terminal_status\":\"failed\",\"error\":\"result serialization failed: {}\"}}",
            error
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use turna_state_backend::{Backend, InMemoryBackend};

    fn bootstrap() -> ConfigRuntimeSnapshot {
        ConfigRuntimeSnapshot {
            version: 0,
            limits: DynamicLimits {
                max_bytes_per_sec_per_allocation: 1_000,
                max_per_user: 4,
                max_allocations: 10,
            },
        }
    }

    fn validation_ctx() -> RuntimeValidationCtx {
        RuntimeValidationCtx {
            min_port: 50_000,
            max_port: 50_020,
            production: false,
            allow_unlimited_bandwidth: true,
        }
    }

    fn new_store() -> Arc<AllocationStore> {
        let store = Arc::new(AllocationStore::new(50_000, 50_020, 10));
        store.publish_runtime(session_runtime(&bootstrap()));
        store.set_bootstrap_max_lifetime(600);
        store
    }

    fn new_backend() -> Arc<Backend> {
        Arc::new(Backend::Memory(InMemoryBackend::new()))
    }

    fn manager(
        incarnation: &str,
        store: Arc<AllocationStore>,
        backend: Arc<Backend>,
    ) -> RuntimeManagement {
        RuntimeManagement::new(
            "node-a".into(),
            incarnation.into(),
            store,
            backend,
            Arc::new(Metrics::new()),
            validation_ctx(),
        )
    }

    fn pending<T: serde::Serialize>(op: &str, incarnation: &str, payload: &T) -> PendingCommand {
        // Each call is a DISTINCT logical command: unique request_id and
        // idempotency_key so the §2 last_applied guard only recognises a genuine
        // replay (the same struct reused), never two independent apply() calls.
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        PendingCommand {
            request_id: format!("req-{op}-{n}"),
            target_node_id: "node-a".into(),
            op: op.into(),
            args: Vec::new(),
            payload_json: serde_json::to_string(payload).unwrap(),
            target_incarnation: incarnation.into(),
            status: "in_progress".into(),
            result: String::new(),
            created_at_ms: 0,
            updated_at_ms: 0,
            claimed_by: "node-a".into(),
            lease_until_ms: u64::MAX,
            attempts: 1,
            claim_token: "claim".into(),
            idempotency_key: format!("idem-{op}-{n}"),
        }
    }

    fn decode_update(raw: &str) -> UpdateConfigResult {
        serde_json::from_str(raw).unwrap()
    }

    fn decode_limits(raw: &str) -> SetUserLimitsResult {
        serde_json::from_str(raw).unwrap()
    }

    fn user_target() -> UserLimitTarget {
        UserLimitTarget {
            scope: UserLimitScope::User,
            tenant: "tenant-a".into(),
            realm: "realm-a".into(),
            username: "alice".into(),
        }
    }

    #[tokio::test]
    async fn update_config_applies_atomically_then_noops_and_conflicts() {
        let backend = new_backend();
        let store = new_store();
        let manager = manager("inc-1", Arc::clone(&store), Arc::clone(&backend));
        manager.restore(&bootstrap()).await.unwrap();

        let first = UpdateConfigCommand {
            schema_version: COMMAND_SCHEMA_VERSION,
            expected_version: 0,
            max_allocations: Some(8),
            max_allocations_per_user: Some(2),
            max_bytes_per_sec_per_allocation: Some(500),
            reason: "test".into(),
        };
        let (_, raw) = manager
            .apply_update_config(&pending("update_config", "inc-1", &first))
            .await;
        let applied = decode_update(&raw);
        assert_eq!(applied.terminal_status, "applied");
        assert_eq!(applied.previous_version, 0);
        assert_eq!(applied.observed_version, 1);
        assert!(applied.changed);
        let snapshot = store.runtime_snapshot();
        assert_eq!(snapshot.version, 1);
        assert_eq!(snapshot.max_allocations, 8);
        assert_eq!(snapshot.max_per_user, 2);
        assert_eq!(snapshot.max_bytes_per_sec_per_allocation, 500);

        let no_op = UpdateConfigCommand {
            expected_version: 1,
            ..first.clone()
        };
        let no_op_cmd = pending("update_config", "inc-1", &no_op);
        backend.enqueue_command(&no_op_cmd).await.unwrap();
        let (_, raw) = manager.apply_update_config(&no_op_cmd).await;
        let no_op = decode_update(&raw);
        assert_eq!(no_op.terminal_status, "no_op");
        assert_eq!(no_op.observed_version, 1);
        assert!(!no_op.changed);

        let stale = UpdateConfigCommand {
            expected_version: 0,
            max_allocations: Some(7),
            ..first
        };
        let stale_cmd = pending("update_config", "inc-1", &stale);
        backend.enqueue_command(&stale_cmd).await.unwrap();
        let (_, raw) = manager.apply_update_config(&stale_cmd).await;
        let conflict = decode_update(&raw);
        assert_eq!(conflict.terminal_status, "conflict");
        assert_eq!(store.runtime_snapshot().version, 1);
    }

    #[tokio::test]
    async fn concurrent_config_updates_with_same_version_apply_only_once() {
        let backend = new_backend();
        let store = new_store();
        let manager = manager("inc-1", store, Arc::clone(&backend));
        manager.restore(&bootstrap()).await.unwrap();

        let a = pending(
            "update_config",
            "inc-1",
            &UpdateConfigCommand {
                schema_version: COMMAND_SCHEMA_VERSION,
                expected_version: 0,
                max_allocations: Some(8),
                max_allocations_per_user: None,
                max_bytes_per_sec_per_allocation: None,
                reason: "a".into(),
            },
        );
        let b = pending(
            "update_config",
            "inc-1",
            &UpdateConfigCommand {
                schema_version: COMMAND_SCHEMA_VERSION,
                expected_version: 0,
                max_allocations: Some(9),
                max_allocations_per_user: None,
                max_bytes_per_sec_per_allocation: None,
                reason: "b".into(),
            },
        );
        backend.enqueue_command(&a).await.unwrap();
        backend.enqueue_command(&b).await.unwrap();
        let (left, right) = tokio::join!(
            manager.apply_update_config(&a),
            manager.apply_update_config(&b)
        );
        let mut statuses = vec![
            decode_update(&left.1).terminal_status,
            decode_update(&right.1).terminal_status,
        ];
        statuses.sort();
        assert_eq!(
            statuses,
            vec!["applied".to_string(), "conflict".to_string()]
        );
    }

    #[tokio::test]
    async fn restart_restores_only_confirmed_runtime_and_limits_state() {
        let backend = new_backend();
        let first_store = new_store();
        let first = manager("inc-1", Arc::clone(&first_store), Arc::clone(&backend));
        first.restore(&bootstrap()).await.unwrap();

        let update = UpdateConfigCommand {
            schema_version: COMMAND_SCHEMA_VERSION,
            expected_version: 0,
            max_allocations: None,
            max_allocations_per_user: Some(3),
            max_bytes_per_sec_per_allocation: Some(700),
            reason: "persist".into(),
        };
        let (_, raw) = first
            .apply_update_config(&pending("update_config", "inc-1", &update))
            .await;
        assert_eq!(decode_update(&raw).terminal_status, "applied");

        let limits = SetUserLimitsCommand {
            schema_version: COMMAND_SCHEMA_VERSION,
            expected_version: 0,
            target: user_target(),
            patch: UserLimitsPatch {
                max_allocations: Some(LimitU32 {
                    mode: LimitMode::Value,
                    value: 2,
                }),
                max_bytes_per_sec_per_allocation: Some(LimitU64 {
                    mode: LimitMode::Value,
                    value: 200,
                }),
                max_lifetime_secs: Some(LimitU32 {
                    mode: LimitMode::Value,
                    value: 120,
                }),
            },
            reason: "persist".into(),
        };
        let (_, raw) = first
            .apply_set_user_limits(&pending("set_user_limits", "inc-1", &limits))
            .await;
        assert_eq!(decode_limits(&raw).terminal_status, "applied");

        let restarted_store = new_store();
        let restarted = manager("inc-2", Arc::clone(&restarted_store), Arc::clone(&backend));
        restarted.restore(&bootstrap()).await.unwrap();

        let restored_runtime = restarted_store.runtime_snapshot();
        assert_eq!(restored_runtime.version, 1);
        assert_eq!(restored_runtime.max_per_user, 3);
        assert_eq!(restored_runtime.max_bytes_per_sec_per_allocation, 700);
        let effective = restarted_store.effective_user_limits("realm-a", Some("tenant-a"), "alice");
        assert_eq!(effective.max_allocations, 2);
        assert_eq!(effective.max_bytes_per_sec_per_allocation, 200);
        assert_eq!(effective.max_lifetime_secs, 120);
    }

    #[tokio::test]
    async fn lowering_user_cap_below_usage_keeps_allocations_and_blocks_new_ones() {
        let backend = new_backend();
        let store = new_store();
        let manager = manager("inc-1", Arc::clone(&store), backend);
        manager.restore(&bootstrap()).await.unwrap();

        for index in 0..2_u16 {
            store
                .create_for_identity(
                    format!("127.0.0.1:{}", 40_000 + index).parse().unwrap(),
                    format!("127.0.0.1:{}", 50_000 + index).parse().unwrap(),
                    "alice".into(),
                    vec![1; 16],
                    300,
                    "realm-a".into(),
                    Some("tenant-a".into()),
                )
                .unwrap();
        }

        let command = SetUserLimitsCommand {
            schema_version: COMMAND_SCHEMA_VERSION,
            expected_version: 0,
            target: user_target(),
            patch: UserLimitsPatch {
                max_allocations: Some(LimitU32 {
                    mode: LimitMode::Value,
                    value: 1,
                }),
                ..UserLimitsPatch::default()
            },
            reason: "reduce".into(),
        };
        let (_, raw) = manager
            .apply_set_user_limits(&pending("set_user_limits", "inc-1", &command))
            .await;
        let result = decode_limits(&raw);
        assert_eq!(result.terminal_status, "applied");
        assert_eq!(result.max_user_allocations_in_scope, 2);
        assert!(result.max_user_allocations_above_limit);
        assert_eq!(store.len(), 2, "existing allocations must remain active");

        let new_allocation = store.create_for_identity(
            "127.0.0.1:40002".parse().unwrap(),
            "127.0.0.1:50002".parse().unwrap(),
            "alice".into(),
            vec![1; 16],
            300,
            "realm-a".into(),
            Some("tenant-a".into()),
        );
        assert!(new_allocation.is_err(), "new allocation must be refused");
    }

    #[tokio::test]
    async fn inherit_removes_one_override_without_erasing_other_fields() {
        let backend = new_backend();
        let store = new_store();
        let manager = manager("inc-1", Arc::clone(&store), Arc::clone(&backend));
        manager.restore(&bootstrap()).await.unwrap();

        let initial = SetUserLimitsCommand {
            schema_version: COMMAND_SCHEMA_VERSION,
            expected_version: 0,
            target: user_target(),
            patch: UserLimitsPatch {
                max_allocations: Some(LimitU32 {
                    mode: LimitMode::Value,
                    value: 1,
                }),
                max_bytes_per_sec_per_allocation: Some(LimitU64 {
                    mode: LimitMode::Value,
                    value: 123,
                }),
                max_lifetime_secs: None,
            },
            reason: "set".into(),
        };
        let (_, raw) = manager
            .apply_set_user_limits(&pending("set_user_limits", "inc-1", &initial))
            .await;
        assert_eq!(decode_limits(&raw).observed_version, 1);

        let inherit = SetUserLimitsCommand {
            schema_version: COMMAND_SCHEMA_VERSION,
            expected_version: 1,
            target: user_target(),
            patch: UserLimitsPatch {
                max_allocations: Some(LimitU32 {
                    mode: LimitMode::Inherit,
                    value: 0,
                }),
                ..UserLimitsPatch::default()
            },
            reason: "inherit".into(),
        };
        let (_, raw) = manager
            .apply_set_user_limits(&pending("set_user_limits", "inc-1", &inherit))
            .await;
        let result = decode_limits(&raw);
        assert_eq!(result.terminal_status, "applied");
        assert_eq!(result.observed_version, 2);
        let effective = store.effective_user_limits("realm-a", Some("tenant-a"), "alice");
        assert_eq!(effective.max_allocations, 4, "allocation cap must inherit");
        assert_eq!(
            effective.max_bytes_per_sec_per_allocation, 123,
            "other override must remain"
        );

        let repeated = SetUserLimitsCommand {
            expected_version: 2,
            ..inherit
        };
        let repeated_cmd = pending("set_user_limits", "inc-1", &repeated);
        backend.enqueue_command(&repeated_cmd).await.unwrap();
        let (_, raw) = manager.apply_set_user_limits(&repeated_cmd).await;
        assert_eq!(decode_limits(&raw).terminal_status, "no_op");
    }

    #[tokio::test]
    async fn reapply_same_command_returns_stored_result_not_conflict() {
        // §2.2/§2.3: a re-delivered command (lost completion, reclaim, restart)
        // whose operation already applied durably returns the ORIGINAL result via
        // the last_applied guard — not a version conflict, and without a second
        // side effect.
        let backend = new_backend();
        let store = new_store();
        let manager = manager("inc-1", Arc::clone(&store), Arc::clone(&backend));
        manager.restore(&bootstrap()).await.unwrap();

        let cmd = UpdateConfigCommand {
            schema_version: COMMAND_SCHEMA_VERSION,
            expected_version: 0,
            max_allocations: Some(8),
            max_allocations_per_user: Some(2),
            max_bytes_per_sec_per_allocation: Some(500),
            reason: "test".into(),
        };
        let command = pending("update_config", "inc-1", &cmd);

        let (status1, raw1) = manager.apply_update_config(&command).await;
        assert_eq!(status1, "done");
        assert_eq!(decode_update(&raw1).terminal_status, "applied");
        assert_eq!(store.runtime_snapshot().version, 1);

        // Re-deliver the exact same command (same request_id + idem key + payload).
        let (status2, raw2) = manager.apply_update_config(&command).await;
        assert_eq!(status2, "done");
        let replay = decode_update(&raw2);
        assert_eq!(
            replay.terminal_status, "applied",
            "replay returns the stored applied result, not a conflict"
        );
        assert_eq!(replay.observed_version, 1);
        assert_eq!(
            store.runtime_snapshot().version,
            1,
            "the guard must prevent a second apply"
        );
    }

    #[tokio::test]
    async fn sweep_finalizes_stale_update_config_as_superseded() {
        // §2.4: a command left non-terminal by a prior incarnation (inc-1) is
        // finalized to done + superseded by the current incarnation (inc-2), with
        // no side effect on runtime config.
        let backend = new_backend();
        let store = new_store();
        let manager = manager("inc-2", Arc::clone(&store), Arc::clone(&backend));
        manager.restore(&bootstrap()).await.unwrap();

        let cmd = UpdateConfigCommand {
            schema_version: COMMAND_SCHEMA_VERSION,
            expected_version: 0,
            max_allocations: Some(9),
            max_allocations_per_user: Some(3),
            max_bytes_per_sec_per_allocation: Some(600),
            reason: "stale".into(),
        };
        // Target the OLD incarnation; never claimed by inc-2.
        let stale = pending("update_config", "inc-1", &cmd);
        backend.enqueue_command(&stale).await.unwrap();

        let version_before = store.runtime_snapshot().version;
        let swept = manager.sweep_stale_commands().await;
        assert_eq!(swept, 1);

        let got = backend
            .get_command(&stale.request_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.status, "done");
        assert_eq!(decode_update(&got.result).terminal_status, "superseded");
        assert_eq!(
            store.runtime_snapshot().version,
            version_before,
            "the sweeper must not apply a stale command"
        );
    }

    #[tokio::test]
    async fn lost_completion_recovers_from_idem_journal_when_last_applied_misses() {
        // #5: the node-local `last_applied` slot only remembers the most-recent
        // applied op. An older, interleaved command must still recover its
        // terminal result from the durable idempotency journal — not be wrongly
        // re-applied or finalized as `superseded`.
        let store = new_store();
        let backend = new_backend();
        let mgr = manager("inc-1", store, backend.clone());

        // Drive one command to a durable terminal outcome via the real path:
        // enqueue → claim → complete (mirrors the command-worker ceremony).
        let mut cmd = pending("update_config", "inc-1", &serde_json::json!({ "x": 1 }));
        cmd.status = "pending".into();
        backend.enqueue_command(&cmd).await.unwrap();
        let claimed = backend
            .claim_commands("node-a", "inc-1", 10, 60_000)
            .await
            .unwrap();
        let token = claimed
            .iter()
            .find(|c| c.request_id == cmd.request_id)
            .map(|c| c.claim_token.clone())
            .expect("command claimed");
        let stored = "{\"terminal_status\":\"applied\"}".to_string();
        assert!(backend
            .complete_command(&cmd.request_id, "node-a", &token, "applied", &stored)
            .await
            .unwrap());

        let hash = command_payload_hash(&cmd.op, &cmd.args, &cmd.payload_json);

        // last_applied = None (as if a later op overwrote the single slot): the
        // fast path misses, the durable journal fallback recovers the result.
        let recovered = mgr.stored_terminal_result(None, &cmd, &hash).await;
        assert_eq!(recovered.as_deref(), Some(stored.as_str()));

        // A mismatched payload hash must never yield a false replay.
        let miss = mgr
            .stored_terminal_result(None, &cmd, "different-hash")
            .await;
        assert!(miss.is_none());
    }

    #[tokio::test]
    async fn node_rejects_lifetime_above_absolute_ceiling() {
        // #8: node-side backstop — a finite max_lifetime_secs above the absolute
        // protocol ceiling is refused at apply even if it bypassed control-plane
        // ingress, and nothing is published.
        let backend = new_backend();
        let store = new_store();
        let manager = manager("inc-1", Arc::clone(&store), Arc::clone(&backend));
        manager.restore(&bootstrap()).await.unwrap();

        let command = SetUserLimitsCommand {
            schema_version: COMMAND_SCHEMA_VERSION,
            expected_version: 0,
            target: user_target(),
            patch: UserLimitsPatch {
                max_lifetime_secs: Some(LimitU32 {
                    mode: LimitMode::Value,
                    value: turna_proto_turn::MAX_LIFETIME + 1,
                }),
                ..UserLimitsPatch::default()
            },
            reason: "too-long".into(),
        };
        let cmd = pending("set_user_limits", "inc-1", &command);
        backend.enqueue_command(&cmd).await.unwrap();
        let (_, raw) = manager.apply_set_user_limits(&cmd).await;
        let result = decode_limits(&raw);
        assert_eq!(result.terminal_status, "failed");
        assert!(
            result.error.contains("absolute lifetime ceiling"),
            "expected ceiling rejection, got: {}",
            result.error
        );
    }

    // ── #4: durable outcome survives a lost completion + state change ────────

    fn base_update() -> UpdateConfigCommand {
        UpdateConfigCommand {
            schema_version: COMMAND_SCHEMA_VERSION,
            expected_version: 0,
            max_allocations: Some(8),
            max_allocations_per_user: Some(2),
            max_bytes_per_sec_per_allocation: Some(500),
            reason: "init".into(),
        }
    }

    // Bring the node to observed version 1 via a real applied update.
    async fn init_v1(manager: &RuntimeManagement, backend: &Arc<Backend>) {
        let init = base_update();
        let cmd = pending("update_config", "inc-1", &init);
        backend.enqueue_command(&cmd).await.unwrap();
        let (_, raw) = manager.apply_update_config(&cmd).await;
        assert_eq!(decode_update(&raw).terminal_status, "applied");
    }

    #[tokio::test]
    async fn no_op_outcome_survives_lost_completion_and_state_change() {
        let backend = new_backend();
        let store = new_store();
        let manager = manager("inc-1", Arc::clone(&store), Arc::clone(&backend));
        manager.restore(&bootstrap()).await.unwrap();
        init_v1(&manager, &backend).await;

        // A no_op (same values, expected_version = 1). Enqueue creates the
        // canonical idempotency record; apply records the outcome but we simulate
        // a LOST completion (complete_command is never called).
        let noop = UpdateConfigCommand {
            expected_version: 1,
            ..base_update()
        };
        let noop_cmd = pending("update_config", "inc-1", &noop);
        backend.enqueue_command(&noop_cmd).await.unwrap();
        let (_, raw1) = manager.apply_update_config(&noop_cmd).await;
        assert_eq!(decode_update(&raw1).terminal_status, "no_op");

        // State moves underneath: a different command bumps the version to 2.
        let change = UpdateConfigCommand {
            expected_version: 1,
            max_allocations: Some(9),
            ..base_update()
        };
        let change_cmd = pending("update_config", "inc-1", &change);
        backend.enqueue_command(&change_cmd).await.unwrap();
        manager.apply_update_config(&change_cmd).await;
        assert_eq!(store.runtime_snapshot().version, 2);

        // Replay the ORIGINAL no_op. Without the durable outcome it would now
        // re-validate against version 2 (expected 1) and flip to a conflict; the
        // recorded outcome must make it return the original no_op verbatim.
        let (_, raw2) = manager.apply_update_config(&noop_cmd).await;
        assert_eq!(
            decode_update(&raw2).terminal_status,
            "no_op",
            "replay after state change must return the recorded no_op"
        );
        assert_eq!(
            store.runtime_snapshot().version,
            2,
            "replay must not mutate"
        );
    }

    #[tokio::test]
    async fn conflict_outcome_survives_lost_completion_and_state_change() {
        let backend = new_backend();
        let store = new_store();
        let manager = manager("inc-1", Arc::clone(&store), Arc::clone(&backend));
        manager.restore(&bootstrap()).await.unwrap();
        init_v1(&manager, &backend).await;

        // A stale command (expected_version = 0) → conflict against version 1.
        let stale = UpdateConfigCommand {
            expected_version: 0,
            max_allocations: Some(7),
            ..base_update()
        };
        let stale_cmd = pending("update_config", "inc-1", &stale);
        backend.enqueue_command(&stale_cmd).await.unwrap();
        let (_, raw1) = manager.apply_update_config(&stale_cmd).await;
        let c1 = decode_update(&raw1);
        assert_eq!(c1.terminal_status, "conflict");
        assert_eq!(c1.observed_version, 1);

        // Move the version to 2.
        let change = UpdateConfigCommand {
            expected_version: 1,
            max_allocations: Some(9),
            ..base_update()
        };
        let change_cmd = pending("update_config", "inc-1", &change);
        backend.enqueue_command(&change_cmd).await.unwrap();
        manager.apply_update_config(&change_cmd).await;
        assert_eq!(store.runtime_snapshot().version, 2);

        // Replay the ORIGINAL stale command. A fresh re-validation would report
        // the conflict against version 2; recovery must return the recorded
        // conflict (observed_version = 1) verbatim.
        let (_, raw2) = manager.apply_update_config(&stale_cmd).await;
        let c2 = decode_update(&raw2);
        assert_eq!(c2.terminal_status, "conflict");
        assert_eq!(
            c2.observed_version, 1,
            "replay must return the recorded conflict, not re-validate against v2"
        );
    }

    #[tokio::test]
    async fn failed_outcome_is_durably_recorded_and_replays() {
        let backend = new_backend();
        let store = new_store();
        let manager = manager("inc-1", Arc::clone(&store), Arc::clone(&backend));
        manager.restore(&bootstrap()).await.unwrap();

        // A permanently invalid command (unsupported payload schema) → failed.
        let bad = UpdateConfigCommand {
            schema_version: 999,
            ..base_update()
        };
        let bad_cmd = pending("update_config", "inc-1", &bad);
        backend.enqueue_command(&bad_cmd).await.unwrap();
        let (_, raw1) = manager.apply_update_config(&bad_cmd).await;
        assert_eq!(decode_update(&raw1).terminal_status, "failed");

        // The failed outcome is durable (recorded before any completion).
        let rec = backend
            .get_idempotency(&bad_cmd.idempotency_key)
            .await
            .unwrap()
            .expect("idempotency record exists");
        assert!(
            !rec.final_status.is_empty(),
            "failed outcome recorded durably"
        );
        assert!(rec.result.contains("failed"));

        // Replay returns the same failed outcome.
        let (_, raw2) = manager.apply_update_config(&bad_cmd).await;
        assert_eq!(decode_update(&raw2).terminal_status, "failed");
    }

    #[tokio::test]
    async fn command_not_completed_when_outcome_cannot_be_journaled() {
        let backend = new_backend();
        let store = new_store();
        let manager = manager("inc-1", Arc::clone(&store), Arc::clone(&backend));
        manager.restore(&bootstrap()).await.unwrap();
        init_v1(&manager, &backend).await; // version -> 1

        // A canonical record exists for the key (enqueued with payload P1).
        let p1 = UpdateConfigCommand {
            expected_version: 1,
            ..base_update()
        };
        let c1 = pending("update_config", "inc-1", &p1);
        backend.enqueue_command(&c1).await.unwrap();

        // A DIFFERENT command reuses the same key with a different payload (P2)
        // and produces a non-applied outcome. Its result cannot be journaled
        // against the P1 record (identity/hash mismatch) and no terminal outcome
        // is durable → apply must signal retry so the loop does NOT complete it.
        let p2 = UpdateConfigCommand {
            expected_version: 0,
            max_allocations: Some(7),
            ..base_update()
        };
        let mut c2 = pending("update_config", "inc-1", &p2);
        c2.idempotency_key = c1.idempotency_key.clone();
        let (status, _) = manager.apply_update_config(&c2).await;
        assert_eq!(
            status, RETRY_LATER_STATUS,
            "an un-journaled outcome must not complete the command"
        );
    }

    #[tokio::test]
    async fn command_not_completed_when_backend_read_and_write_fail() {
        let backend = new_backend();
        let store = new_store();
        let manager = manager("inc-1", Arc::clone(&store), Arc::clone(&backend));
        manager.restore(&bootstrap()).await.unwrap();
        init_v1(&manager, &backend).await; // version -> 1

        // A command with a canonical record that yields a non-applied outcome:
        // stale expected_version (0 vs current 1) → business `conflict`, so it
        // must be journaled via record_command_outcome before completing.
        let stale = UpdateConfigCommand {
            expected_version: 0,
            ..base_update()
        };
        let c = pending("update_config", "inc-1", &stale);
        backend.enqueue_command(&c).await.unwrap();

        // Simulate a backend outage AFTER the record was created: BOTH the
        // outcome write and every read-back now fail. The durable-replay fast
        // path misses (read errors → treated as "no stored result"), the handler
        // re-derives the conflict, then record_command_outcome fails AND the
        // read-back to prove durability also fails.
        if let Backend::Memory(m) = &*backend {
            m.set_idempotency_fault(true);
        }

        // The outcome cannot be proven durable, so apply must fail closed: signal
        // retry so the command loop does NOT complete it (it stays claimed until
        // lease expiry + reclaim once the backend recovers).
        let (status, _) = manager.apply_update_config(&c).await;
        assert_eq!(
            status, RETRY_LATER_STATUS,
            "when the write and the read-back both fail, the outcome is unprovable \
             and the command must not be completed"
        );
    }

    #[tokio::test]
    async fn replay_returns_durable_outcome_across_incarnation_change() {
        let backend = new_backend();
        let store = new_store();
        let manager1 = manager("inc-1", Arc::clone(&store), Arc::clone(&backend));
        manager1.restore(&bootstrap()).await.unwrap();

        // Apply (and journal) an `applied` outcome under inc-1.
        let cmd = pending("update_config", "inc-1", &base_update());
        backend.enqueue_command(&cmd).await.unwrap();
        let (_, raw1) = manager1.apply_update_config(&cmd).await;
        assert_eq!(decode_update(&raw1).terminal_status, "applied");

        // Replay the SAME command under a NEW incarnation. The command targets
        // inc-1, which the incarnation check would reject under inc-2 — but the
        // journal replay precedes that check and returns the original outcome.
        let manager2 = manager("inc-2", Arc::clone(&store), Arc::clone(&backend));
        let (_, raw2) = manager2.apply_update_config(&cmd).await;
        assert_eq!(
            decode_update(&raw2).terminal_status,
            "applied",
            "replay across an incarnation change returns the durable outcome, \
             not a target-mismatch failure"
        );
    }
}
