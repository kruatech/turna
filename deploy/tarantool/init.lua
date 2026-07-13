-- deploy/tarantool/init.lua
--
-- One-shot bootstrap for a Tarantool instance backing a turna
-- cluster. Idempotent: safe to re-run after upgrades — every create
-- uses `if_not_exists = true` and every grant uses `if_not_exists`.
--
-- # What this does
--
--   1. Configures the iproto listener and disables `guest` access.
--   2. Creates three spaces: turna_allocations, turna_nodes, turna_rooms.
--   3. Creates the indexes turna relies on for performance.
--   4. Creates a dedicated role `turna_app` with exactly the rights
--      turna needs — read + write on its own spaces, nothing else.
--   5. Creates a user `turna` (default name; override via TURNA_USER env)
--      with a generated password, grants it `turna_app`, and prints the
--      password to STDOUT once. The operator captures it from the log
--      and feeds it back via TURNA_BACKEND_PASSWORD.
--
-- # Usage
--
-- On the Tarantool host, with the Tarantool server stopped:
--
--   sudo -u tarantool tarantool /path/to/deploy/tarantool/init.lua
--
-- Or against a running Tarantool via `tt connect`:
--
--   tt connect admin:adminpw@127.0.0.1:3301 -f deploy/tarantool/init.lua
--
-- The Tarantool admin user must exist already and have superuser
-- privileges; if you're on a fresh install, the default `admin` user
-- works once you've set its password via `box.schema.user.passwd()`.
--
-- # Environment variables read
--
--   TURNA_USER             — application user name (default: "turna")
--   TURNA_PASSWORD         — application user password. If unset, a
--                          random 32-byte hex password is generated
--                          and printed once.
--   TURNA_LISTEN           — iproto bind address (default: "0.0.0.0:3301")
--   TURNA_WORK_DIR         — Tarantool data dir (default: "/var/lib/tarantool")
--   TURNA_MEMTX_MEMORY     — memtx_memory in bytes (default: 1 GiB)
--
-- # Operator checklist
--
--   [ ] Run this script.
--   [ ] Note the printed password (or supply TURNA_PASSWORD).
--   [ ] Drop it into a secret store (Vault, systemd LoadCredential, k8s
--       Secret) — never commit, never paste in chat.
--   [ ] On the turna-node host, set TURNA_BACKEND_URI, TURNA_BACKEND_USER,
--       TURNA_BACKEND_PASSWORD.
--   [ ] In turn.toml under [cluster.persistence] set mode = "write_behind".
--   [ ] Start turna-node. Logs should show:
--         "state backend: tarantool" + "Tarantool schema initialized"

local function env(name, default)
    local v = os.getenv(name)
    if v == nil or v == "" then return default end
    return v
end

local APP_USER   = env("TURNA_USER",         "turna")
local LISTEN     = env("TURNA_LISTEN",       "0.0.0.0:3301")
local WORK_DIR   = env("TURNA_WORK_DIR",     "/var/lib/tarantool")
local MEMORY     = tonumber(env("TURNA_MEMTX_MEMORY", tostring(1024 * 1024 * 1024)))

-- Generate a password if the operator didn't supply one. 32 hex chars
-- = 128 bits of entropy; matches `openssl rand -hex 16`.
local function gen_password()
    local fd = io.open("/dev/urandom", "rb")
    if fd == nil then
        error("cannot open /dev/urandom; supply TURNA_PASSWORD instead")
    end
    local raw = fd:read(16)
    fd:close()
    local hex = ""
    for i = 1, #raw do
        hex = hex .. string.format("%02x", string.byte(raw, i))
    end
    return hex
end

local APP_PASSWORD = env("TURNA_PASSWORD", nil)
local generated_password = false
if APP_PASSWORD == nil then
    APP_PASSWORD = gen_password()
    generated_password = true
end

-- box.cfg may already be running (when invoked via `tt connect`); in that
-- case calling it again with the same options is a no-op. When run as a
-- standalone tarantool process, this is what brings the engine up.
if box.info == nil or box.info.status ~= "running" then
    box.cfg{
        listen        = LISTEN,
        work_dir      = WORK_DIR,
        memtx_memory  = MEMORY,
        log_level     = 5,
    }
end

print("─────────────────────────────────────────────────")
print("turna Tarantool bootstrap")
print(string.format("  listen       : %s", LISTEN))
print(string.format("  app user     : %s", APP_USER))
print(string.format("  memtx_memory : %d bytes", MEMORY))
print("─────────────────────────────────────────────────")

-- ── 1. Lock down guest ──────────────────────────────────────────────────────
-- Default Tarantool installs grant `guest` read access to every space.
-- Revoke it: the only way in is via the named user we create below.
pcall(function()
    box.schema.user.revoke("guest", "read,write,execute", "universe",
                           nil, { if_exists = true })
end)

-- ── 2. Spaces ────────────────────────────────────────────────────────────────
-- These match the Rust-side INIT_SCRIPT in crates/state-backend/src/tarantool.rs.
-- If you change one place, change both.

box.schema.space.create("turna_allocations", { if_not_exists = true })
box.space.turna_allocations:format({
    { name = "relay_port",    type = "unsigned" },
    { name = "user_id",       type = "string"   },
    { name = "node_id",       type = "string"   },
    { name = "expires_at_ms", type = "unsigned" },
    { name = "data",          type = "string"   },
})
box.space.turna_allocations:create_index("primary",
    { parts = { "relay_port" },    if_not_exists = true })
box.space.turna_allocations:create_index("by_user",
    { parts = { "user_id" },       unique = false, if_not_exists = true })
box.space.turna_allocations:create_index("by_node",
    { parts = { "node_id" },       unique = false, if_not_exists = true })
box.space.turna_allocations:create_index("by_expiry",
    { parts = { "expires_at_ms" }, unique = false, if_not_exists = true })

box.schema.space.create("turna_nodes", { if_not_exists = true })
box.space.turna_nodes:format({
    { name = "node_id", type = "string" },
    { name = "data",    type = "string" },
})
box.space.turna_nodes:create_index("primary",
    { parts = { "node_id" }, if_not_exists = true })

box.schema.space.create("turna_rooms", { if_not_exists = true })
box.space.turna_rooms:format({
    { name = "room_id", type = "string" },
    { name = "data",    type = "string" },
})
box.space.turna_rooms:create_index("primary",
    { parts = { "room_id" }, if_not_exists = true })

box.schema.space.create("turna_token_blacklist", { if_not_exists = true })
box.space.turna_token_blacklist:format({
    { name = "jti",           type = "string"   },
    { name = "sub",           type = "string"   },
    { name = "revoked_at_ms", type = "unsigned" },
    { name = "expires_at_ms", type = "unsigned" },
})
box.space.turna_token_blacklist:create_index("primary",
    { parts = { "jti" }, if_not_exists = true })
box.space.turna_token_blacklist:create_index("by_expiry",
    { parts = { "expires_at_ms" }, unique = false, if_not_exists = true })

-- R8: runtime long-term users (Variant B — two pre-derived keys, no password).
box.schema.space.create("turna_users", { if_not_exists = true })
box.space.turna_users:format({
    { name = "username", type = "string" },
    { name = "realm",    type = "string" },
    { name = "data",     type = "string" },
})
box.space.turna_users:create_index("primary",
    { parts = { "username", "realm" }, if_not_exists = true })

-- P0 #4: control->node command log. Control-plane enqueues; the owning node
-- claims (pending->in_progress), applies, and completes (done/failed).
box.schema.space.create("turna_commands", { if_not_exists = true })
box.space.turna_commands:format({
    { name = "request_id",     type = "string" },
    { name = "target_node_id", type = "string" },
    { name = "data",           type = "string" },  -- full PendingCommand JSON
    -- Command-log GC: status + updated_at_ms are promoted to indexed columns so GC scans
    -- only terminal rows via `by_status` instead of the whole space. The `data`
    -- blob stays authoritative; these mirror d.status / d.updated_at_ms and are
    -- nullable so a pre-2b command row keeps parsing (GC falls back to leaving
    -- such legacy rows for the next completion to backfill).
    { name = "status",         type = "string",   is_nullable = true },
    { name = "updated_at_ms",  type = "unsigned", is_nullable = true },
})
box.space.turna_commands:create_index("primary",
    { parts = { "request_id" }, if_not_exists = true })
box.space.turna_commands:create_index("by_node",
    { parts = { "target_node_id" }, unique = false, if_not_exists = true })
box.space.turna_commands:create_index("by_status",
    { parts = {{ field = 4, type = "string", is_nullable = true }},
      unique = false, if_not_exists = true })

-- Durable idempotency records: keyed by idempotency_key, each carrying the
-- payload hash + terminal outcome. Retained INDEPENDENTLY of the command
-- (retain_idempotency_secs, which must be >= the longest terminal window) so a
-- record deliberately OUTLIVES its command — a replay after the command row is
-- GC'd still recovers the outcome. turna_enqueue_command dedups on it so a retried
-- management op (same key, new request_id) creates at most one command.
box.schema.space.create("turna_command_idem", { if_not_exists = true })
box.space.turna_command_idem:format({
    { name = "idempotency_key", type = "string" },
    { name = "request_id",      type = "string" },
    -- The record outlives the command it guards, carrying the payload hash
    -- (conflict detection) + terminal outcome/timestamps (post-prune replay
    -- returns the prior result; GC prunes via `by_completed`). All nullable so a
    -- pre-2b 2-field row still reads (legacy rows never trigger a false conflict).
    { name = "payload_hash",    type = "string",   is_nullable = true },
    { name = "final_status",    type = "string",   is_nullable = true },
    { name = "result",          type = "string",   is_nullable = true },
    { name = "created_at_ms",   type = "unsigned", is_nullable = true },
    { name = "completed_at_ms", type = "unsigned", is_nullable = true },
})
box.space.turna_command_idem:create_index("primary",
    { parts = { "idempotency_key" }, if_not_exists = true })
box.space.turna_command_idem:create_index("by_completed",
    { parts = {{ field = 7, type = "unsigned", is_nullable = true }},
      unique = false, if_not_exists = true })


-- Durable desired/observed runtime configuration per node.
box.schema.space.create("turna_runtime_state", { if_not_exists = true })
box.space.turna_runtime_state:format({
    { name = "node_id",          type = "string" },
    { name = "observed_version", type = "unsigned" },
    { name = "desired_version",  type = "unsigned" },
    { name = "status",           type = "string" },
    { name = "updated_at_ms",    type = "unsigned" },
    { name = "data",             type = "string" },
})
box.space.turna_runtime_state:create_index("primary",
    { parts = { "node_id" }, if_not_exists = true })
box.space.turna_runtime_state:create_index("by_status",
    { parts = { "status" }, unique = false, if_not_exists = true })

-- Durable global/tenant/user limits overrides. `state_key` length-prefixes
-- node_id before the already length-prefixed subject key, avoiding delimiter
-- collisions without exposing subjects as separate high-cardinality indexes.
box.schema.space.create("turna_user_limits", { if_not_exists = true })
box.space.turna_user_limits:format({
    { name = "state_key",        type = "string" },
    { name = "node_id",          type = "string" },
    { name = "subject_key",      type = "string" },
    { name = "observed_version", type = "unsigned" },
    { name = "desired_version",  type = "unsigned" },
    { name = "status",           type = "string" },
    { name = "updated_at_ms",    type = "unsigned" },
    { name = "data",             type = "string" },
})
box.space.turna_user_limits:create_index("primary",
    { parts = { "state_key" }, if_not_exists = true })
box.space.turna_user_limits:create_index("by_node",
    { parts = { "node_id" }, unique = false, if_not_exists = true })

-- Versioned, resumable migration progress. Each migration stores its last
-- processed primary-key cursor and completion flag; no startup full scan.
box.schema.space.create("turna_migrations", { if_not_exists = true })
box.space.turna_migrations:format({
    { name = "name",             type = "string" },
    { name = "cursor",           type = "string" },
    { name = "processed",        type = "unsigned" },
    { name = "completed",        type = "boolean" },
    { name = "updated_at_ms",    type = "unsigned" },
    -- #4 (B): phased/leased migration state. Nullable so a pre-B v1 row
    -- (5 fields) still reads. #2: `lease_generation` is a monotonic fencing
    -- token bumped on every new lease acquisition (takeover/first grab), so a
    -- stale page from an expired lease cannot apply even under the same owner.
    { name = "phase",            type = "string",   is_nullable = true },
    { name = "errors",           type = "unsigned", is_nullable = true },
    { name = "owner",            type = "string",   is_nullable = true },
    { name = "lease_expires_ms", type = "unsigned", is_nullable = true },
    { name = "lease_generation", type = "unsigned", is_nullable = true },
})
box.space.turna_migrations:create_index("primary",
    { parts = { "name" }, if_not_exists = true })

-- ── 3. Stored functions ──────────────────────────────────────────────────────
-- All data operations go through stored functions called via iproto CALL.
-- This means turna_app needs `execute on function <name>` only — NOT
-- `execute on universe`. A compromised turna-node cannot execute arbitrary
-- Lua, read _user/_priv, or touch any space outside these functions.
--
-- Functions receive string args (from Rust's &[&str] encoding); tonumber()
-- converts where needed. Tarantool 2.x wraps the body as function(...) end.

-- Drop and recreate stored functions on every run so body changes take effect.
-- (if_not_exists alone won't update an existing function's body.)
local TURNA_FUNCS_ALL = {
    "turna_init_schema",
    "turna_store_allocation", "turna_get_allocation",    "turna_remove_allocation",
    "turna_update_bandwidth", "turna_find_by_user",      "turna_find_by_node",
    "turna_find_expired",     "turna_count_allocations", "turna_list_allocations",
    "turna_store_heartbeat",  "turna_get_live_nodes",
    "turna_store_room",       "turna_get_room",          "turna_remove_room",
    "turna_ping",             "turna_claim_allocation",
    "turna_revoke_token", "turna_is_token_revoked",
    "turna_cleanup_revoked_tokens", "turna_load_active_revocations",
    "turna_store_user", "turna_get_user", "turna_remove_user", "turna_list_users",
    "turna_enqueue_command", "turna_claim_commands",
    "turna_complete_command", "turna_get_command", "turna_get_idempotency",
    "turna_record_command_outcome",
    "turna_finalize_stale_command",
    "turna_list_stale_commands",
    "turna_gc_command_log", "turna_migrate_command_log_batch",
    "turna_migration_idem_fetch", "turna_migration_idem_apply",
    "turna_get_runtime_state", "turna_adopt_node_incarnation",
    "turna_cas_runtime_desired", "turna_confirm_runtime_observed",
    "turna_get_user_limits_state", "turna_list_user_limits_states",
    "turna_cas_user_limits_desired", "turna_confirm_user_limits_observed",
}
for _, fn_name in ipairs(TURNA_FUNCS_ALL) do
    box.schema.func.drop(fn_name, { if_exists = true })
end

-- #5: single canonical uint64 version parser, shared by every runtime/limits
-- CAS and confirm below (all is_sandboxed=false, so they see this global). Rust
-- passes versions as decimal strings and Tarantool stores them in `unsigned`
-- tuple fields / decodes large JSON integers as cdata; a plain tonumber() would
-- route any of these through a Lua double and silently lose integer precision
-- above 2^53. This normalizes string / number / cdata to an exact uint64 cdata
-- and refuses negative, fractional, or malformed input — never a silent wrap.
--
-- #6.5 CONTRACT (see deploy/tarantool/tests/u64_parser_test.lua):
--   * Accepts: a `cdata` uint64 (non-negative), a `number` that is a
--     non-negative integer < 2^53, or a decimal `string` matching `^%d+$`.
--   * Decimal strings are the ONLY way to pass a value >= 2^53 (a `number`
--     >= 2^53 is rejected precisely because a double cannot represent it).
--   * Leading zeros in a string are allowed ("01" -> 1); a sign ("+1"/"-1"),
--     spaces, decimals ("1.5"), empty string, or any non-digit are rejected.
--   * Returns a `uint64_t` cdata; the value never passes through a Lua double
--     for comparison or arithmetic, so equality/CAS is exact across all of u64.
--   * u64::MAX + 1 (and beyond) is rejected via a round-trip check, never wrapped.
function turna_parse_u64_exact(v)
    local ffi = require('ffi')
    local tv = type(v)
    if tv == 'cdata' then
        if tostring(v):sub(1, 1) == '-' then
            error('turna_parse_u64_exact: negative version', 0)
        end
        return ffi.cast('uint64_t', v)
    elseif tv == 'number' then
        if v < 0 then error('turna_parse_u64_exact: negative version', 0) end
        if v ~= math.floor(v) then
            error('turna_parse_u64_exact: fractional version', 0)
        end
        -- Above 2^53 a double cannot represent every integer exactly, so such a
        -- value must arrive as a decimal string, never a Lua number.
        if v >= 9007199254740992 then
            error('turna_parse_u64_exact: numeric version exceeds exact range; pass a string', 0)
        end
        return ffi.cast('uint64_t', v)
    elseif tv == 'string' then
        if not string.match(v, '^%d+$') then
            error('turna_parse_u64_exact: non-integer version string: ' .. v, 0)
        end
        local n = tonumber64(v)
        if n == nil then
            error('turna_parse_u64_exact: unparseable version string: ' .. v, 0)
        end
        local u = ffi.cast('uint64_t', n)
        -- #6: guard against silent overflow/truncation. The cast must round-trip
        -- back to the same decimal (ignoring leading zeros); u64::MAX + 1 and
        -- beyond therefore cannot slip through as a wrapped value even if the
        -- underlying tonumber64 does not itself reject out-of-range input.
        local normalized = v:gsub('^0+(%d)', '%1')
        if tostring(u):gsub('ULL$', '') ~= normalized then
            error('turna_parse_u64_exact: version string out of uint64 range: ' .. v, 0)
        end
        return u
    end
    error('turna_parse_u64_exact: unsupported version type ' .. tv, 0)
end

-- body must be the FULL function text: function(...) ... end
-- Tarantool prepends "return" to get the function object at load time.
-- is_sandboxed = false, setuid = true gives access to box.* at call time.

box.schema.func.create("turna_init_schema", {
    language = "LUA",
    is_sandboxed = false, setuid = true,
    body = [[function()
        box.schema.space.create("turna_allocations", { if_not_exists = true })
        box.space.turna_allocations:format({
            { name = "relay_port",    type = "unsigned" },
            { name = "user_id",       type = "string"   },
            { name = "node_id",       type = "string"   },
            { name = "expires_at_ms", type = "unsigned" },
            { name = "data",          type = "string"   },
        })
        box.space.turna_allocations:create_index("primary",
            { parts = { "relay_port" },    if_not_exists = true })
        box.space.turna_allocations:create_index("by_user",
            { parts = { "user_id" },       unique = false, if_not_exists = true })
        box.space.turna_allocations:create_index("by_node",
            { parts = { "node_id" },       unique = false, if_not_exists = true })
        box.space.turna_allocations:create_index("by_expiry",
            { parts = { "expires_at_ms" }, unique = false, if_not_exists = true })
        box.schema.space.create("turna_nodes", { if_not_exists = true })
        box.space.turna_nodes:format({
            { name = "node_id", type = "string" },
            { name = "data",    type = "string" },
        })
        box.space.turna_nodes:create_index("primary",
            { parts = { "node_id" }, if_not_exists = true })
        box.schema.space.create("turna_rooms", { if_not_exists = true })
        box.space.turna_rooms:format({
            { name = "room_id", type = "string" },
            { name = "data",    type = "string" },
        })
        box.space.turna_rooms:create_index("primary",
            { parts = { "room_id" }, if_not_exists = true })
        box.schema.space.create("turna_users", { if_not_exists = true })
        box.space.turna_users:format({
            { name = "username", type = "string" },
            { name = "realm",    type = "string" },
            { name = "data",     type = "string" },
        })
        box.space.turna_users:create_index("primary",
            { parts = { "username", "realm" }, if_not_exists = true })
        -- Command log + idempotency map (kept in sync with the top-level schema
        -- so a node that only calls turna_init_schema still gets them).
        box.schema.space.create("turna_commands", { if_not_exists = true })
        box.space.turna_commands:format({
            { name = "request_id",     type = "string" },
            { name = "target_node_id", type = "string" },
            { name = "data",           type = "string" },
            { name = "status",         type = "string",   is_nullable = true },
            { name = "updated_at_ms",  type = "unsigned", is_nullable = true },
        })
        box.space.turna_commands:create_index("primary",
            { parts = { "request_id" }, if_not_exists = true })
        box.space.turna_commands:create_index("by_node",
            { parts = { "target_node_id" }, unique = false, if_not_exists = true })
        box.space.turna_commands:create_index("by_status",
            { parts = {{ field = 4, type = "string", is_nullable = true }},
              unique = false, if_not_exists = true })
        box.schema.space.create("turna_command_idem", { if_not_exists = true })
        box.space.turna_command_idem:format({
            { name = "idempotency_key", type = "string" },
            { name = "request_id",      type = "string" },
            { name = "payload_hash",    type = "string",   is_nullable = true },
            { name = "final_status",    type = "string",   is_nullable = true },
            { name = "result",          type = "string",   is_nullable = true },
            { name = "created_at_ms",   type = "unsigned", is_nullable = true },
            { name = "completed_at_ms", type = "unsigned", is_nullable = true },
        })
        box.space.turna_command_idem:create_index("primary",
            { parts = { "idempotency_key" }, if_not_exists = true })
        box.space.turna_command_idem:create_index("by_completed",
            { parts = {{ field = 7, type = "unsigned", is_nullable = true }},
              unique = false, if_not_exists = true })
        box.schema.space.create("turna_runtime_state", { if_not_exists = true })
        box.space.turna_runtime_state:format({
            { name = "node_id",          type = "string" },
            { name = "observed_version", type = "unsigned" },
            { name = "desired_version",  type = "unsigned" },
            { name = "status",           type = "string" },
            { name = "updated_at_ms",    type = "unsigned" },
            { name = "data",             type = "string" },
        })
        box.space.turna_runtime_state:create_index("primary",
            { parts = { "node_id" }, if_not_exists = true })
        box.space.turna_runtime_state:create_index("by_status",
            { parts = { "status" }, unique = false, if_not_exists = true })
        box.schema.space.create("turna_user_limits", { if_not_exists = true })
        box.space.turna_user_limits:format({
            { name = "state_key",        type = "string" },
            { name = "node_id",          type = "string" },
            { name = "subject_key",      type = "string" },
            { name = "observed_version", type = "unsigned" },
            { name = "desired_version",  type = "unsigned" },
            { name = "status",           type = "string" },
            { name = "updated_at_ms",    type = "unsigned" },
            { name = "data",             type = "string" },
        })
        box.space.turna_user_limits:create_index("primary",
            { parts = { "state_key" }, if_not_exists = true })
        box.space.turna_user_limits:create_index("by_node",
            { parts = { "node_id" }, unique = false, if_not_exists = true })
        box.schema.space.create("turna_migrations", { if_not_exists = true })
        box.space.turna_migrations:format({
            { name = "name",             type = "string" },
            { name = "cursor",           type = "string" },
            { name = "processed",        type = "unsigned" },
            { name = "completed",        type = "boolean" },
            { name = "updated_at_ms",    type = "unsigned" },
            { name = "phase",            type = "string",   is_nullable = true },
            { name = "errors",           type = "unsigned", is_nullable = true },
            { name = "owner",            type = "string",   is_nullable = true },
            { name = "lease_expires_ms", type = "unsigned", is_nullable = true },
            { name = "lease_generation", type = "unsigned", is_nullable = true },
        })
        box.space.turna_migrations:create_index("primary",
            { parts = { "name" }, if_not_exists = true })
        -- Legacy metadata is retained for compatibility, but migration work is
        -- performed only by turna_migrate_command_log_batch in bounded calls.
        -- Schema-version marker so the one-time rolling-upgrade backfill below
        -- runs ONCE (on the first init_schema after upgrade) instead of full-
        -- scanning turna_commands / turna_command_idem on every node startup.
        box.schema.space.create("turna_meta", { if_not_exists = true })
        box.space.turna_meta:format({
            { name = "key",   type = "string" },
            { name = "value", type = "string" },
        })
        box.space.turna_meta:create_index("primary",
            { parts = { "key" }, if_not_exists = true })
        -- No unbounded startup backfill. The control-plane invokes
        -- turna_migrate_command_log_batch repeatedly; progress is stored in
        -- turna_migrations and survives interruption/restart.
    end]],
})

box.schema.func.create("turna_store_allocation", {
    language = "LUA", is_sandboxed = false, setuid = true,
    body = [[function(port, user_id, node_id, expires_at_ms, data)
        box.space.turna_allocations:replace({
            tonumber(port), user_id, node_id, tonumber(expires_at_ms), data
        })
    end]],
})

box.schema.func.create("turna_get_allocation", {
    language = "LUA", is_sandboxed = false, setuid = true,
    body = [[function(port)
        local t = box.space.turna_allocations:get(tonumber(port))
        if t then return t[5] end
    end]],
})

box.schema.func.create("turna_remove_allocation", {
    language = "LUA", is_sandboxed = false, setuid = true,
    body = [[function(port)
        box.space.turna_allocations:delete(tonumber(port))
    end]],
})

box.schema.func.create("turna_update_bandwidth", {
    language = "LUA", is_sandboxed = false, setuid = true,
    body = [[function(port, bytes_in, bytes_out, packets_in, packets_out)
        local p = tonumber(port)
        local t = box.space.turna_allocations:get(p)
        if not t then return end
        local json = require('json')
        local d = json.decode(t[5])
        d.bytes_in    = d.bytes_in    + tonumber(bytes_in)
        d.bytes_out   = d.bytes_out   + tonumber(bytes_out)
        d.packets_in  = d.packets_in  + tonumber(packets_in)
        d.packets_out = d.packets_out + tonumber(packets_out)
        box.space.turna_allocations:update(p, {{'=', 5, json.encode(d)}})
    end]],
})

box.schema.func.create("turna_find_by_user", {
    language = "LUA", is_sandboxed = false, setuid = true,
    body = [[function(user_id)
        local res = {}
        for _,t in box.space.turna_allocations.index.by_user:pairs({user_id}) do
            table.insert(res, t[5])
        end
        return res
    end]],
})

box.schema.func.create("turna_find_by_node", {
    language = "LUA", is_sandboxed = false, setuid = true,
    body = [[function(node_id)
        local res = {}
        for _,t in box.space.turna_allocations.index.by_node:pairs({node_id}) do
            table.insert(res, t[5])
        end
        return res
    end]],
})

box.schema.func.create("turna_find_expired", {
    language = "LUA", is_sandboxed = false, setuid = true,
    body = [[function(before_ms)
        local cutoff = tonumber(before_ms)
        local res = {}
        for _,t in box.space.turna_allocations.index.by_expiry:pairs() do
            if t[4] >= cutoff then break end
            table.insert(res, t[5])
        end
        return res
    end]],
})

box.schema.func.create("turna_count_allocations", {
    language = "LUA", is_sandboxed = false, setuid = true,
    body = [[function() return box.space.turna_allocations:len() end]],
})

box.schema.func.create("turna_list_allocations", {
    language = "LUA", is_sandboxed = false, setuid = true,
    body = [[function(offset, limit)
        local off = tonumber(offset)
        local lim = tonumber(limit)
        local res = {}
        local i = 0
        for _,t in box.space.turna_allocations:pairs() do
            i = i + 1
            if i > off then table.insert(res, t[5]) end
            if #res >= lim then break end
        end
        return res
    end]],
})

box.schema.func.create("turna_store_heartbeat", {
    language = "LUA", is_sandboxed = false, setuid = true,
    body = [[function(node_id, data)
        box.space.turna_nodes:replace({node_id, data})
    end]],
})

box.schema.func.create("turna_get_live_nodes", {
    language = "LUA", is_sandboxed = false, setuid = true,
    body = [[function(cutoff_ms)
        local cutoff = tonumber(cutoff_ms)
        local res = {}
        for _,t in box.space.turna_nodes:pairs() do
            local d = require('json').decode(t[2])
            if d.last_seen_ms >= cutoff then table.insert(res, t[2]) end
        end
        return res
    end]],
})

box.schema.func.create("turna_store_room", {
    language = "LUA", is_sandboxed = false, setuid = true,
    body = [[function(room_id, data)
        box.space.turna_rooms:replace({room_id, data})
    end]],
})

box.schema.func.create("turna_get_room", {
    language = "LUA", is_sandboxed = false, setuid = true,
    body = [[function(room_id)
        local t = box.space.turna_rooms:get(room_id)
        if t then return t[2] end
    end]],
})

box.schema.func.create("turna_remove_room", {
    language = "LUA", is_sandboxed = false, setuid = true,
    body = [[function(room_id)
        box.space.turna_rooms:delete(room_id)
    end]],
})

box.schema.func.create("turna_ping", {
    language = "LUA", is_sandboxed = false, setuid = true,
    body = [[function() return 'pong' end]],
})


box.schema.func.create("turna_revoke_token", {
    language = "LUA", is_sandboxed = false, setuid = true,
    body = [[function(jti, sub, revoked_at_ms, expires_at_ms)
        box.space.turna_token_blacklist:replace({
            jti, sub, tonumber(revoked_at_ms), tonumber(expires_at_ms)
        })
    end]],
})

box.schema.func.create("turna_is_token_revoked", {
    language = "LUA", is_sandboxed = false, setuid = true,
    body = [[function(jti)
        return box.space.turna_token_blacklist:get(jti) ~= nil
    end]],
})

box.schema.func.create("turna_cleanup_revoked_tokens", {
    language = "LUA", is_sandboxed = false, setuid = true,
    body = [[function(before_ms)
        local cutoff = tonumber(before_ms)
        local deleted = 0
        for _, t in box.space.turna_token_blacklist.index.by_expiry:pairs() do
            if t[4] >= cutoff then break end
            box.space.turna_token_blacklist:delete(t[1])
            deleted = deleted + 1
        end
        return deleted
    end]],
})

box.schema.func.create("turna_load_active_revocations", {
    language = "LUA", is_sandboxed = false, setuid = true,
    body = [[function(after_ms)
        local cutoff = tonumber(after_ms)
        local res = {}
        for _, t in box.space.turna_token_blacklist.index.by_expiry:pairs() do
            if t[4] >= cutoff then table.insert(res, t[1] .. ":" .. tostring(t[4])) end
        end
        return res
    end]],
})

box.schema.func.create("turna_claim_allocation", {
    language = "LUA", is_sandboxed = false, setuid = true,
    body = [[function(port, expected_node_id, new_node_id)
        local p = tonumber(port)
        local t = box.space.turna_allocations:get(p)
        if t == nil then return false end
        if t[3] ~= expected_node_id then return false end
        local json = require('json')
        local payload = json.decode(t[5])
        payload.node_id = new_node_id
        local new_json = json.encode(payload)
        box.space.turna_allocations:update(p, {{'=', 3, new_node_id}, {'=', 5, new_json}})
        return true
    end]],
})

box.schema.func.create("turna_store_user", {
    language = "LUA", is_sandboxed = false, setuid = true,
    body = [[function(username, realm, data)
        box.space.turna_users:replace({ username, realm, data })
    end]],
})

box.schema.func.create("turna_get_user", {
    language = "LUA", is_sandboxed = false, setuid = true,
    body = [[function(username, realm)
        local t = box.space.turna_users:get({ username, realm })
        if t then return t[3] end
    end]],
})

box.schema.func.create("turna_remove_user", {
    language = "LUA", is_sandboxed = false, setuid = true,
    body = [[function(username, realm)
        local existed = box.space.turna_users:get({ username, realm }) ~= nil
        box.space.turna_users:delete({ username, realm })
        return existed
    end]],
})

box.schema.func.create("turna_list_users", {
    language = "LUA", is_sandboxed = false, setuid = true,
    body = [[function()
        local res = {}
        for _, t in box.space.turna_users:pairs() do
            table.insert(res, t[3])
        end
        return res
    end]],
})

box.schema.func.create("turna_get_runtime_state", {
    language = "LUA", is_sandboxed = false, setuid = true,
    body = [[function(node_id)
        local t = box.space.turna_runtime_state:get(node_id)
        if t then return t[6] end
    end]],
})

box.schema.func.create("turna_adopt_node_incarnation", {
    language = "LUA", is_sandboxed = false, setuid = true,
    body = [[function(node_id, incarnation)
        local json = require('json')
        local clock = require('clock')
        local now = math.floor(clock.realtime() * 1000)
        local runtime = box.space.turna_runtime_state:get(node_id)
        if runtime ~= nil then
            local state = json.decode(runtime[6])
            state.incarnation = incarnation
            state.updated_at_ms = now
            box.space.turna_runtime_state:replace({
                node_id, turna_parse_u64_exact(runtime[2]), turna_parse_u64_exact(runtime[3]), runtime[4], now,
                json.encode(state)
            })
        end
        -- Never mutate an index while iterating it. Snapshot the matching rows
        -- first, then replace them in a second pass. This keeps adoption
        -- repeatable even when a Tarantool engine invalidates an iterator after
        -- replace().
        local rows = {}
        for _, t in box.space.turna_user_limits.index.by_node:pairs({node_id}) do
            if t[2] ~= node_id then break end
            table.insert(rows, t)
        end
        for _, t in ipairs(rows) do
            local state = json.decode(t[8])
            state.incarnation = incarnation
            state.updated_at_ms = now
            box.space.turna_user_limits:replace({
                t[1], t[2], t[3], turna_parse_u64_exact(t[4]), turna_parse_u64_exact(t[5]), t[6], now,
                json.encode(state)
            })
        end
        return true
    end]],
})

box.schema.func.create("turna_cas_runtime_desired", {
    language = "LUA", is_sandboxed = false, setuid = true,
    body = [[function(node_id, expected_version, incarnation, desired_json)
        local json = require('json')
        local clock = require('clock')
        local expected = turna_parse_u64_exact(expected_version)
        local desired = json.decode(desired_json)
        local dver = turna_parse_u64_exact(desired.version)
        local now = math.floor(clock.realtime() * 1000)
        local t = box.space.turna_runtime_state:get(node_id)
        if t == nil then
            if expected ~= 0 or dver ~= 0 then return false end
            local state = {
                node_id = node_id, incarnation = incarnation,
                desired_version = 0, observed_version = 0,
                desired_snapshot = desired, observed_snapshot = desired,
                status = 'applying', last_error = '', updated_at_ms = now,
            }
            box.space.turna_runtime_state:insert({node_id, 0, 0, 'applying', now, json.encode(state)})
            return true
        end
        local state = json.decode(t[6])
        if turna_parse_u64_exact(t[2]) ~= expected then return false end
        if state.incarnation ~= nil and state.incarnation ~= '' and state.incarnation ~= incarnation then
            return false
        end
        state.incarnation = incarnation
        state.desired_version = dver
        state.desired_snapshot = desired
        state.status = 'applying'
        state.last_error = ''
        state.updated_at_ms = now
        box.space.turna_runtime_state:replace({
            node_id, turna_parse_u64_exact(t[2]), dver, 'applying', now, json.encode(state)
        })
        return true
    end]],
})

box.schema.func.create("turna_confirm_runtime_observed", {
    language = "LUA", is_sandboxed = false, setuid = true,
    body = [[function(node_id, desired_version, incarnation, observed_json, status, err, applied_op_json)
        local json = require('json')
        local clock = require('clock')
        -- #3: the CAS re-read, the durable idempotency journal write, and the
        -- observed-state update MUST be one all-or-nothing unit. memtx does NOT
        -- make a stored proc atomic by itself, so an explicit box.atomic wraps
        -- them: without it a crash (or a failing second replace) could leave the
        -- journal saying 'applied' while observed state was never bumped,
        -- reopening the exactly-once crash window. Either both writes land or
        -- neither does; the CAS is inside the transaction to avoid a TOCTOU race.
        return box.atomic(function()
            local desired = turna_parse_u64_exact(desired_version)
            local t = box.space.turna_runtime_state:get(node_id)
            if t == nil or turna_parse_u64_exact(t[3]) ~= desired then return false end
            local state = json.decode(t[6])
            if state.incarnation ~= incarnation then return false end
            local observed = json.decode(observed_json)
            if status == 'observed' then
                state.observed_version = turna_parse_u64_exact(observed.version)
                state.observed_snapshot = observed
                if applied_op_json ~= nil and applied_op_json ~= '' then
                    local ao = json.decode(applied_op_json)
                    state.last_applied = ao
                    -- Persist the durable terminal outcome into the idempotency
                    -- journal BEFORE turna_complete_command runs; recovers the
                    -- original result by key even if a later op has overwritten
                    -- the single last_applied slot. Never downgrades an
                    -- already-terminal record (created pending at enqueue).
                    if ao.idempotency_key ~= nil and ao.idempotency_key ~= '' then
                        local ex = box.space.turna_command_idem:get(ao.idempotency_key)
                        if ex ~= nil and (ex[4] == nil or ex[4] == '') then
                            box.space.turna_command_idem:replace({
                                ao.idempotency_key, ao.request_id,
                                ao.payload_hash or ex[3] or '',
                                'done',
                                ao.terminal_result or '',
                                ex[6] or tonumber(ao.applied_at_ms) or 0,
                                tonumber(ao.applied_at_ms)
                                    or math.floor(clock.realtime() * 1000),
                            })
                        end
                    end
                end
            end
            state.status = status
            state.last_error = err or ''
            state.updated_at_ms = math.floor(clock.realtime() * 1000)
            box.space.turna_runtime_state:replace({
                node_id, turna_parse_u64_exact(state.observed_version), turna_parse_u64_exact(state.desired_version),
                status, state.updated_at_ms, json.encode(state)
            })
            return true
        end)
    end]],
})

box.schema.func.create("turna_get_user_limits_state", {
    language = "LUA", is_sandboxed = false, setuid = true,
    body = [[function(node_id, subject_key)
        local state_key = tostring(#node_id) .. ':' .. node_id .. subject_key
        local t = box.space.turna_user_limits:get(state_key)
        if t then return t[8] end
    end]],
})

box.schema.func.create("turna_list_user_limits_states", {
    language = "LUA", is_sandboxed = false, setuid = true,
    body = [[function(node_id)
        local res = {}
        for _, t in box.space.turna_user_limits.index.by_node:pairs({node_id}) do
            if t[2] ~= node_id then break end
            table.insert(res, t[8])
        end
        return res
    end]],
})

box.schema.func.create("turna_cas_user_limits_desired", {
    language = "LUA", is_sandboxed = false, setuid = true,
    body = [[function(node_id, subject_key, expected_version, incarnation, target_json, desired_json)
        local json = require('json')
        local clock = require('clock')
        -- #5/#7: parse the version as an exact uint64 (never a Lua double, which
        -- loses integer precision above 2^53); Rust passes it as a decimal string.
        local expected = turna_parse_u64_exact(expected_version)
        local now = math.floor(clock.realtime() * 1000)
        local state_key = tostring(#node_id) .. ':' .. node_id .. subject_key
        local t = box.space.turna_user_limits:get(state_key)
        -- #7: explicit u64 ceiling BEFORE the add (a post-add comparison is not
        -- a valid overflow proof under LuaJIT arithmetic). True overflow is also
        -- refused upstream in Rust (checked_add) before this CALL is ever made.
        if expected >= 18446744073709551615ULL then
            error('turna_cas_user_limits_desired: version counter overflow', 0)
        end
        local desired_version = expected + 1
        if t == nil then
            if expected ~= 0 then return false end
            local state = {
                schema_version = 1,
                node_id = node_id, subject_key = subject_key,
                target = json.decode(target_json), incarnation = incarnation,
                desired_version = desired_version, observed_version = 0,
                desired_patch = json.decode(desired_json), observed_patch = {},
                status = 'applying', last_error = '', updated_at_ms = now,
            }
            box.space.turna_user_limits:insert({
                state_key, node_id, subject_key, 0, desired_version,
                'applying', now, json.encode(state)
            })
            return true
        end
        local state = json.decode(t[8])
        if turna_parse_u64_exact(t[4]) ~= expected then return false end
        if state.incarnation ~= nil and state.incarnation ~= '' and state.incarnation ~= incarnation then
            return false
        end
        state.incarnation = incarnation
        state.desired_version = desired_version
        state.desired_patch = json.decode(desired_json)
        state.status = 'applying'
        state.last_error = ''
        state.updated_at_ms = now
        box.space.turna_user_limits:replace({
            state_key, node_id, subject_key, t[4], desired_version,
            'applying', now, json.encode(state)
        })
        return true
    end]],
})

box.schema.func.create("turna_confirm_user_limits_observed", {
    language = "LUA", is_sandboxed = false, setuid = true,
    body = [[function(node_id, subject_key, desired_version, incarnation, observed_json, status, err, applied_op_json)
        local json = require('json')
        local clock = require('clock')
        -- #3: CAS re-read + idempotency journal write + observed-state update as
        -- one all-or-nothing unit (explicit box.atomic — memtx does not make a
        -- stored proc atomic on its own). See turna_confirm_runtime_observed for
        -- the crash-window rationale.
        return box.atomic(function()
            local state_key = tostring(#node_id) .. ':' .. node_id .. subject_key
            local desired = turna_parse_u64_exact(desired_version)
            local t = box.space.turna_user_limits:get(state_key)
            if t == nil or turna_parse_u64_exact(t[5]) ~= desired then return false end
            local state = json.decode(t[8])
            if state.incarnation ~= incarnation then return false end
            if status == 'observed' then
                state.observed_version = desired
                state.observed_patch = json.decode(observed_json)
                if applied_op_json ~= nil and applied_op_json ~= '' then
                    local ao = json.decode(applied_op_json)
                    state.last_applied = ao
                    if ao.idempotency_key ~= nil and ao.idempotency_key ~= '' then
                        local ex = box.space.turna_command_idem:get(ao.idempotency_key)
                        if ex ~= nil and (ex[4] == nil or ex[4] == '') then
                            box.space.turna_command_idem:replace({
                                ao.idempotency_key, ao.request_id,
                                ao.payload_hash or ex[3] or '',
                                'done',
                                ao.terminal_result or '',
                                ex[6] or tonumber(ao.applied_at_ms) or 0,
                                tonumber(ao.applied_at_ms)
                                    or math.floor(clock.realtime() * 1000),
                            })
                        end
                    end
                end
            end
            state.status = status
            state.last_error = err or ''
            state.updated_at_ms = math.floor(clock.realtime() * 1000)
            box.space.turna_user_limits:replace({
                state_key, node_id, subject_key, turna_parse_u64_exact(state.observed_version),
                turna_parse_u64_exact(state.desired_version), status, state.updated_at_ms, json.encode(state)
            })
            return true
        end)
    end]],
})

box.schema.func.create("turna_enqueue_command", {
    language = "LUA", is_sandboxed = false, setuid = true,
    body = [[function(request_id, target_node_id, data, payload_hash)
        -- P0.3 durable idempotency conflict/outcome semantics. First request_id
        -- to claim a non-empty key is canonical. A later retry with the SAME key:
        --   same payload_hash  -> return the canonical id (genuine retry);
        --   different hash      -> return (request_id, true) = CONFLICT.
        -- The idem record is self-sufficient (carries hash + outcome) so it can
        -- outlive the command under GC. A single CALL is atomic (box ops do not
        -- yield), so check-then-insert cannot race. Returns (canonical, conflict).
        local json = require('json')
        local d = json.decode(data)
        local key = d.idempotency_key
        local now = math.floor(require('clock').realtime() * 1000)
        if key ~= nil and key ~= '' then
            local existing = box.space.turna_command_idem:get(key)
            if existing ~= nil then
                -- Legacy (pre-2b) rows have no payload_hash (field 3 nil): never
                -- treat as a conflict — fall back to prior dedup behaviour.
                if existing[3] ~= nil and payload_hash ~= nil and payload_hash ~= ''
                    and existing[3] ~= payload_hash then
                    return request_id, true
                end
                if existing[2] ~= request_id then
                    return existing[2], false
                end
            else
                box.space.turna_command_idem:insert({
                    key, request_id, payload_hash or '', '', '', now, 0
                })
            end
        end
        if box.space.turna_commands:get(request_id) == nil then
            box.space.turna_commands:insert({
                request_id, target_node_id, data, d.status, d.updated_at_ms or now
            })
        end
        return request_id, false
    end]],
})

box.schema.func.create("turna_claim_commands", {
    language = "LUA", is_sandboxed = false, setuid = true,
    body = [[function(node_id, incarnation, max, lease_ms, now_ms)
        -- P0.2 lease + reclaim + dead-letter; P0.4 per-claim fencing token.
        -- Claims fresh 'pending' rows AND reclaims 'in_progress' rows whose lease
        -- expired (the previous claimant died before completing). A row reclaimed
        -- too many times (attempts >= MAX_ATTEMPTS, matching Rust
        -- MAX_COMMAND_ATTEMPTS) is dead-lettered to terminal 'failed' instead of
        -- being handed out again. Each claim mints a fresh unique claim_token so a
        -- stale claimant's later completion is fenced out. memory.rs is the
        -- reference implementation.
        local json  = require('json')
        local uuid  = require('uuid')
        local lim   = tonumber(max)
        local lease = tonumber(lease_ms)
        local now   = tonumber(now_ms)
        local MAX_ATTEMPTS = 5
        -- Snapshot candidate primary keys first: mutating a space while iterating
        -- one of its indexes is unsafe in Tarantool, so read then write.
        local keys = {}
        for _, t in box.space.turna_commands.index.by_node:pairs({ node_id }) do
            table.insert(keys, t[1])
        end
        local res = {}
        for _, rid in ipairs(keys) do
            if #res >= lim then break end
            local t = box.space.turna_commands:get(rid)
            if t ~= nil then
                local d = json.decode(t[3])
                local claimable = d.status == 'pending'
                    or (d.status == 'in_progress' and (d.lease_until_ms or 0) <= now)
                local target_incarnation = d.target_incarnation or ''
                local incarnation_ok = target_incarnation == ''
                    or target_incarnation == incarnation
                if claimable and incarnation_ok then
                    if (d.attempts or 0) >= MAX_ATTEMPTS then
                        d.status = 'failed'
                        d.result = 'dead_letter: exceeded ' .. MAX_ATTEMPTS .. ' claim attempts'
                        d.updated_at_ms = now
                        -- replace (not update) rewrites the whole tuple, so a
                        -- pre-2b 3-field row is upgraded in place instead of
                        -- erroring on a non-contiguous field write.
                        box.space.turna_commands:replace({
                            rid, t[2], json.encode(d), d.status, d.updated_at_ms
                        })
                        -- Record the terminal outcome on the idem record so a
                        -- replay after GC still sees 'failed' (upgrades legacy
                        -- 2-field rows too, preserving hash/created if present).
                        if d.idempotency_key ~= nil and d.idempotency_key ~= '' then
                            local ex = box.space.turna_command_idem:get(d.idempotency_key)
                            -- #3.7: never downgrade an already-terminal outcome
                            -- (an applied command whose completion was lost keeps
                            -- its journaled result rather than being dead-lettered).
                            if ex ~= nil and (ex[4] == nil or ex[4] == '') then
                                box.space.turna_command_idem:replace({
                                    ex[1], ex[2], ex[3] or '', 'failed', d.result, ex[6] or 0, now
                                })
                            end
                        end
                    else
                        d.status = 'in_progress'
                        d.claimed_by = node_id
                        d.claim_token = node_id .. ':' .. uuid.str()
                        d.lease_until_ms = now + lease
                        d.attempts = (d.attempts or 0) + 1
                        d.updated_at_ms = now
                        local encoded = json.encode(d)
                        box.space.turna_commands:replace({
                            rid, t[2], encoded, d.status, d.updated_at_ms
                        })
                        table.insert(res, encoded)
                    end
                end
            end
        end
        return res
    end]],
})

box.schema.func.create("turna_complete_command", {
    language = "LUA", is_sandboxed = false, setuid = true,
    body = [[function(request_id, claimed_by, claim_token, status, result)
        -- P0.4 fenced completion: apply ONLY when the row is 'in_progress' and
        -- BOTH claimed_by and the per-claim claim_token match. A stale claimant
        -- (lease expired, row reclaimed with a new token) is rejected even if its
        -- node id matches. Returns true iff applied, false otherwise.
        local t = box.space.turna_commands:get(request_id)
        if t == nil then return false end
        local json = require('json')
        local d = json.decode(t[3])
        if d.status == 'in_progress'
            and d.claimed_by == claimed_by
            and d.claim_token == claim_token then
            local now = math.floor(require('clock').realtime() * 1000)
            d.status = status
            d.result = result
            d.updated_at_ms = now
            box.space.turna_commands:replace({
                request_id, t[2], json.encode(d), d.status, d.updated_at_ms
            })
            -- Mirror the terminal outcome onto the idem record (post-prune replay);
            -- replace upgrades a legacy 2-field row and preserves hash/created.
            if d.idempotency_key ~= nil and d.idempotency_key ~= '' then
                local ex = box.space.turna_command_idem:get(d.idempotency_key)
                -- #3.7: the confirm-observed outcome is authoritative; completion
                -- writes the same terminal result and never downgrades a record
                -- that already reached a terminal outcome.
                if ex ~= nil and (ex[4] == nil or ex[4] == '') then
                    box.space.turna_command_idem:replace({
                        ex[1], ex[2], ex[3] or '', status, result, ex[6] or 0, now
                    })
                end
            end
            return true
        end
        return false
    end]],
})

box.schema.func.create("turna_finalize_stale_command", {
    language = "LUA", is_sandboxed = false, setuid = true,
    body = [[function(request_id, current_incarnation, result)
        -- §2.3/§2.4: finalize a STALE-incarnation, non-terminal command to
        -- `done` with a caller-built typed result. Fenced: acts only when the
        -- command exists, is non-terminal, and its target_incarnation is
        -- non-empty and differs from current_incarnation. Returns true iff it
        -- transitioned the command to done. Mirrors the terminal outcome onto
        -- the idempotency record (post-prune replay), like turna_complete_command.
        local t = box.space.turna_commands:get(request_id)
        if t == nil then return false end
        local json = require('json')
        local d = json.decode(t[3])
        local terminal = d.status == 'done' or d.status == 'failed'
        local stale = d.target_incarnation ~= nil and d.target_incarnation ~= ''
            and d.target_incarnation ~= current_incarnation
        if terminal or not stale then return false end
        local now = math.floor(require('clock').realtime() * 1000)
        d.status = 'done'
        d.result = result
        d.updated_at_ms = now
        box.space.turna_commands:replace({
            request_id, t[2], json.encode(d), d.status, d.updated_at_ms
        })
        if d.idempotency_key ~= nil and d.idempotency_key ~= '' then
            local ex = box.space.turna_command_idem:get(d.idempotency_key)
            -- #3.7: never downgrade an already-terminal outcome — an applied
            -- command whose completion was lost keeps its journaled result rather
            -- than being overwritten by a superseding finalize.
            if ex ~= nil and (ex[4] == nil or ex[4] == '') then
                box.space.turna_command_idem:replace({
                    ex[1], ex[2], ex[3] or '', 'done', result, ex[6] or 0, now
                })
            end
        end
        return true
    end]],
})

box.schema.func.create("turna_list_stale_commands", {
    language = "LUA", is_sandboxed = false, setuid = true,
    body = [[function(node_id, current_incarnation, max)
        -- §2.4: list up to `max` non-terminal commands for node_id whose
        -- target_incarnation is non-empty and differs from current_incarnation
        -- (left behind by a prior incarnation; claim fences them out). Read-only.
        local json = require('json')
        local lim = tonumber(max) or 0
        local res = {}
        for _, t in box.space.turna_commands.index.by_node:pairs({ node_id }) do
            if #res >= lim then break end
            local d = json.decode(t[3])
            local terminal = d.status == 'done' or d.status == 'failed'
            local ti = d.target_incarnation or ''
            local stale = ti ~= '' and ti ~= current_incarnation
            if (not terminal) and stale then
                table.insert(res, json.encode(d))
            end
        end
        return res
    end]],
})

box.schema.func.create("turna_get_command", {
    language = "LUA", is_sandboxed = false, setuid = true,
    body = [[function(request_id)
        local t = box.space.turna_commands:get(request_id)
        if t then return t[3] end
    end]],
})

-- Fetch the durable idempotency record by key. The record outlives the command
-- it guards, so after GC prunes the command a replay recovers the terminal
-- outcome from here. Returned as a JSON object shaped like `IdempotencyRecord`
-- (the Rust side deserializes it with the same path as turna_get_command).
box.schema.func.create("turna_get_idempotency", {
    language = "LUA", is_sandboxed = false, setuid = true,
    body = [[function(key)
        local t = box.space.turna_command_idem:get(key)
        if t == nil then return end
        return require('json').encode({
            request_id      = t[2],
            payload_hash    = t[3] or "",
            final_status    = t[4] or "",
            result          = t[5] or "",
            created_at_ms   = t[6] or 0,
            completed_at_ms = t[7] or 0,
        })
    end]],
})

-- #4: durably record a NON-mutating terminal business outcome (no_op / conflict
-- / failed) into the keyed idempotency journal BEFORE the command is completed,
-- so a lost completion replays the ORIGINAL result instead of re-validating
-- against since-changed state. Touches only the existing canonical row; verifies
-- request_id + payload_hash; never downgrades a terminal record. Returns a status
-- code the caller maps to Ok/Conflict: 'ok' (written), 'ok_same' (already the
-- same terminal outcome), 'no_record', 'req_mismatch', 'hash_mismatch',
-- 'conflict' (already terminal with a different result).
box.schema.func.create("turna_record_command_outcome", {
    language = "LUA", is_sandboxed = false, setuid = true,
    body = [[function(key, req, payload_hash, final_status, result, completed_at_ms)
        if key == nil or key == '' then return 'no_key' end
        local ex = box.space.turna_command_idem:get(key)
        if ex == nil then return 'no_record' end
        if (ex[2] or '') ~= tostring(req or '') then return 'req_mismatch' end
        if (ex[3] or '') ~= tostring(payload_hash or '') then return 'hash_mismatch' end
        if ex[4] ~= nil and ex[4] ~= '' then
            -- Already terminal: idempotent iff the stored result is identical.
            if (ex[5] or '') == tostring(result or '') then return 'ok_same' end
            return 'conflict'
        end
        local fs = tostring(final_status or '')
        if fs == '' then fs = 'done' end
        box.space.turna_command_idem:replace({
            ex[1], ex[2], ex[3], fs, tostring(result or ''),
            tonumber(ex[6]) or 0, tonumber(completed_at_ms) or 0,
        })
        return 'ok'
    end]],
})

box.schema.func.create("turna_migrate_command_log_batch", {
    language = "LUA", is_sandboxed = false, setuid = true,
    body = [[function(batch_size, owner_id, lease_ttl_ms)
        local json = require('json')
        local clock = require('clock')
        local now = math.floor(clock.realtime() * 1000)
        local cap = math.max(1, math.min(tonumber(batch_size) or 100, 1000))
        local owner = tostring(owner_id or '')
        local lease_ttl = tonumber(lease_ttl_ms) or 30000
        local name = 'command_log_backfill_v2'

        local row = box.space.turna_migrations:get(name)
        -- Already complete → idempotent no-op; the startup driver never rescans.
        if row ~= nil and row[4] == true then
            return 0, row[2] or '', tonumber(row[3]) or 0, true, 'complete'
        end

        local cursor    = (row and row[2]) or ''
        local processed = (row and tonumber(row[3])) or 0
        local phase     = (row and row[6]) or 'commands'
        local errors    = (row and tonumber(row[7])) or 0
        local cur_owner = (row and row[8]) or ''
        local lease_exp = (row and tonumber(row[9])) or 0
        local lease_gen = turna_parse_u64_exact((row and row[10]) or 0)

        -- Concurrency: a live lease held by a different owner wins; back off.
        -- On owner death the lease expires and the next caller resumes the
        -- cursor. Batches are idempotent (replace + modern-guard), so a reprocessed
        -- last page after a crash is safe.
        if cur_owner ~= '' and cur_owner ~= owner and lease_exp > now then
            return 0, cursor, processed, false, phase
        end
        -- #2/#6: bump the monotonic fencing generation on a NEW acquisition (first
        -- grab or a takeover after expiry); a same-owner refresh within a live
        -- lease keeps it. The generation is an EXACT uint64 (never a lossy Lua
        -- double), so a stale page carrying the old token can never be misread as
        -- the current one above 2^53. A stale page then can never apply
        -- (turna_migration_idem_apply CAS-checks the token).
        if cur_owner ~= owner or lease_exp <= now then
            if lease_gen >= 18446744073709551615ULL then
                error('migration lease generation overflow', 0)
            end
            lease_gen = lease_gen + 1ULL
        end
        cur_owner = owner
        lease_exp = now + lease_ttl

        local count = 0

        -- Phase `commands`: normalize the extracted status/timestamp columns for
        -- legacy turna_commands rows. Collect first, mutate after — never modify a
        -- space while iterating its own index (turna_gc_command_log convention).
        if phase == 'commands' then
            local todo, last = {}, cursor
            for _, t in box.space.turna_commands.index.primary:pairs(cursor,
                    { iterator = cursor == '' and 'GE' or 'GT' }) do
                table.insert(todo, t)
                last = t[1]
                count = count + 1
                if count >= cap then break end
            end
            if count < cap then phase = 'idempotency'; cursor = '' else cursor = last end
            processed = processed + count
            -- #2.4: the legacy-column normalizations and the cursor advance commit
            -- as one transaction; on any error nothing lands and the batch simply
            -- re-runs (replace is idempotent). A stored function is not implicitly
            -- transactional in memtx, and nothing here yields, so box.atomic fits.
            box.atomic(function()
                for _, t in ipairs(todo) do
                    if t[4] == nil or t[5] == nil then
                        local ok, d = pcall(function() return json.decode(t[3]) end)
                        if ok and d then
                            box.space.turna_commands:replace({
                                t[1], t[2], t[3],
                                t[4] or d.status,
                                t[5] or d.updated_at_ms or d.created_at_ms or now,
                            })
                        end
                    end
                end
                box.space.turna_migrations:replace({
                    name, cursor, processed, false, now, phase, errors, cur_owner, lease_exp, lease_gen
                })
            end)
            return count, cursor, processed, false, phase
        end

        -- Phase `idempotency`: a restorable legacy record's payload hash must be
        -- recomputed by the canonical Rust `command_payload_hash`, never a
        -- divergent Lua copy. So this entry does NOT mutate here — it only holds
        -- and refreshes the lease and signals the phase. The state-backend driver
        -- then runs the Rust-driven pair `turna_migration_idem_fetch` (bounded,
        -- no mutation) → hash in Rust → `turna_migration_idem_apply` (writes and
        -- advances the cursor only after the durable commit). A reprocessed page
        -- is idempotent (replace by key).
        if phase == 'idempotency' then
            box.space.turna_migrations:replace({
                name, cursor, processed, false, now, phase, errors, cur_owner, lease_exp, lease_gen
            })
            return 0, cursor, processed, false, phase
        end

        -- Phase `complete` (or unknown): finalize idempotently. Reached only once
        -- both prior phases have drained.
        box.space.turna_migrations:replace({
            name, cursor, processed, true, now, 'complete', errors, cur_owner, lease_exp, lease_gen
        })
        return 0, cursor, processed, true, 'complete'
    end]],
})

-- #2.5/#2.6: idempotency-phase FETCH. Returns a bounded page of legacy/partial
-- idempotency rows (empty payload hash) together with the linked command's
-- op/args/payload_json, so the caller (state-backend `tarantool.rs`) can
-- recompute the canonical hash with the Rust `command_payload_hash`. Modern rows
-- (pending or terminal) already carry the Rust hash and are skipped. This call
-- does NOT mutate idempotency rows and does NOT advance the cursor — it only
-- holds/refreshes the migration lease. `turna_migration_idem_apply` commits.
box.schema.func.create("turna_migration_idem_fetch", {
    language = "LUA", is_sandboxed = false, setuid = true,
    body = [[function(batch_size, owner_id, lease_ttl_ms)
        local json = require('json')
        local clock = require('clock')
        local now = math.floor(clock.realtime() * 1000)
        local cap = math.max(1, math.min(tonumber(batch_size) or 100, 1000))
        local owner = tostring(owner_id or '')
        local lease_ttl = tonumber(lease_ttl_ms) or 30000
        local name = 'command_log_backfill_v2'

        local rows = setmetatable({}, { __serialize = 'seq' })
        local row = box.space.turna_migrations:get(name)
        if row == nil or row[6] ~= 'idempotency' then
            return json.encode({ rows = rows, cursor_next = (row and row[2]) or '',
                                 done = true, scanned = 0 })
        end
        local cursor    = row[2] or ''
        local cur_owner = row[8] or ''
        local lease_exp = tonumber(row[9]) or 0
        local lease_gen = turna_parse_u64_exact(row[10] or 0)
        -- A live lease held by a different owner wins; back off with no work.
        if cur_owner ~= '' and cur_owner ~= owner and lease_exp > now then
            return json.encode({ rows = rows, cursor_next = cursor, done = false,
                                 scanned = 0, phase = 'idempotency' })
        end
        -- #2/#6: bump the monotonic fencing generation on a NEW acquisition; a
        -- same-owner refresh within a live lease keeps it. The token is an EXACT
        -- uint64 so it pins this page to this exact lease across the whole u64
        -- range (turna_migration_idem_apply CAS-checks it).
        if cur_owner ~= owner or lease_exp <= now then
            if lease_gen >= 18446744073709551615ULL then
                error('migration lease generation overflow', 0)
            end
            lease_gen = lease_gen + 1ULL
        end
        box.space.turna_migrations:replace({
            name, cursor, tonumber(row[3]) or 0, false, now, 'idempotency',
            tonumber(row[7]) or 0, owner, now + lease_ttl, lease_gen
        })

        local scanned, last = 0, cursor
        for _, t in box.space.turna_command_idem.index.primary:pairs(cursor,
                { iterator = cursor == '' and 'GE' or 'GT' }) do
            scanned = scanned + 1
            last = t[1]
            -- #3: a row is fully modern (skip) only if it is either a full
            -- terminal row (hash + final_status + result + created + completed)
            -- OR a genuine full pending row — hash set, no terminal fields, AND
            -- the LINKED COMMAND is still non-terminal. A row that merely *looks*
            -- pending (hash set, no outcome) but whose command is already terminal
            -- is a PARTIAL row and must be enriched; the command status is
            -- therefore checked here, not assumed from the idem fields alone.
            local payload_hash = t[3]
            local final_status = t[4]
            local result       = t[5]
            local created_ms   = tonumber(t[6]) or 0
            local completed_ms = tonumber(t[7]) or 0
            local has_hash   = payload_hash ~= nil and payload_hash ~= ''
            local has_status = final_status ~= nil and final_status ~= ''
            local has_result = result ~= nil and result ~= ''
            local full_terminal = has_hash and has_status and has_result
                and created_ms ~= 0 and completed_ms ~= 0
            if not full_terminal then
                local key, req = t[1], t[2]
                local cmd = box.space.turna_commands:get(req)
                local d = nil
                if cmd ~= nil then
                    local ok, dd = pcall(function() return json.decode(cmd[3]) end)
                    if ok then d = dd end
                end
                local cmd_status = (d and d.status) or ''
                local cmd_terminal = cmd_status ~= '' and cmd_status ~= 'pending'
                    and cmd_status ~= 'in_progress'
                -- Genuine full-pending: idem row has only a hash, and a live
                -- (non-terminal) command backs it → leave for its lifecycle.
                local full_pending = has_hash and (not has_status) and (not has_result)
                    and completed_ms == 0 and (d ~= nil) and (not cmd_terminal)
                if not full_pending then
                    if d ~= nil then
                        table.insert(rows, {
                            key = key, req = req, orphan = false,
                            op = d.op or '',
                            args = setmetatable(d.args or {}, { __serialize = 'seq' }),
                            payload_json = d.payload_json or '',
                            status = d.status or '',
                            result = d.result or (result or ''),
                            created = (created_ms ~= 0 and created_ms)
                                or (tonumber(d.created_at_ms) or 0),
                            updated = tonumber(d.updated_at_ms) or 0,
                        })
                    else
                        -- Command gone or undecodable → orphan, terminally closed by apply.
                        table.insert(rows, { key = key, req = req, orphan = true,
                                             created = created_ms })
                    end
                end
            end
            if scanned >= cap then break end
        end
        local done = scanned < cap
        return json.encode({
            rows = rows, cursor_next = last, done = done, scanned = scanned,
            version = name, phase = 'idempotency', expected_cursor = cursor,
            lease_owner = owner, lease_token = lease_gen,
        })
    end]],
})

-- #2.5/#2.6: idempotency-phase APPLY. CAS-checks the migration owner, replaces
-- each supplied idempotency row with the Rust-computed hash (restorable) or an
-- explicit terminal orphan outcome, then advances the cursor and bumps
-- processed/errors — the cursor moves only after this durable write, so an
-- interrupted batch simply re-fetches and re-applies the same page (idempotent).
box.schema.func.create("turna_migration_idem_apply", {
    language = "LUA", is_sandboxed = false, setuid = true,
    body = [[function(owner_id, updates_json, cursor_next, done_flag, scanned, errors_delta, lease_ttl_ms, expected_cursor, expected_token, expected_phase)
        local json = require('json')
        local clock = require('clock')
        local now = math.floor(clock.realtime() * 1000)
        local owner = tostring(owner_id or '')
        local lease_ttl = tonumber(lease_ttl_ms) or 30000
        local name = 'command_log_backfill_v2'

        -- Result captured in outer locals so the 5-tuple is returned verbatim
        -- regardless of how box.atomic proxies return values.
        local r_scanned, r_cursor, r_processed, r_done, r_phase = 0, '', 0, false, 'complete'
        local function stale(r)
            r_scanned   = 0
            r_cursor    = (r and r[2]) or ''
            r_processed = (r and tonumber(r[3])) or 0
            r_done      = (r and r[4]) or false
            r_phase     = (r and r[6]) or 'complete'
        end

        -- #2/#2.4: the CAS re-check, every idempotency-row write, and the cursor
        -- advance commit as ONE transaction — the whole page lands or, on any
        -- error, nothing does (no partially-applied batch, no half-advanced
        -- cursor). A stored function is not an implicit transaction in memtx, so
        -- box.atomic is required; nothing inside yields, so it is safe.
        box.atomic(function()
            local row = box.space.turna_migrations:get(name)
            if row == nil then return stale(nil) end
            -- #2: full page CAS — the batch may only apply to the exact state it
            -- was fetched for. Any drift (phase, cursor, owner, fencing token) or
            -- an expired lease → stale, no write, cursor unchanged; driver re-fetches.
            local exp_phase = (expected_phase ~= nil and expected_phase ~= '')
                and tostring(expected_phase) or 'idempotency'
            if (row[6] or '') ~= exp_phase then return stale(row) end
            if (row[2] or '') ~= tostring(expected_cursor or '') then return stale(row) end
            if (row[8] or '') ~= owner then return stale(row) end
            -- #6: compare the fencing token as an EXACT uint64 — a lossy Lua
            -- double could equate two distinct tokens above 2^53 and let a stale
            -- page pass the CAS.
            if turna_parse_u64_exact(row[10] or 0)
                    ~= turna_parse_u64_exact(expected_token or 0) then
                return stale(row)
            end
            if (tonumber(row[9]) or 0) <= now then return stale(row) end
            local lease_gen = turna_parse_u64_exact(row[10] or 0)

            local ok, updates = pcall(function() return json.decode(updates_json) end)
            if not ok or type(updates) ~= 'table' then return stale(row) end
            for _, u in ipairs(updates) do
                -- #2.5/#8: re-read the row and migrate it only when it is still the
                -- SAME command's non-terminal record. This refuses to:
                --   * downgrade a terminal outcome written between fetch and apply;
                --   * resurrect a row GC removed in the meantime (ex == nil);
                --   * clobber a NEW pending row after the idempotency key was GC'd
                --     and reused by a different command (ex[2] ~= u.req, or a
                --     since-set hash that disagrees with the page's).
                local ex = box.space.turna_command_idem:get(u.key)
                local same_req = ex ~= nil and (ex[2] or '') == tostring(u.req or '')
                local non_term = ex ~= nil and (ex[4] == nil or ex[4] == '')
                local hash_ok  = ex ~= nil and (ex[3] == nil or ex[3] == ''
                    or ex[3] == (u.payload_hash or ''))
                if same_req and non_term and hash_ok then
                    box.space.turna_command_idem:replace({
                        u.key, u.req,
                        u.payload_hash or ex[3] or '',
                        u.final_status or '',
                        u.result or '',
                        tonumber(u.created_at_ms) or tonumber(ex[6]) or 0,
                        tonumber(u.completed_at_ms) or 0,
                    })
                end
            end

            local scanned_n = tonumber(scanned) or 0
            local processed = (tonumber(row[3]) or 0) + scanned_n
            local errors    = (tonumber(row[7]) or 0) + (tonumber(errors_delta) or 0)
            local done      = (tostring(done_flag) == 'true')
            local phase     = done and 'complete' or 'idempotency'
            local cursor    = done and '' or tostring(cursor_next or '')
            box.space.turna_migrations:replace({
                name, cursor, processed, done, now, phase, errors, owner, now + lease_ttl, lease_gen
            })
            r_scanned, r_cursor, r_processed, r_done, r_phase =
                scanned_n, cursor, processed, done, phase
        end)
        return r_scanned, r_cursor, r_processed, r_done, r_phase
    end]],
})

box.schema.func.create("turna_gc_command_log", {
    language = "LUA", is_sandboxed = false, setuid = true,
    -- One bounded GC batch per CALL (<= `batch` command deletes and
    -- <= `batch` idempotency deletes, so the implicit transaction stays small).
    -- The control-plane sweep loops up to max_batches while `more` is true.
    -- Terminal commands are pruned per status via the by_status index (no full
    -- space scan); idempotency records via by_completed (ascending → break once
    -- past the window). Keys are collected first, deleted after — never mutate a
    -- space while iterating its index. Returns
    --   (deleted_commands, deleted_idempotency, terminal_remaining, oldest_age, more).
    body = [[function(now_ms, done_ms, failed_ms, superseded_ms, expired_ms, idem_ms, batch)
        local now = tonumber(now_ms)
        local cap = tonumber(batch)
        if cap < 1 then cap = 1 end
        local ttl = {
            done = tonumber(done_ms), failed = tonumber(failed_ms),
            superseded = tonumber(superseded_ms), expired = tonumber(expired_ms),
        }
        local cmds = box.space.turna_commands
        local idem = box.space.turna_command_idem
        local to_del = {}
        for st, win in pairs(ttl) do
            for _, t in cmds.index.by_status:pairs({ st }) do
                if #to_del >= cap then break end
                if (now - (t[5] or 0)) > win then table.insert(to_del, t[1]) end
            end
            if #to_del >= cap then break end
        end
        for _, rid in ipairs(to_del) do cmds:delete(rid) end
        local deleted_cmd = #to_del

        local idem_del = {}
        for _, r in idem.index.by_completed:pairs({ 0 }, { iterator = 'GT' }) do
            if #idem_del >= cap then break end
            if (now - r[7]) > tonumber(idem_ms) then
                table.insert(idem_del, r[1])
            else
                break
            end
        end
        for _, k in ipairs(idem_del) do idem:delete(k) end
        local deleted_idem = #idem_del

        local terminal_remaining =
            cmds.index.by_status:count({ 'done' })
            + cmds.index.by_status:count({ 'failed' })
            + cmds.index.by_status:count({ 'superseded' })
            + cmds.index.by_status:count({ 'expired' })

        local oldest = 0
        -- Oldest NOT-YET-terminal command by age since enqueue (created_at_ms),
        -- to match the memory backend's semantics and the metric name. Non-
        -- terminal rows are few and short-lived, so this read-only scan over
        -- pending/in_progress is cheap; created_at_ms lives in the JSON blob
        -- (field 3), not an indexed column, so decode it per row.
        for _, stn in ipairs({ 'pending', 'in_progress' }) do
            for _, t in cmds.index.by_status:pairs({ stn }) do
                local ok, cmd = pcall(function() return require('json').decode(t[3]) end)
                local created = (ok and cmd and cmd.created_at_ms) or 0
                local age = now - created
                if age > oldest then oldest = age end
            end
        end

        local more = (deleted_cmd >= cap) or (deleted_idem >= cap)
        return deleted_cmd, deleted_idem, terminal_remaining, oldest, more
    end]],
})

-- ── 4. Role with minimum required privileges ─────────────────────────────────
-- Only execute on the specific functions above. No universe-wide execute.
-- A compromised turna-node can ONLY call the explicitly listed functions below.

box.schema.role.create("turna_app", { if_not_exists = true })

local TURNA_FUNCS = {
    "turna_init_schema",
    "turna_store_allocation",  "turna_get_allocation",   "turna_remove_allocation",
    "turna_update_bandwidth",  "turna_find_by_user",     "turna_find_by_node",
    "turna_find_expired",      "turna_count_allocations","turna_list_allocations",
    "turna_store_heartbeat",   "turna_get_live_nodes",
    "turna_store_room",        "turna_get_room",         "turna_remove_room",
    "turna_ping",              "turna_claim_allocation",
    "turna_revoke_token", "turna_is_token_revoked",
    "turna_cleanup_revoked_tokens", "turna_load_active_revocations",
    "turna_store_user", "turna_get_user", "turna_remove_user", "turna_list_users",
    "turna_enqueue_command", "turna_claim_commands",
    "turna_complete_command", "turna_get_command", "turna_get_idempotency",
    "turna_record_command_outcome",
    "turna_finalize_stale_command",
    "turna_list_stale_commands",
    "turna_gc_command_log", "turna_migrate_command_log_batch",
    "turna_migration_idem_fetch", "turna_migration_idem_apply",
    "turna_get_runtime_state", "turna_adopt_node_incarnation",
    "turna_cas_runtime_desired", "turna_confirm_runtime_observed",
    "turna_get_user_limits_state", "turna_list_user_limits_states",
    "turna_cas_user_limits_desired", "turna_confirm_user_limits_observed",
}
for _, fn_name in ipairs(TURNA_FUNCS) do
    box.schema.role.grant("turna_app", "execute", "function", fn_name,
                          { if_not_exists = true })
end

-- ── 4. User ─────────────────────────────────────────────────────────────────

if box.schema.user.exists(APP_USER) then
    -- Refresh the password on every run if TURNA_PASSWORD was supplied;
    -- preserve the existing one if we're using a generated value and the
    -- user already exists (idempotent reruns shouldn't rotate secrets).
    if not generated_password then
        box.schema.user.passwd(APP_USER, APP_PASSWORD)
        print("user '" .. APP_USER .. "' password updated from TURNA_PASSWORD")
    else
        print("user '" .. APP_USER .. "' already exists; password unchanged")
    end
else
    box.schema.user.create(APP_USER, { password = APP_PASSWORD })
    print("user '" .. APP_USER .. "' created")
end
box.schema.user.grant(APP_USER, "turna_app", nil, nil, { if_not_exists = true })

-- ── 5. Done ─────────────────────────────────────────────────────────────────

print("─────────────────────────────────────────────────")
print("Schema:")
print("  turna_allocations  : indexed by primary, by_user, by_node, by_expiry")
print("  turna_nodes        : indexed by primary")
print("  turna_rooms        : indexed by primary")
print("  turna_runtime_state: durable desired/observed state per node")
print("  turna_user_limits  : durable scoped limits state per node")
print("  turna_migrations   : resumable schema/data migration progress")
print("Role 'turna_app' grants:")
print("  execute on versioned turna stored functions (least privilege)")
print("  NO execute on universe — privilege-tightened")
print("User '" .. APP_USER .. "' granted 'turna_app'.")
print("─────────────────────────────────────────────────")
if generated_password then
    print("")
    print("GENERATED PASSWORD (capture this once; will not be shown again):")
    print("")
    print("  " .. APP_PASSWORD)
    print("")
    print("Set on the turna-node host:")
    print("  export TURNA_BACKEND_URI='" .. LISTEN .. "'")
    print("  export TURNA_BACKEND_USER='" .. APP_USER .. "'")
    print("  export TURNA_BACKEND_PASSWORD='" .. APP_PASSWORD .. "'")
end
print("─────────────────────────────────────────────────")