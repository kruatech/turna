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
}
for _, fn_name in ipairs(TURNA_FUNCS_ALL) do
    box.schema.func.drop(fn_name, { if_exists = true })
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
        return unpack(res)
    end]],
})

box.schema.func.create("turna_find_by_node", {
    language = "LUA", is_sandboxed = false, setuid = true,
    body = [[function(node_id)
        local res = {}
        for _,t in box.space.turna_allocations.index.by_node:pairs({node_id}) do
            table.insert(res, t[5])
        end
        return unpack(res)
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
        return unpack(res)
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
        return unpack(res)
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
        return unpack(res)
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
        return unpack(res)
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

-- ── 4. Role with minimum required privileges ─────────────────────────────────
-- Only execute on the specific functions above. No universe-wide execute.
-- A compromised turna-node can ONLY call these 17 functions — nothing else.

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
print("Role 'turna_app' grants:")
print("  execute on 17 stored functions (turna_init_schema, turna_store_allocation, ...)")
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