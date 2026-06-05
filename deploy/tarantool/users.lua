-- deploy/tarantool/users.lua
-- Run AFTER init.lua to add user authentication support.
-- Idempotent: safe to re-run.
--
-- Usage:
--   tarantool deploy/tarantool/users.lua
-- or inside tarantool console:
--   dofile('deploy/tarantool/users.lua')


-- ── Space ─────────────────────────────────────────────────────────────────────

box.schema.space.create("turna_users", { if_not_exists = true })

box.space.turna_users:format({
    { name = "id",            type = "string"   }, -- UUID
    { name = "username",      type = "string"   }, -- unique login name
    { name = "email",         type = "string"   }, -- unique email
    { name = "data",          type = "string"   }, -- JSON blob (role, display_name, password_hash, etc.)
    { name = "created_at_ms", type = "unsigned" }, -- Unix ms
})

box.space.turna_users:create_index("primary",
    { parts = { "id" }, if_not_exists = true })

box.space.turna_users:create_index("by_username",
    { parts = { "username" }, unique = true, if_not_exists = true })

box.space.turna_users:create_index("by_email",
    { parts = { "email" }, unique = true, if_not_exists = true })

print("turna_users space ready")

-- ── Stored functions ──────────────────────────────────────────────────────────

-- Create user
box.schema.func.create("turna_create_user", { if_not_exists = true,
    body = [[
        function(id, username, email, data, created_at_ms)
            local existing_u = box.space.turna_users.index.by_username:get(username)
            if existing_u ~= nil then
                return false, "username_taken"
            end
            local existing_e = box.space.turna_users.index.by_email:get(email)
            if existing_e ~= nil then
                return false, "email_taken"
            end
            box.space.turna_users:insert({ id, username, email, data, created_at_ms })
            return true, nil
        end
    ]]
})

-- Get user by ID
box.schema.func.create("turna_get_user", { if_not_exists = true,
    body = [[
        function(id)
            local t = box.space.turna_users:get(id)
            if t == nil then return nil end
            return t:totable()
        end
    ]]
})

-- Get user by username
box.schema.func.create("turna_get_user_by_username", { if_not_exists = true,
    body = [[
        function(username)
            local t = box.space.turna_users.index.by_username:get(username)
            if t == nil then return nil end
            return t:totable()
        end
    ]]
})

-- Get user by email
box.schema.func.create("turna_get_user_by_email", { if_not_exists = true,
    body = [[
        function(email)
            local t = box.space.turna_users.index.by_email:get(email)
            if t == nil then return nil end
            return t:totable()
        end
    ]]
})

-- Update user data blob
box.schema.func.create("turna_update_user", { if_not_exists = true,
    body = [[
        function(id, data)
            local t = box.space.turna_users:get(id)
            if t == nil then return false end
            box.space.turna_users:update(id, { { "=", 4, data } })
            return true
        end
    ]]
})

-- Count users
box.schema.func.create("turna_count_users", { if_not_exists = true,
    body = [[
        function()
            return box.space.turna_users:count()
        end
    ]]
})

print("turna_users stored functions ready")

-- ── Privileges ────────────────────────────────────────────────────────────────

-- Grant execute on user functions to turna_app role
-- (turna_app role was created in init.lua)
local user_funcs = {
    "turna_create_user",
    "turna_get_user",
    "turna_get_user_by_username",
    "turna_get_user_by_email",
    "turna_update_user",
    "turna_count_users",
}
for _, fname in ipairs(user_funcs) do
    box.schema.role.grant("turna_app", "execute", "function", fname,
        { if_not_exists = true })
end

print("turna_users privileges granted to turna_app")
print("users.lua done")
