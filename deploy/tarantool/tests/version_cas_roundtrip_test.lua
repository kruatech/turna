-- deploy/tarantool/tests/version_cas_roundtrip_test.lua
--
-- #6: end-to-end exact-u64 round-trip through the REAL Tarantool CAS stored
-- procedures — the path a version actually travels:
--
--     Rust decimal string → turna_parse_u64_exact → unsigned tuple / state JSON
--         → read back → exact decimal
--
-- Complements u64_parser_test.lua (which exercises the parser in isolation) and
-- the Rust memory-backend boundary tests (the reference). Verifies runtime and
-- user-limits desired-version CAS stay exact at 2^53+1 and u64::MAX, and that the
-- user-limits counter refuses to overflow.
--
-- Usage (against a throwaway instance that has already loaded init.lua):
--     tarantool
--     > dofile('deploy/tarantool/init.lua')
--     > dofile('deploy/tarantool/tests/version_cas_roundtrip_test.lua')
--
-- NOTE: NOT executed in the authoring environment (no Tarantool).

local tap = require('tap')
local json = require('json')
local clock = require('clock')

assert(box.func['turna_cas_runtime_desired'] ~= nil
    and box.func['turna_cas_user_limits_desired'] ~= nil,
    'load deploy/tarantool/init.lua before this test')

local function now_ms() return math.floor(clock.realtime() * 1000) end
local function dec(v) return (tostring(v):gsub('[UL]+$', '')) end

local test = tap.test('runtime / user-limits CAS u64 round-trip')
test:plan(5)

test:test('runtime desired version round-trips exactly', function(t)
    t:plan(4)
    box.space.turna_runtime_state:truncate()
    local CAS = box.func['turna_cas_runtime_desired']
    local GET = box.func['turna_get_runtime_state']
    -- vacant at version 0 (observed stays 0, so expected=0 keeps matching).
    t:ok(CAS:call({ 'rt', '0', 'inc-1', json.encode({ version = 0 }) }), 'vacant v0')
    -- desired = 2^53 + 1 (the classic f64-collapse boundary).
    t:ok(
        CAS:call({ 'rt', '0', 'inc-1', json.encode({ version = 9007199254740993ULL }) }),
        'set desired 2^53+1'
    )
    t:is(dec(json.decode(GET:call({ 'rt' })).desired_version), '9007199254740993',
        '2^53+1 stored and read back exactly')
    -- desired = u64::MAX.
    CAS:call({ 'rt', '0', 'inc-1', json.encode({ version = 18446744073709551615ULL }) })
    t:is(dec(json.decode(GET:call({ 'rt' })).desired_version), '18446744073709551615',
        'u64::MAX stored and read back exactly')
end)

test:test('user-limits desired counter crosses 2^53 exactly', function(t)
    t:plan(2)
    box.space.turna_user_limits:truncate()
    local CAS = box.func['turna_cas_user_limits_desired']
    local GET = box.func['turna_get_user_limits_state']
    local node, subject = 'uln', 's'
    local key = tostring(#node) .. ':' .. node .. subject
    -- Seed observed = 2^53 so the +1 counter crosses the boundary on the next CAS.
    local st = {
        schema_version = 1, node_id = node, subject_key = subject, target = {},
        incarnation = 'inc-1',
        desired_version = 9007199254740992ULL, observed_version = 9007199254740992ULL,
        desired_patch = {}, observed_patch = {},
        status = 'observed', last_error = '', updated_at_ms = now_ms(),
    }
    box.space.turna_user_limits:replace({
        key, node, subject, 9007199254740992ULL, 9007199254740992ULL,
        'observed', now_ms(), json.encode(st),
    })
    t:ok(
        CAS:call({ node, subject, '9007199254740992', 'inc-1', json.encode({}), json.encode({}) }),
        'cas at expected 2^53'
    )
    t:is(dec(json.decode(GET:call({ node, subject })).desired_version), '9007199254740993',
        '2^53 + 1 counter value is exact')
end)

test:test('user-limits CAS refuses to overflow at u64::MAX', function(t)
    t:plan(1)
    box.space.turna_user_limits:truncate()
    local CAS = box.func['turna_cas_user_limits_desired']
    local node, subject = 'ulm', 's'
    local key = tostring(#node) .. ':' .. node .. subject
    local st = {
        schema_version = 1, node_id = node, subject_key = subject, target = {},
        incarnation = 'inc-1',
        desired_version = 18446744073709551615ULL, observed_version = 18446744073709551615ULL,
        desired_patch = {}, observed_patch = {},
        status = 'observed', last_error = '', updated_at_ms = now_ms(),
    }
    box.space.turna_user_limits:replace({
        key, node, subject, 18446744073709551615ULL, 18446744073709551615ULL,
        'observed', now_ms(), json.encode(st),
    })
    local ok = pcall(function()
        return CAS:call({ node, subject, '18446744073709551615', 'inc-1',
                          json.encode({}), json.encode({}) })
    end)
    t:ok(not ok, 'cas at expected = u64::MAX errors instead of wrapping to 0')
end)

-- #3 (GA blocker): confirm_* commits the idempotency journal write and the
-- observed-state update as ONE box.atomic transaction. If the observed write
-- fails, the journal write from the same transaction must roll back too — the
-- journal must never say 'applied' while observed state was never bumped.

test:test('runtime confirm rolls back the journal write if observed fails', function(t)
    t:plan(2)
    box.space.turna_runtime_state:truncate()
    box.space.turna_command_idem:truncate()
    local RT = box.func['turna_cas_runtime_desired']
    -- Occupy the runtime row at version 0 (observed 0, incarnation inc-1) and
    -- seed a still-pending canonical idempotency record for the command.
    RT:call({ 'rtx', '0', 'inc-1', json.encode({ version = 0 }) })
    box.space.turna_command_idem:replace({ 'krt', 'reqrt', 'hrt', '', '', 0, 0 })
    -- Force the SECOND write (the observed-state replace) to fail.
    local trig = box.space.turna_runtime_state:before_replace(function()
        error('injected runtime_state write failure', 0)
    end)
    local applied = json.encode({
        idempotency_key = 'krt', request_id = 'reqrt', payload_hash = 'hrt',
        terminal_result = json.encode({ business_outcome = 'applied' }),
        applied_at_ms = 123,
    })
    local ok = pcall(function()
        return box.func['turna_confirm_runtime_observed']:call({
            'rtx', '0', 'inc-1', json.encode({ version = 0 }), 'observed', '', applied,
        })
    end)
    box.space.turna_runtime_state:before_replace(nil, trig) -- always remove
    t:ok(not ok, 'confirm errors when the observed-state write fails')
    local rec = box.space.turna_command_idem:get('krt')
    t:is(rec[4], '',
        'journal outcome rolled back with the failed observed update (still pending)')
end)

test:test('user-limits confirm rolls back the journal write if observed fails', function(t)
    t:plan(2)
    box.space.turna_user_limits:truncate()
    box.space.turna_command_idem:truncate()
    local CAS = box.func['turna_cas_user_limits_desired']
    local node, subject = 'ulx', 's'
    -- Occupy the limits row: vacant CAS sets desired_version = 1, observed 0.
    CAS:call({ node, subject, '0', 'inc-1', json.encode({}), json.encode({}) })
    box.space.turna_command_idem:replace({ 'kul', 'requl', 'hul', '', '', 0, 0 })
    local trig = box.space.turna_user_limits:before_replace(function()
        error('injected user_limits write failure', 0)
    end)
    local applied = json.encode({
        idempotency_key = 'kul', request_id = 'requl', payload_hash = 'hul',
        terminal_result = json.encode({ business_outcome = 'applied' }),
        applied_at_ms = 123,
    })
    local ok = pcall(function()
        return box.func['turna_confirm_user_limits_observed']:call({
            node, subject, '1', 'inc-1', json.encode({}), 'observed', '', applied,
        })
    end)
    box.space.turna_user_limits:before_replace(nil, trig) -- always remove
    t:ok(not ok, 'confirm errors when the observed-state write fails')
    local rec = box.space.turna_command_idem:get('kul')
    t:is(rec[4], '',
        'journal outcome rolled back with the failed observed update (still pending)')
end)

os.exit(test:check() and 0 or 1)
