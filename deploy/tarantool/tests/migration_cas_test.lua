-- deploy/tarantool/tests/migration_cas_test.lua
--
-- Regression tests for the command-log idempotency-migration page CAS (#2) and
-- the partial-terminal-row classification (#3). Exercises the REAL stored
-- functions from init.lua — it does not re-implement their logic.
--
-- Usage (against a throwaway instance that has already loaded init.lua):
--
--     tarantool
--     > dofile('deploy/tarantool/init.lua')          -- schema + funcs
--     > dofile('deploy/tarantool/tests/migration_cas_test.lua')
--
-- or wire it into the project's Tarantool test runner. It only reads/writes the
-- migration spaces and calls the published procedures, so it is safe to run on
-- a disposable instance.
--
-- NOTE: this file has NOT been executed here (no Tarantool in the authoring
-- environment); it is provided for the maintainer to run.

local tap = require('tap')
local json = require('json')
local clock = require('clock')

assert(box.func['turna_migration_idem_apply'] ~= nil
    and box.func['turna_migration_idem_fetch'] ~= nil,
    'load deploy/tarantool/init.lua before this test')

local M = box.space.turna_migrations
local I = box.space.turna_command_idem
local C = box.space.turna_commands
local NAME = 'command_log_backfill_v2'

local function now_ms() return math.floor(clock.realtime() * 1000) end

local function reset()
    M:truncate(); I:truncate(); C:truncate()
end

-- Seed the migration row directly in the idempotency phase with a known
-- (cursor, owner, lease, fencing token).
local function seed_mig(cursor, owner, token, lease_expires_ms)
    M:replace({ NAME, cursor, 0, false, now_ms(), 'idempotency', 0,
                owner, lease_expires_ms, token })
end

-- apply(owner, updates_tbl, cursor_next, done, scanned, errors, ttl,
--       expected_cursor, expected_token, expected_phase)
local function apply(owner, updates, cur_next, done, scanned, exp_cursor, exp_token, exp_phase)
    return box.func['turna_migration_idem_apply']:call({
        owner, json.encode(updates), cur_next, tostring(done), tostring(scanned),
        '0', '30000', exp_cursor, tostring(exp_token), exp_phase,
    })
end

local function fetch(owner, cap)
    local raw = box.func['turna_migration_idem_fetch']:call({ tostring(cap), owner, '30000' })
    return json.decode(raw)
end

local test = tap.test('command-log migration page CAS + partial rows')
test:plan(12)

-- 1. Stale fencing token → no write, cursor unchanged.
test:test('stale token does not apply or advance', function(t)
    t:plan(2)
    reset()
    seed_mig('C1', 'A', 5, now_ms() + 60000)
    I:replace({ 'k1', 'req1', '', '', '', 0, 0 })          -- legacy, empty hash
    apply('A', { { key = 'k1', req = 'req1', payload_hash = 'h1',
                   final_status = 'done', result = 'R', created_at_ms = 1, completed_at_ms = 2 } },
          'C2', false, 1, 'C1', 4 --[[ stale: real token is 5 ]], 'idempotency')
    t:is(M:get(NAME)[2], 'C1', 'cursor not advanced by stale page')
    t:is(I:get('k1')[4], '', 'row not written by stale page')
end)

-- 2. Cursor mismatch → stale.
test:test('cursor mismatch does not apply', function(t)
    t:plan(1)
    reset()
    seed_mig('C1', 'A', 5, now_ms() + 60000)
    I:replace({ 'k1', 'req1', '', '', '', 0, 0 })
    apply('A', { { key = 'k1', req = 'req1', payload_hash = 'h1', final_status = 'done',
                   result = 'R', created_at_ms = 1, completed_at_ms = 2 } },
          'C2', false, 1, 'CX' --[[ wrong ]], 5, 'idempotency')
    t:is(I:get('k1')[4], '', 'row not written on cursor mismatch')
end)

-- 3. Phase mismatch → stale.
test:test('phase mismatch does not apply', function(t)
    t:plan(1)
    reset()
    seed_mig('C1', 'A', 5, now_ms() + 60000)
    I:replace({ 'k1', 'req1', '', '', '', 0, 0 })
    apply('A', { { key = 'k1', req = 'req1', payload_hash = 'h1', final_status = 'done',
                   result = 'R', created_at_ms = 1, completed_at_ms = 2 } },
          'C2', false, 1, 'C1', 5, 'commands' --[[ wrong phase ]])
    t:is(I:get('k1')[4], '', 'row not written on phase mismatch')
end)

-- 4. Matching CAS → applies + advances cursor.
test:test('matching CAS applies and advances', function(t)
    t:plan(2)
    reset()
    seed_mig('C1', 'A', 5, now_ms() + 60000)
    I:replace({ 'k1', 'req1', '', '', '', 0, 0 })
    apply('A', { { key = 'k1', req = 'req1', payload_hash = 'h1', final_status = 'done',
                   result = 'R', created_at_ms = 1, completed_at_ms = 2 } },
          'C2', false, 1, 'C1', 5, 'idempotency')
    t:is(I:get('k1')[4], 'done', 'row written under matching CAS')
    t:is(M:get(NAME)[2], 'C2', 'cursor advanced under matching CAS')
end)

-- 5. A terminal outcome written between fetch and apply is never overwritten.
test:test('terminal outcome not downgraded', function(t)
    t:plan(1)
    reset()
    seed_mig('C1', 'A', 5, now_ms() + 60000)
    I:replace({ 'k2', 'req2', 'h2', 'done', 'OLD', 1, 2 })   -- already terminal
    apply('A', { { key = 'k2', req = 'req2', payload_hash = 'h2', final_status = 'failed',
                   result = 'NEW', created_at_ms = 9, completed_at_ms = 9 } },
          'C2', false, 1, 'C1', 5, 'idempotency')
    t:is(I:get('k2')[5], 'OLD', 'concurrent terminal result preserved')
end)

-- 6. Key GC'd + reused by a different command → the new row is not clobbered.
test:test('reused idempotency key not clobbered', function(t)
    t:plan(2)
    reset()
    seed_mig('C1', 'A', 5, now_ms() + 60000)
    -- The page was fetched for req-OLD, but by apply time the key belongs to a
    -- brand-new pending command req-NEW (empty final_status).
    I:replace({ 'k3', 'req-NEW', 'hnew', '', '', 100, 0 })
    apply('A', { { key = 'k3', req = 'req-OLD', payload_hash = 'hold', final_status = 'done',
                   result = 'STALE', created_at_ms = 1, completed_at_ms = 2 } },
          'C2', false, 1, 'C1', 5, 'idempotency')
    t:is(I:get('k3')[2], 'req-NEW', 'new owner of the key preserved')
    t:is(I:get('k3')[4], '', 'new pending row not turned terminal by a stale page')
end)

-- 7. Expired lease → stale (even for the same owner).
test:test('expired lease does not apply', function(t)
    t:plan(1)
    reset()
    seed_mig('C1', 'A', 5, now_ms() - 1000 --[[ already expired ]])
    I:replace({ 'k1', 'req1', '', '', '', 0, 0 })
    apply('A', { { key = 'k1', req = 'req1', payload_hash = 'h1', final_status = 'done',
                   result = 'R', created_at_ms = 1, completed_at_ms = 2 } },
          'C2', false, 1, 'C1', 5, 'idempotency')
    t:is(I:get('k1')[4], '', 'row not written when lease expired')
end)

-- 8. #3: a row that LOOKS pending (hash set, no outcome) but whose command is
--    already terminal is classified as partial and included by fetch.
test:test('partial terminal row (hash set, command done) is migrated', function(t)
    t:plan(2)
    reset()
    seed_mig('', 'A', 0, now_ms() + 60000)
    -- idem row looks pending: hash present, no final_status/result/completed.
    I:replace({ 'k4', 'req4', 'h4', '', '', 0, 0 })
    -- linked command is terminal.
    C:replace({ 'req4', 'node', json.encode({ op = 'update_config', args = {},
                payload_json = '{}', status = 'done', result = 'DONE',
                created_at_ms = 1, updated_at_ms = 2 }), 'done', 2 })
    local page = fetch('A', 10)
    local found = false
    for _, r in ipairs(page.rows or {}) do if r.key == 'k4' then found = true end end
    t:ok(found, 'partial-terminal row selected for migration')
    t:is(page.lease_token, page.lease_token, 'fetch returns a fencing token') -- token present
end)

-- 9. #3: a genuine pending row (hash set, command still in-flight) is NOT
--    migrated by fetch.
test:test('genuine pending row (command in-flight) is skipped', function(t)
    t:plan(1)
    reset()
    seed_mig('', 'A', 0, now_ms() + 60000)
    I:replace({ 'k5', 'req5', 'h5', '', '', 0, 0 })
    C:replace({ 'req5', 'node', json.encode({ op = 'update_config', args = {},
                payload_json = '{}', status = 'in_progress' }), 'in_progress', 1 })
    local page = fetch('A', 10)
    local found = false
    for _, r in ipairs(page.rows or {}) do if r.key == 'k5' then found = true end end
    t:ok(not found, 'in-flight pending row left for its command lifecycle')
end)

-- 10. #6: the fencing token is an EXACT uint64 — a value above 2^53 is never
--     collapsed onto a neighbour, so a stale page cannot pass the CAS.
test:test('fencing token above 2^53 is compared exactly', function(t)
    t:plan(2)
    reset()
    local p53 = 9007199254740992ULL -- 2^53
    M:replace({ NAME, 'C1', 0, false, now_ms(), 'idempotency', 0, 'A',
                now_ms() + 60000, p53 + 1ULL }) -- generation = 2^53 + 1
    I:replace({ 'k1', 'req1', '', '', '', 0, 0 })
    -- expected_token = 2^53 must NOT match the stored 2^53 + 1 → stale, no write.
    apply('A', { { key = 'k1', req = 'req1', payload_hash = 'h1', final_status = 'done',
                   result = 'R', created_at_ms = 1, completed_at_ms = 2 } },
          'C2', false, 1, 'C1', '9007199254740992', 'idempotency')
    t:is(I:get('k1')[4], '', 'token 2^53 must not equal 2^53+1')
    -- the exact token applies.
    apply('A', { { key = 'k1', req = 'req1', payload_hash = 'h1', final_status = 'done',
                   result = 'R', created_at_ms = 1, completed_at_ms = 2 } },
          'C2', false, 1, 'C1', '9007199254740993', 'idempotency')
    t:is(I:get('k1')[4], 'done', 'exact token 2^53+1 applies')
end)

-- 11. #6: a takeover bumps the generation by exactly one, even at the top of the
--     range (MAX-1 -> MAX), with no rounding.
test:test('lease generation increments exactly to u64::MAX', function(t)
    t:plan(1)
    reset()
    M:replace({ NAME, '', 0, false, now_ms(), 'idempotency', 0, 'A',
                now_ms() - 1000, 18446744073709551614ULL }) -- gen = MAX-1, lease expired
    fetch('B', 10) -- new owner + expired lease -> takeover bumps the generation
    local gen = M:get(NAME)[10]
    t:is((tostring(gen):gsub('ULL$', '')), '18446744073709551615',
        'MAX-1 bumped exactly to MAX')
end)

-- 12. #6: at u64::MAX the generation refuses to overflow — no new lease is
--     issued and the row is left unchanged (no wrap to 0).
test:test('lease generation refuses to overflow at u64::MAX', function(t)
    t:plan(2)
    reset()
    M:replace({ NAME, 'C9', 5, false, now_ms(), 'idempotency', 0, 'A',
                now_ms() - 1000, 18446744073709551615ULL }) -- gen = MAX, lease expired
    local ok = pcall(function()
        return box.func['turna_migration_idem_fetch']:call({ '10', 'B', '30000' })
    end)
    t:ok(not ok, 'takeover at generation u64::MAX errors instead of wrapping')
    local row = M:get(NAME)
    t:is((tostring(row[10]):gsub('ULL$', '')), '18446744073709551615',
        'generation unchanged after a refused overflow')
end)

os.exit(test:check() and 0 or 1)
