-- deploy/tarantool/tests/u64_parser_test.lua
--
-- #6: exact-u64 boundary tests for the shared version parser
-- `turna_parse_u64_exact`. Verifies the §6.5 contract: exact parsing across the
-- whole u64 range (no f64 collapse above 2^53), decimal-string requirement for
-- large values, and rejection of overflow / malformed inputs.
--
-- Usage (against a throwaway instance that has already loaded init.lua):
--     tarantool
--     > dofile('deploy/tarantool/init.lua')
--     > dofile('deploy/tarantool/tests/u64_parser_test.lua')
--
-- NOTE: NOT executed in the authoring environment (no Tarantool). Provided for
-- the maintainer to run.

local tap = require('tap')
assert(type(turna_parse_u64_exact) == 'function',
    'load deploy/tarantool/init.lua before this test')

-- Decimal of a parsed uint64, without the LuaJIT "ULL" suffix (if present).
local function dec(u)
    return (tostring(u):gsub('ULL$', ''))
end

local test = tap.test('turna_parse_u64_exact boundaries')
test:plan(2)

test:test('valid boundary values parse exactly', function(t)
    local cases = {
        { '0', '0' },
        { '1', '1' },
        { '9007199254740991', '9007199254740991' },        -- 2^53 - 1
        { '9007199254740992', '9007199254740992' },        -- 2^53 (string only)
        { '9007199254740993', '9007199254740993' },        -- 2^53 + 1 (f64-collapse case)
        { '18446744073709551614', '18446744073709551614' }, -- u64::MAX - 1
        { '18446744073709551615', '18446744073709551615' }, -- u64::MAX
        { '01', '1' },                                       -- leading zeros allowed
    }
    t:plan(#cases + 2)
    for _, c in ipairs(cases) do
        local ok, u = pcall(turna_parse_u64_exact, c[1])
        t:ok(ok and dec(u) == c[2], 'string "' .. c[1] .. '" -> ' .. c[2])
    end
    -- A Lua number is fine while it stays in the exact (< 2^53) range.
    local ok_n, un = pcall(turna_parse_u64_exact, 9007199254740991)
    t:ok(ok_n and dec(un) == '9007199254740991', 'number 2^53-1 accepted')
    -- Distinctness: 2^53 and 2^53+1 must NOT be equal after parsing.
    local a = turna_parse_u64_exact('9007199254740992')
    local b = turna_parse_u64_exact('9007199254740993')
    t:ok(a ~= b, '2^53 and 2^53+1 stay distinct')
end)

test:test('invalid inputs are rejected (never wrapped)', function(t)
    local bad_strings = {
        '18446744073709551616', -- u64::MAX + 1
        '-1', '1.5', '', ' ', '1x', '+1', '0x10', '1e3',
    }
    t:plan(#bad_strings + 3)
    for _, v in ipairs(bad_strings) do
        t:ok(not (pcall(turna_parse_u64_exact, v)), 'string "' .. v .. '" rejected')
    end
    -- A Lua number >= 2^53 must be rejected (pass a decimal string instead).
    t:ok(not (pcall(turna_parse_u64_exact, 9007199254740992)), 'number 2^53 rejected')
    -- Fractional / negative numbers rejected.
    t:ok(not (pcall(turna_parse_u64_exact, 1.5)), 'number 1.5 rejected')
    t:ok(not (pcall(turna_parse_u64_exact, -1)), 'number -1 rejected')
end)

os.exit(test:check() and 0 or 1)
