-- The boundary between the agent and uloop, without uloop.
--
--   lua tests/guard.lua        (from the repository root)
--
-- The thing being asserted is narrow and worth being sure of: a callback that
-- throws must cost one event, not the session — and for the callbacks that
-- re-arm their own timer, it must cost one turn and not the whole cycle.
package.path = 'files/usr/lib/lua/?.lua;' .. package.path
local guard = require('apman-guard')

local logged = {}
guard.log = function(m) logged[#logged + 1] = m end
local function reset() guard.reset(); logged = {} end

-- a callback that works is passed through untouched, arguments and all
reset()
local add = guard.wrap('add', function(a, b) return a + b, 'and more' end)
local x, y = add(2, 3)
assert(x == 5 and y == 'and more', 'return values must survive the wrapper')
assert(guard.errors == 0 and #logged == 0, 'and nothing is logged for a good call')
print('1 a working callback is untouched')

-- one that throws is caught, counted and named
reset()
local boom = guard.wrap('reader', function() local t = nil; return t.x end)
assert(boom() == nil, 'a thrown callback returns nil rather than propagating')
assert(guard.errors == 1, 'counted')
assert(guard.last.name == 'reader', 'and named, got ' .. tostring(guard.last.name))
assert(#logged == 1 and string.find(logged[1], 'reader', 1, true), 'the name is in the log')
print('2 a throw costs the event, not the session')

-- repeated failures are countable per callback, so a loop looks like a loop
reset()
local bad = guard.wrap('loop', function() error('again') end)
for _ = 1, 5 do bad() end
assert(guard.by_name['loop'] == 5, 'five, got ' .. tostring(guard.by_name['loop']))
assert(guard.errors == 5)
print('3 a loop is visible as a loop')

-- the case that matters most: a self-rescheduling callback must be re-armed,
-- because swallowing the error without it would stop the cycle for good
reset()
local rearmed = 0
local tick = guard.wrap('status', function() error('mid-cycle') end,
	function() rearmed = rearmed + 1 end)
tick(); tick()
assert(rearmed == 2, 'the timer is put back every time, got ' .. rearmed)
print('4 a self-rescheduling callback is re-armed')

-- and if putting it back throws as well, that is reported rather than thrown
-- out of the handler that exists to stop throws
reset()
local hopeless = guard.wrap('doomed', function() error('one') end,
	function() error('two') end)
assert(hopeless() == nil, 'still does not propagate')
assert(#logged == 2, 'both the error and the failed recovery are logged, got ' .. #logged)
print('5 a failing recovery does not escape either')

-- counters(), which is what gets published
reset()
guard.wrap('published', function() error('x') end)()
local c = guard.counters()
assert(c.errors == 1 and c.last == 'published' and c.by_name['published'] == 1,
	'the counters name what failed')
print('6 counters ok')

-- anything that is not a function comes back as it was, rather than being
-- turned into one that returns nil
assert(guard.wrap('n', 42) == 42, 'a non-function is not wrapped')
assert(guard.wrap('n', nil) == nil)
print('7 non-callables pass through')

print('guard tests passed')
