-- The boundary between this agent and uloop.
--
-- An error thrown out of a uloop callback does not end the callback, it ends
-- uloop.run() and with it the agent. procd puts it back about ten seconds
-- later, so the access point survives — but the control channel monitors, the
-- syslog stream and every counter start again from nothing, and what reaches
-- the log is a stack traceback with no name on it.
--
-- That is not hypothetical. On 2026-08-18 an unguarded nil index at
-- apman.lua:503 killed the agent during boot on every access point that came
-- up with an interface hostapd had not finished setting up. The fix at the
-- time was the one line; this is the shape.
--
-- Nothing here makes errors go away. It makes one cost an event instead of a
-- session, and it puts the name of the callback in the log next to the reason,
-- which is the difference between "something threw" and "the syslog reader
-- threw".
local guard = {}

-- 5.1 on the access points has a global unpack, 5.3 and later have
-- table.unpack. This module runs on both — the tests run on whatever lua the
-- workstation has, the agent on whatever the image ships.
local unpack_ = table.unpack or unpack

guard.errors = 0
guard.last = nil          -- { name, err, ts } of the most recent one
guard.by_name = {}        -- name -> count, so a loop is visible as a loop

-- Optional: set by the host so a failure can be printed the same way the rest
-- of the agent prints. Defaults to print, which reaches syslog through procd.
guard.log = print

--
-- Wrap a callback so a throw inside it is caught, counted and named.
--
-- Arguments and return values pass through untouched: uloop hands an fd
-- callback its events and a process callback its exit code, and a caller that
-- wraps a function must not change what that function is.
--
-- `recover` matters more than it looks. The periodic callbacks of this agent
-- re-arm their own timer as their last statement — apman.lua's status, mqtt
-- and ubus_check all do, and the comment above ubusCheckCallback says why:
-- "the poll must stay armed or the whole resubscribe machinery dies quietly".
-- For those, catching the error without re-arming would be WORSE than letting
-- it through: a crash is loud and procd puts the agent back within seconds,
-- while a timer that quietly stopped looks like an agent that is running fine
-- and doing nothing. So a self-rescheduling callback passes a recover function
-- that sets its timer again, and it runs after the error is logged.
--
function guard.wrap(name, fn, recover)
	if type(fn) ~= 'function' then
		return fn
	end

	return function(...)
		local res = { pcall(fn, ...) }
		if res[1] then
			return unpack_(res, 2)
		end

		local err = tostring(res[2])
		guard.errors = guard.errors + 1
		guard.by_name[name] = (guard.by_name[name] or 0) + 1
		guard.last = { name = name, err = err, count = guard.by_name[name] }
		guard.log(string.format('apman-error in %s (%d. time): %s',
			name, guard.by_name[name], err))

		if type(recover) == 'function' then
			-- and if putting it back fails too, say so rather than throwing
			-- from inside the handler that exists to stop throws
			local ok2, err2 = pcall(recover)
			if not ok2 then
				guard.log(string.format('apman-error recovering %s: %s',
					name, tostring(err2)))
			end
		end

		return nil
	end
end

-- What to publish alongside the other counters.
function guard.counters()
	return {
		errors = guard.errors,
		last = guard.last and guard.last.name or nil,
		last_error = guard.last and guard.last.err or nil,
		by_name = guard.by_name,
	}
end

function guard.reset()
	guard.errors = 0
	guard.last = nil
	guard.by_name = {}
end

return guard
