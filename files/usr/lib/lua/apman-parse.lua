-- The parsing that has no dependencies.
--
-- Both of these are pure string in, table out — no ubus, no broker, no state.
-- That is the whole reason they are here: while they sat in the middle of
-- apman.lua they could not be exercised without an access point, and neither
-- of them had a single test. tests/parse.lua runs them anywhere lua does.

local parse = {}


-- Turn the station dump text into a map station -> fields.
--
-- The consumer used to do this with string operations on every status message,
-- ten times a second in a single process. Doing it here spreads the work over
-- the access points and it only happens once per interval anyway. Payload
-- version 2 marks the structured form.
function parse.station_dump(text)
	local stations = {}
	local current = nil
	local pos, len = 1, #text

	while pos <= len do
		local line
		local nl = string.find(text, "\n", pos, true)
		if nl then
			line = string.sub(text, pos, nl - 1)
			pos = nl + 1
		else
			line = string.sub(text, pos)
			pos = len + 1
		end

		local mac = string.match(line, "^Station (%x%x:%x%x:%x%x:%x%x:%x%x:%x%x)")
		if mac ~= nil then
			current = string.lower(mac)
			stations[current] = { device = string.match(line, "%(on (%S+)%)") }
		elseif current ~= nil then
			local key, value = string.match(line, "^%s*(.-):%s*(.*)$")
			if key ~= nil and key ~= '' then
				-- same normalisation the consumer used, so the field names
				-- stay the ones everything downstream already knows
				key = string.gsub(key, "[ ,%.%-/]", "_")
				stations[current][key] = value
			end
		end
	end

	return stations
end


-- 12 bare hex chars -> aa:bb:cc:dd:ee:ff, the format the controller and
-- every log reader expects; anything else passes through untouched
-- bare hex to colon form; case is left alone, and anything that is not
-- twelve hex characters comes back unchanged
function parse.format_mac(hex)
	if type(hex) == 'string' and #hex == 12 then
		-- the parentheses matter: gsub returns the string AND the number of
		-- replacements, and without them a caller that takes several values
		-- (a table constructor, the tail of an argument list) silently gets
		-- a stray 1 alongside the address
		return (hex:gsub('(%x%x)(%x%x)(%x%x)(%x%x)(%x%x)(%x%x)', '%1:%2:%3:%4:%5:%6'))
	end
	return hex
end

return parse
