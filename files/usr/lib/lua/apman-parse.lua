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



-- The "key=value" tail of a hostapd control channel event.
--
--   AP-STA-CONNECTED 00:11:22:33:44:55 auth_alg=open keyid=17-anna vlanid=7
--
-- This used to be one gmatch over '([%w_%-]+)=(%S+)' inside apman-ctrl.lua,
-- which was right for as long as no value could contain a space.
--
-- The SAE-over-RADIUS patches (810-815, package wpad-saeradh2e) end that:
-- AP-STA-CONNECTED now also carries
--
--   identity="alice" sae_password_id="guest-week33"
--
-- and both are quoted precisely because they may contain spaces -- hostapd.conf's
-- own example of a password identifier is `id=pw identifier`. Under the old
-- pattern that value arrived as `"pw` and the remainder was silently dropped,
-- which is the kind of loss that looks like a working parser.
--
-- Quotes are stripped, so a consumer never sees them. hostapd printf_encode()s
-- both values before quoting, so a literal quote inside arrives as \" and must
-- not be allowed to end the value; that pair and \\ are turned back into the
-- character they stand for, and any other escape is left exactly as it came so
-- nothing is invented.
function parse.event_fields(tail)
	local fields = {}
	if type(tail) ~= 'string' then
		return fields
	end
	local pos, len = 1, #tail
	while pos <= len do
		local s, e, key = string.find(tail, '([%w_%-]+)=', pos)
		if s == nil then
			break
		end
		local value
		if string.sub(tail, e + 1, e + 1) == '"' then
			local out, i = {}, e + 2
			while i <= len do
				local c = string.sub(tail, i, i)
				if c == '\\' and i < len then
					local nxt = string.sub(tail, i + 1, i + 1)
					if nxt == '"' or nxt == '\\' then
						out[#out + 1] = nxt
					else
						out[#out + 1] = c .. nxt
					end
					i = i + 2
				elseif c == '"' then
					break
				else
					out[#out + 1] = c
					i = i + 1
				end
			end
			value = table.concat(out)
			-- past the closing quote, or past the end if there was none
			pos = i + 1
		else
			value = string.match(tail, '^(%S*)', e + 1) or ''
			pos = e + 1 + #value
		end
		fields[key] = value
	end

	return fields
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
