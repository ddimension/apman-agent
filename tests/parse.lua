-- The two pure parsers. Runs anywhere lua does:
--
--   lua tests/parse.lua        (from the repository root)
--
-- They had no test while they lived inside apman.lua, because reaching them
-- meant reaching ubus and a broker first. That is the point of the split.
package.path = 'files/usr/lib/lua/?.lua;/tmp/?.lua;' .. package.path
local P = require('apman-parse')

-- format_mac: the agent receives bare hex from the radius module
assert(P.format_mac('aabbccddeeff') == 'aa:bb:cc:dd:ee:ff', 'bare hex')
assert(P.format_mac('AABBCCDDEEFF') == 'AA:BB:CC:DD:EE:FF', 'case is left alone')
local addr, extra = P.format_mac('aabbccddeeff')
assert(extra == nil, 'gsub must not leak its replacement count to the caller')
assert(P.format_mac('aa:bb:cc:dd:ee:ff') == 'aa:bb:cc:dd:ee:ff', 'already formatted')
assert(P.format_mac('nonsense') == 'nonsense', 'anything else comes back unchanged')
assert(P.format_mac(nil) == nil, 'nil stays nil')
print('1 format_mac ok')

-- station_dump: the text `iw dev <dev> station dump` produces
local dump = [[
Station aa:bb:cc:dd:ee:01 (on wap-kc0)
	inactive time:	120 ms
	rx bytes:	123456
	tx bitrate:	866.7 MBit/s VHT-MCS 9 80MHz short GI VHT-NSS 2
	signal:  	-51 [-54, -57] dBm
	authorized:	yes
Station aa:bb:cc:dd:ee:02 (on wap-kc0)
	inactive time:	5 ms
	signal:  	-72 dBm
	authorized:	no
]]
local st = P.station_dump(dump)
assert(st ~= nil, 'a dump with stations must not parse to nil')
local n = 0
for _ in pairs(st) do n = n + 1 end
assert(n == 2, 'two stations, got ' .. n)
assert(st['aa:bb:cc:dd:ee:01'], 'first station missing')
assert(st['aa:bb:cc:dd:ee:02'], 'second station missing')
print('2 station_dump: ' .. n .. ' stations')

-- the empty cases: an interface with nobody on it, and junk
assert(P.station_dump('') == nil or next(P.station_dump('')) == nil, 'empty dump')
assert(P.station_dump('no stations here') == nil
	or next(P.station_dump('no stations here')) == nil, 'junk dump')
print('3 empty and junk ok')

-- event_fields: the "key=value" tail of a control channel event
local f = P.event_fields('00:11:22:33:44:55 auth_alg=open keyid=17-anna vlanid=7')
assert(f.auth_alg == 'open' and f.keyid == '17-anna' and f.vlanid == '7',
	'the plain form still works')
assert(f['00'] == nil, 'the station address is not a field')
print('4 event_fields: bare values')

-- quoted, which is what the SAE-over-RADIUS patches added
local q = P.event_fields('8c:fd:00:00:00:01 identity="alice" sae_password_id="guest-week33"')
assert(q.identity == 'alice', 'quotes are stripped, got ' .. tostring(q.identity))
assert(q.sae_password_id == 'guest-week33', 'second quoted value')
print('5 event_fields: quotes stripped')

-- the case the old gmatch lost: hostapd.conf's own example is `id=pw identifier`
local sp = P.event_fields('aa:bb:cc:dd:ee:ff sae_password_id="pw identifier" vlanid=7')
assert(sp.sae_password_id == 'pw identifier',
	'a space inside quotes must survive, got ' .. tostring(sp.sae_password_id))
assert(sp.vlanid == '7', 'the field after a quoted one is still found')
print('6 event_fields: a space inside quotes survives')

-- printf_encode escapes: \" is content, not the end of the value
local esc = P.event_fields('identity="a\\"b" keyid=k1')
assert(esc.identity == 'a"b', 'escaped quote decoded, got ' .. tostring(esc.identity))
assert(esc.keyid == 'k1', 'parsing continues after an escaped quote')
local bs = P.event_fields('identity="a\\\\b"')
assert(bs.identity == 'a\\b', 'escaped backslash decoded, got ' .. tostring(bs.identity))
local other = P.event_fields('identity="a\\x41b"')
assert(other.identity == 'a\\x41b', 'an escape we do not decode passes through untouched')
print('7 event_fields: escapes')

-- things that must not hang or throw
assert(next(P.event_fields('')) == nil, 'empty tail')
assert(next(P.event_fields(nil)) == nil, 'nil tail')
assert(next(P.event_fields('AP-DISABLED')) == nil, 'an event with no fields')
local empty = P.event_fields('keyid= vlanid=7')
assert(empty.keyid == '' and empty.vlanid == '7', 'an empty value does not swallow the next field')
local unterminated = P.event_fields('identity="never closed')
assert(unterminated.identity == 'never closed', 'an unterminated quote takes the rest')
print('8 event_fields: edges')

print('parse tests passed')
