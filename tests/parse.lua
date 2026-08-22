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

print('parse tests passed')
