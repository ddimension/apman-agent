-- The filter, without a broker and without an access point.
--
--   lua tests/syslog.lua        (from the repository root)
--
-- Everything here is a decision the agent makes about a line before it leaves
-- the device, which is exactly the kind of thing that is cheap to be sure of
-- here and expensive to be wrong about in the field.
package.path = 'files/usr/lib/lua/?.lua;/tmp/?.lua;' .. package.path
local S = require('apman-syslog')

-- ident: syslog writes "ident: text" and "ident[pid]: text"
assert(S.ident('hostapd: wap-kc1: AP-ENABLED') == 'hostapd', 'plain ident')
assert(S.ident('apman-status[8493]: Attached to ...') == 'apman-status', 'ident with pid')
assert(S.ident('netifd: radio1 (4141): wifi-scripts: ...') == 'netifd', 'first colon wins')
assert(S.ident('[115337.276446] apman kernel probe') == nil, 'the kernel names nobody')
assert(S.ident('a line without a colon') == nil, 'no colon, no ident')
assert(S.ident(nil) == nil, 'nil stays nil')
print('1 ident ok')

-- text: the ident is not repeated in the payload
assert(S.text('hostapd: wap-kc1: AP-ENABLED') == 'wap-kc1: AP-ENABLED', 'only the first colon')
assert(S.text('apman-status[8493]: hello') == 'hello', 'pid form')
assert(S.text('[115337.276446] apman kernel probe') == '[115337.276446] apman kernel probe',
	'a kernel line has no ident to cut')
print('2 text ok')

-- priority: syslog(3) packs facility and level into one number.
-- Measured on the device: daemon.warn arrived as 28, user.notice as 13.
assert(S.facility(28) == 3 and S.level(28) == 4, 'daemon.warn is 28')
assert(S.facility(13) == 1 and S.level(13) == 5, 'user.notice is 13')
assert(S.facility(12) == 1 and S.level(12) == 4, 'kernel probe came in as 12')
assert(S.facility(nil) == nil, 'nothing in, nothing out')
print('3 priority ok')

-- the filter itself
S.configure({ enabled = true, allow_add = { 'mydaemon' }, allow_re = { '^wpa%-' } })

local kernel = { source = 0, priority = 12, msg = '[1.0] something' }
local hostapd = { source = 1, priority = 28, msg = 'hostapd: wap-kc1: AP-ENABLED' }
local own = { source = 1, priority = 30, msg = 'apman-status[1]: published' }
local other = { source = 1, priority = 30, msg = 'somethingelse: chatter' }
local added = { source = 1, priority = 30, msg = 'mydaemon: from uci' }
local bypat = { source = 1, priority = 30, msg = 'wpa-cli: matched a pattern' }
local nameless = { source = 1, priority = 30, msg = 'no ident here at all' }

local function want(rec) local w = S.wanted(rec); return w end
assert(want(kernel), 'the kernel always goes through')
assert(want(hostapd), 'a default ident goes through')
assert(not want(own), 'our own lines never do')
assert(not want(other), 'an unlisted ident does not')
assert(want(added), 'uci can add one')
assert(want(bypat), 'and a pattern can match one')
assert(not want(nameless), 'a line naming nobody is not published on a guess')
print('4 filter ok')

-- allow_all lets everything through except our own, which is the one rule
-- that is not a list
S.configure({ enabled = true, allow_all = true })
assert(want(other), 'allow_all means all')
assert(not want(own), 'except ours, still')
print('5 allow_all keeps the one exception')

-- and the kernel can be switched off, for somebody who only wants daemons
S.configure({ enabled = true, kernel = false })
assert(not want(kernel), 'kernel = false is honoured')
S.configure({ enabled = true })
assert(want(kernel), 'and true again by default')
print('6 kernel switch ok')

-- a config that adds an ident must not leave it behind when it stops
S.configure({ enabled = true, allow_add = { 'temporary' } })
assert(want({ source = 1, msg = 'temporary: here' }), 'added')
S.configure({ enabled = true })
assert(not want({ source = 1, msg = 'temporary: here' }), 'and gone again on the next config')
print('7 the list is rebuilt, not accumulated')

-- dropping a default
S.configure({ enabled = true, allow_drop = { 'hostapd' } })
assert(not want(hostapd), 'a default can be dropped')
print('8 allow_drop ok')

-- payload: the shape the controller receives
S.configure({ enabled = true })
local p = S.payload({ id = 10544, time = 1787514663721, source = 1, priority = 28,
	msg = 'hostapd: wap-kc1: AP-ENABLED' })
assert(p.id == 10544 and p.ts == 1787514663721, 'id and time come through as numbers')
assert(p.source == 'syslog' and p.facility == 3 and p.level == 4, 'decoded')
assert(p.ident == 'hostapd' and p.text == 'wap-kc1: AP-ENABLED', 'split once')
assert(p.truncated == nil, 'a short line is not marked')
S.max_text = 8
local long = S.payload({ source = 1, priority = 28, msg = 'hostapd: 0123456789abcdef' })
assert(#long.text == 8 and long.truncated == true, 'a long one is cut and says so')
S.max_text = 1024
print('9 payload ok')

-- feed: framing over a stream. blob_decode is stubbed, because what is being
-- tested here is the buffering around it and not the C.
local fake = { records = {}, }
S.opts.ubus = {
	blob_decode = function(buf)
		-- a record is "<len>|<source>|<msg>"
		local len = buf:match('^(%d+)|')
		if len == nil then return nil, 'invalid' end
		local total = tonumber(len)
		if #buf < total then return nil, 'incomplete' end
		local body = buf:sub(#len + 2, total)
		local source, msg = body:match('^(%d+)|(.*)$')
		return { source = tonumber(source), priority = 28, msg = msg, id = 1, time = 1 }, total
	end,
}
local function record(source, msg)
	local body = source .. '|' .. msg
	local len = #body + 1
	-- the length prefix counts itself, so it has to settle
	local s = tostring(len)
	while #s + 1 + #body ~= tonumber(s) do
		s = tostring(#s + 1 + #body)
	end
	return s .. '|' .. body
end

S.configure({ enabled = true })
S.buf = ''
for k in pairs(S.counters) do S.counters[k] = 0 end
local got = {}
local emit = function(e) got[#got + 1] = e end

local one = record(1, 'hostapd: first')
local two = record(1, 'somethingelse: dropped')
local three = record(0, '[1.0] kernel line')
local stream = one .. two .. three

-- fed in three pieces, none of them on a record boundary
S.feed(stream:sub(1, 5), emit)
S.feed(stream:sub(6, #one + 3), emit)
S.feed(stream:sub(#one + 4), emit)

assert(S.counters.records == 3, 'three records out of three fragments, got ' .. S.counters.records)
assert(#got == 2, 'hostapd and the kernel line, not the chatter — got ' .. #got)
assert(got[1].text == 'first' and got[2].source == 'kernel', 'in order')
assert(S.counters.dropped == 1 and S.counters.kernel == 1, 'counted')
assert(#S.buf == 0, 'nothing left over when the last record was whole')
print('10 feed reassembles across reads')

-- a partial tail stays in the buffer rather than being lost or guessed at
S.buf = ''
for k in pairs(S.counters) do S.counters[k] = 0 end
got = {}
S.feed(one .. two:sub(1, 4), emit)
assert(S.counters.records == 1 and #got == 1, 'only the whole one came out')
assert(#S.buf == 4, 'and the tail waits, got ' .. #S.buf)
print('11 a partial tail waits')

-- junk that is not a record at all: the buffer has lost the boundary and
-- there is no way back to it, so it is dropped and counted rather than
-- retried forever
S.buf = ''
for k in pairs(S.counters) do S.counters[k] = 0 end
S.feed('this is not a record', emit)
assert(#S.buf == 0 and S.counters.restarts == 1, 'buffer reset once and counted')
print('12 a lost boundary is not retried forever')

print('syslog tests passed')
