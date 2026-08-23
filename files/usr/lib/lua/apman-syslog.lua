-- The system log, over the command channel, filtered before it leaves.
--
-- Not a transport. Every access point in this fleet already forwards its full
-- syslog to a central server over tcp/514, and that is not what this is for.
-- What that copy has no idea about is which access point a line belongs to
-- beyond its hostname, which agent version produced it, whether anything was
-- missed, and how it lines up with the control channel ring buffers the
-- controller already keeps per bss. This carries the same lines with those
-- answers attached.
--
-- The descriptor comes from `log read` with stream:true, which hands one back
-- instead of returning data — the reason libubus-lua-async grew fd_cb,
-- read_fd, close_fd and blob_decode. What comes down it is not text: logd
-- writes blob attributes, each length prefixed, each already carrying
--
--     id        a sequence number, so a gap is visible as one
--     time      milliseconds since the epoch
--     source    0 for the kernel, 1 for syslog — measured, see wanted()
--     priority  facility and level, encoded the way syslog(3) does
--     msg       "ident: text" from syslog, "[ts] text" from the kernel
--
-- which is a good deal better than the rendered line, where all of that would
-- have to be taken apart again with a pattern.
--
-- Filtering happens here and not in the controller. Nine lines a minute at
-- rest is nothing, but a radio restart arrives in a burst, and a line that is
-- never published costs nothing to carry.

local syslog = {}

-- filled by the host: ap_topic(sub) -> topic, publish(topic, payload, qos,
-- retain), and the ubus module, because this one needs read_fd and friends
syslog.opts = { ap_topic = function(s) return s end,
		publish = function() end,
		ubus = nil,
		uloop = nil }

function syslog.bind(opts)
	for k, v in pairs(opts or {}) do
		syslog.opts[k] = v
	end
end

syslog.enabled = false		-- off until asked for: this publishes
syslog.kernel = true		-- kernel messages, unfiltered, always
syslog.allow_all = false	-- everything except our own ident
syslog.max_text = 1024		-- longer lines are cut, with a mark

-- The idents worth having by default. Every one of them says something the
-- controller cannot learn any other way; the rest of a busy access point is
-- dropped rather than shipped and thrown away at the far end.
syslog.allow_default = {
	['hostapd'] = true,
	['wpa_supplicant'] = true,
	['netifd'] = true,
	['kernel'] = true,
	['dnsmasq'] = true,
	['odhcpd'] = true,
	['rpcd'] = true,
	['ubusd'] = true,
}
syslog.allow = syslog.allow_default
syslog.allow_re = {}		-- lua patterns, tried after the plain list

-- Our own lines never go out. 143 of the last 500 on one access point were
-- this process, and publishing a line about having published a line is a loop
-- that ends with the broker. The central syslog has them either way.
syslog.self_ident = 'apman-status'

syslog.fd = nil
syslog.ufd = nil
syslog.buf = ''
syslog.counters = { records = 0, forwarded = 0, dropped = 0, own = 0,
		    kernel = 0, reads = 0, bytes = 0, restarts = 0 }

function syslog.configure(cfg)
	syslog.enabled = cfg.enabled and true or false
	syslog.kernel = cfg.kernel ~= false
	syslog.allow_all = cfg.allow_all and true or false
	syslog.max_text = cfg.max_text or syslog.max_text
	if cfg.self_ident ~= nil and cfg.self_ident ~= '' then
		syslog.self_ident = cfg.self_ident
	end

	-- rebuilt from the built in defaults every time, the same way the control
	-- channel does it: an ident added by a previous config must not survive
	-- its removal from uci
	syslog.allow = {}
	for ident in pairs(syslog.allow_default) do
		syslog.allow[ident] = true
	end
	for _, name in ipairs(cfg.allow_add or {}) do
		if name ~= '' then syslog.allow[name] = true end
	end
	for _, name in ipairs(cfg.allow_drop or {}) do
		syslog.allow[name] = nil
	end
	syslog.allow_re = {}
	for _, pattern in ipairs(cfg.allow_re or {}) do
		if pattern ~= '' then syslog.allow_re[#syslog.allow_re + 1] = pattern end
	end
end

-- The ident a line came from, or nil when the line does not name one.
--
-- syslog writes "ident: text" and "ident[pid]: text"; the kernel writes
-- "[   12.345678] text" and names nobody. Anything else is left alone rather
-- than guessed at — a line without a colon is text, not an ident.
function syslog.ident(msg)
	if type(msg) ~= 'string' then
		return nil
	end
	local ident = msg:match('^([%w%-%_%.%/]+)%[%d+%]:')
	if ident then
		return ident
	end
	return msg:match('^([%w%-%_%.%/]+):')
end

-- The text without the ident in front of it, so the two are not repeated.
function syslog.text(msg)
	if type(msg) ~= 'string' then
		return nil
	end
	local rest = msg:match('^[%w%-%_%.%/]+%[%d+%]:%s*(.*)$')
		or msg:match('^[%w%-%_%.%/]+:%s*(.*)$')
	return rest or msg
end

-- Whether this record leaves the access point.
--
-- source 0 is the kernel and 1 is syslog — measured on ap-av-attic on
-- 2026-08-23 by writing to /dev/kmsg and to logger and watching both arrive:
--
--     source=0 prio=12  [115337.276446] apman kernel probe
--     source=1 prio=27  probe: apman syslog probe
--
-- Kernel messages go through whatever the list says. They are the ones nobody
-- thinks to add to a list and the ones that matter when something has gone
-- wrong underneath — the interface that would not join the bridge, the
-- allocation that failed.
function syslog.wanted(rec)
	if type(rec) ~= 'table' then
		return false, 'not a record'
	end
	if tonumber(rec.source) == 0 then
		return syslog.kernel, 'kernel'
	end

	local ident = syslog.ident(rec.msg)
	-- first, and not subject to any list
	if ident ~= nil and ident == syslog.self_ident then
		return false, 'own'
	end
	if syslog.allow_all then
		return true, 'all'
	end
	if ident == nil then
		return false, 'no ident'
	end
	if syslog.allow[ident] then
		return true, 'listed'
	end
	for _, pattern in ipairs(syslog.allow_re) do
		local ok, matched = pcall(string.match, ident, pattern)
		if ok and matched then
			return true, 'pattern'
		end
	end

	return false, 'not listed'
end

-- syslog(3) packs the facility and the level into one number.
function syslog.facility(priority)
	local p = tonumber(priority)
	return p and math.floor(p / 8) or nil
end

function syslog.level(priority)
	local p = tonumber(priority)
	return p and (p % 8) or nil
end

-- What goes on the wire for one record.
function syslog.payload(rec)
	local text = syslog.text(rec.msg) or ''
	local cut = false
	if #text > syslog.max_text then
		text = text:sub(1, syslog.max_text)
		cut = true
	end

	return {
		id = tonumber(rec.id),
		ts = tonumber(rec.time),
		source = (tonumber(rec.source) == 0) and 'kernel' or 'syslog',
		facility = syslog.facility(rec.priority),
		level = syslog.level(rec.priority),
		ident = syslog.ident(rec.msg),
		text = text,
		truncated = cut or nil,
	}
end

-- Take what a read produced, cut whole records out of it and pass them on.
--
-- The descriptor is a stream, so a read ends wherever it ends: in the middle
-- of a record as readily as between two. Whatever is left over stays in the
-- buffer for the next one, which is what blob_decode's 'incomplete' means and
-- why that is not an error.
--
-- emit is passed in so this can be tested without a broker.
function syslog.feed(data, emit)
	local ubus = syslog.opts.ubus
	if ubus == nil or type(data) ~= 'string' then
		return 0
	end
	syslog.buf = syslog.buf .. data
	syslog.counters.bytes = syslog.counters.bytes + #data

	local n = 0
	while true do
		local rec, used = ubus.blob_decode(syslog.buf)
		if rec == nil then
			-- 'incomplete' is the ordinary case on a stream; anything
			-- else means the buffer no longer starts on a record and
			-- there is no way back to the boundary from here
			if used ~= 'incomplete' then
				syslog.buf = ''
				syslog.counters.restarts = syslog.counters.restarts + 1
			end
			break
		end
		syslog.buf = syslog.buf:sub(used + 1)
		syslog.counters.records = syslog.counters.records + 1
		n = n + 1

		local want, why = syslog.wanted(rec)
		if why == 'own' then
			syslog.counters.own = syslog.counters.own + 1
		elseif why == 'kernel' and want then
			syslog.counters.kernel = syslog.counters.kernel + 1
		end
		if want then
			syslog.counters.forwarded = syslog.counters.forwarded + 1
			emit(syslog.payload(rec))
		else
			syslog.counters.dropped = syslog.counters.dropped + 1
		end
	end

	return n
end

function syslog.stats()
	local c = {}
	for k, v in pairs(syslog.counters) do c[k] = v end
	c.buffered = #syslog.buf
	c.attached = syslog.fd ~= nil
	return c
end

-- Ask logd for the stream and read it until told to stop.
--
-- lines = 0 on purpose: the backlog is already on the central syslog, and
-- asking for it makes the call answer with data instead of a descriptor —
-- measured, and the callback then never runs, which is a way to hang a daemon
-- that only shows up on a busy access point.
function syslog.start(conn, cjson)
	if not syslog.enabled or syslog.fd ~= nil then
		return false
	end
	local ubus = syslog.opts.ubus
	local uloop = syslog.opts.uloop
	if conn == nil or ubus == nil or uloop == nil then
		return false
	end
	if type(ubus.read_fd) ~= 'function' or type(ubus.blob_decode) ~= 'function' then
		print('syslog: this ubus binding cannot hand out descriptors, not starting')
		return false
	end

	local ok = conn:call_async('log', 'read', { stream = true, lines = 0 },
		function(res, status, fd)
			if type(fd) ~= 'number' or fd < 0 then
				print(string.format('syslog: log read gave no descriptor (status %s)',
					tostring(status)))
				return
			end
			syslog.fd = fd
			syslog.ufd = uloop.fd_add(fd, function()
				syslog.counters.reads = syslog.counters.reads + 1
				local data, why = ubus.read_fd(fd, 8192)
				if data == nil then
					if why == 'eof' then
						print('syslog: logd closed the stream, detaching')
						syslog.stop()
					elseif why ~= 'again' then
						print('syslog: read failed: ' .. tostring(why))
						syslog.stop()
					end
					return
				end
				syslog.feed(data, function(entry)
					syslog.opts.publish(
						syslog.opts.ap_topic('notifications/syslog'),
						cjson.encode(entry), 0, false)
				end)
			end, uloop.ULOOP_READ)
			print('syslog: attached to the log stream on descriptor ' .. tostring(fd))
		end, 10)

	return ok and true or false
end

function syslog.stop()
	local ubus = syslog.opts.ubus
	if syslog.ufd ~= nil then
		pcall(function() syslog.ufd:delete() end)
		syslog.ufd = nil
	end
	if syslog.fd ~= nil then
		if ubus ~= nil and type(ubus.close_fd) == 'function' then
			ubus.close_fd(syslog.fd)
		end
		syslog.fd = nil
	end
	syslog.buf = ''
end

return syslog
