-- The hostapd control channel, as its own module.
--
-- Same reason apman-radius.lua is one: it owns its transport (a unix datagram
-- socket per bss), its own state and its own allowlists, and what it needs
-- from the agent around it is three things — how to build a topic, how to
-- publish, and the pid for naming its reply sockets. Those come in through
-- ctrl.opts, so the module can be exercised without a broker and without ubus,
-- which was impossible while it lived in the middle of apman.lua.
--
-- Config values are set by apman.apply_config through ctrl.configure().

local socket = require('socket')
local parse = require('apman-parse')
local uloop = require('uloop')
local cjson = require('cjson')
local have_unix, unix = pcall(require, "socket.unix")
have_unix = have_unix and type(unix) == 'table' and type(unix.dgram) == 'function'

local ctrl = {}

-- filled by the host: ap_topic(sub) -> topic, publish(topic, payload, qos,
-- retain), pid. Set through ctrl.bind() before anything else runs.
ctrl.opts = { ap_topic = function(s) return s end,
	publish = function() end, pid = 0 }

function ctrl.bind(opts)
	for k, v in pairs(opts) do
		ctrl.opts[k] = v
	end
end

-- whether the unix socket support this needs is present at all
function ctrl.available()
	return have_unix
end

-- everything apman.apply_config knows about this module
function ctrl.configure(cfg)
	ctrl.enabled = cfg.enabled
	ctrl.allow_all = cfg.allow_all
	ctrl.timeout = cfg.timeout
	ctrl.dir = cfg.dir or ctrl.dir
	ctrl.events = cfg.events
	ctrl.event_all = cfg.event_all
	ctrl.mib_interval = cfg.mib_interval
	ctrl.sta_ctrl_interval = cfg.sta_ctrl_interval
	ctrl.sta_ctrl_retry = cfg.sta_ctrl_retry
	-- rebuilt from the built in defaults every time: a verb or event that
	-- was added by a previous config must not survive its removal in uci
	ctrl.event_allow = {}
	for event in pairs(ctrl.event_allow_default) do
		ctrl.event_allow[event] = true
	end
	for _, name in ipairs(cfg.event_allow_add or {}) do
		ctrl.event_allow[string.upper(name)] = true
	end
	for _, name in ipairs(cfg.event_allow_drop or {}) do
		ctrl.event_allow[string.upper(name)] = nil
	end
	ctrl.allowed = {}
	for verb in pairs(ctrl.allowed_default) do
		ctrl.allowed[verb] = true
	end
	for _, verb in ipairs(cfg.allow_add or {}) do
		ctrl.allowed[string.upper(verb)] = true
	end
end

-- hostapd control channel (see ctrl.request)
ctrl.dir = '/var/run/hostapd'
ctrl.enabled = true
ctrl.timeout = 3			-- s to wait for an answer
ctrl.allow_all = false		-- ignore the allowlist below
ctrl.seq = 0
ctrl.stale_cleaned = false
-- Persistent monitors on the control channel (ATTACH), one per bss.
--
-- The ubus notifications cover what a client does — probe, auth, assoc,
-- disassoc — and they arrive parsed. The control channel covers what hostapd
-- itself does, and a few things about clients that ubus loses on the way:
--
--   * AP-STA-CONNECTED carries keyid, vlanid and ip_addr, so a key handed out
--     is recognised at the moment it is used instead of on the next poll
--   * BSS-TM-RESP prints status_code as a number, while the ubus path renders
--     it through blobmsg_add_u8 and libubox turns that into a boolean
--   * why a station was refused (max sta, blocked, wrong key) and how the EAP
--     server answered — neither exists over ubus at all
--
-- Measured on a busy access point: 171 ubus notifications against 4 control
-- channel events in the same four minutes, because probe requests do not come
-- through here. The stream is cheap.
ctrl.events = true
ctrl.monitors = {}		-- ifname -> { sock, path, ufd }
ctrl.event_all = false		-- forward everything, not just the list
ctrl.event_allow = {
	-- stations
	['AP-STA-CONNECTED'] = true, ['AP-STA-DISCONNECTED'] = true,
	['AP-STA-POSSIBLE-PSK-MISMATCH'] = true, ['EAPOL-4WAY-HS-COMPLETED'] = true,
	['AP-REJECTED-MAX-STA'] = true, ['AP-REJECTED-BLOCKED-STA'] = true,
	-- steering, with the status code the ubus path cannot carry
	['BSS-TM-RESP'] = true, ['BSS-TM-QUERY'] = true,
	['MBO-CELL-PREFERENCE'] = true, ['MBO-TRANSITION-REASON'] = true,
	-- the eap server, which has no ubus equivalent
	['CTRL-EVENT-EAP-SUCCESS2'] = true, ['CTRL-EVENT-EAP-FAILURE2'] = true,
	['CTRL-EVENT-EAP-TIMEOUT-FAILURE2'] = true, ['CTRL-EVENT-EAP-RETRANSMIT2'] = true,
	['EAP-ERROR-CODE'] = true,
	-- channel life cycle
	['ACS-STARTED'] = true, ['ACS-COMPLETED'] = true, ['ACS-FAILED'] = true,
	['DFS-CAC-START'] = true, ['DFS-CAC-COMPLETED'] = true,
	['DFS-RADAR-DETECTED'] = true, ['DFS-NEW-CHANNEL'] = true,
	['DFS-NOP-FINISHED'] = true, ['DFS-PRE-CAC-EXPIRED'] = true,
	['AP-CSA-FINISHED'] = true, ['CTRL-EVENT-CHANNEL-SWITCH'] = true,
	['CTRL-EVENT-STARTED-CHANNEL-SWITCH'] = true,
	['CTRL-EVENT-REGDOM-CHANGE'] = true,
	-- bss state
	['AP-ENABLED'] = true, ['AP-DISABLED'] = true,
	['INTERFACE-ENABLED'] = true, ['INTERFACE-DISABLED'] = true,
	-- radio behaviour of a client, which explains sudden slowness
	['STA-OPMODE-MAX-BW-CHANGED'] = true, ['STA-OPMODE-SMPS-MODE-CHANGED'] = true,
	['STA-OPMODE-N_SS-CHANGED'] = true,
	-- measurements and protection
	['RRM-NEIGHBOR-REP-RECEIVED'] = true, ['BEACON-REQ-TX-STATUS'] = true,
	['LINK-MSR-RESP-RX'] = true, ['OCV-FAILURE'] = true,
	['CTRL-EVENT-UNPROT-BEACON'] = true,
	['PMKSA-CACHE-ADDED'] = true, ['PMKSA-CACHE-REMOVED'] = true,
	-- wps enrolment
	['WPS-PBC-ACTIVE'] = true, ['WPS-PIN-NEEDED'] = true, ['WPS-SUCCESS'] = true,
	['WPS-FAIL'] = true, ['WPS-TIMEOUT'] = true, ['WPS-OVERLAP-DETECTED'] = true,
	['WPS-ENROLLEE-SEEN'] = true, ['WPS-REG-SUCCESS'] = true, ['WPS-CANCEL'] = true,
}
-- the built in allowlists; apply_config rebuilds the live tables from these,
-- so removing an entry in uci revokes it in the running agent
ctrl.event_allow_default = ctrl.event_allow
-- BEACON-RESP-RX is deliberately absent: the ubus beacon-report notification
-- delivers the same measurement already decoded.
-- Extra detail pulled from the control channel and folded into the periodic
-- status. Both are cached and refreshed asynchronously, so building a status
-- message never waits for hostapd: what arrives lands in the next message.
--
-- The per station values (which AKM and cipher a client actually negotiated,
-- the key handshake state, its power save behaviour) do not change while the
-- association lasts, so only stations that are new or stale cost a request.
ctrl.mib_interval = 60			-- s per bss, 0 = off
ctrl.sta_ctrl_interval = 300		-- s per station, 0 = off
ctrl.sta_ctrl_retry = 30		-- s, for stations that report no identity yet
ctrl.mib_cache = {}			-- ifname -> { ts, values }
ctrl.sta_ctrl_cache = {}		-- ifname -> mac -> { ts, values }
-- what is kept from a MIB reply; the rest is either constant or noise
ctrl.mib_fields = {
	'dot11RSNA4WayHandshakeFailures', 'dot11RSNATKIPCounterMeasuresInvoked',
	'dot11RSNAAuthenticationSuiteSelected', 'dot11RSNAPairwiseCipherSelected',
	'dot11RSNAGroupCipherSelected', 'hostapdWPAGroupState',
	'radiusAuthServerAddress', 'radiusAuthClientServerPortNumber',
	'radiusAuthClientRoundTripTime', 'radiusAuthClientAccessRequests',
	'radiusAuthClientAccessAccepts', 'radiusAuthClientAccessRejects',
	'radiusAuthClientAccessChallenges', 'radiusAuthClientAccessRetransmissions',
	'radiusAuthClientTimeouts', 'radiusAuthClientMalformedAccessResponses',
	'radiusAuthClientBadAuthenticators', 'radiusAuthClientPendingRequests',
}
-- and from a STA reply
ctrl.sta_ctrl_fields = {
	-- keyid names the entry of the wpa_psk_file a station authenticated with,
	-- which is the only way to tell apart clients that share a wildcard mac
	'keyid',
	-- what the SAE-over-RADIUS patches added: the RADIUS User-Name the station
	-- was admitted under, and the SAE Password Identifier it used. Without
	-- these two the values reach the controller only in AP-STA-CONNECTED, so a
	-- station that was already associated when the subscriber started would
	-- never show either of them.
	'identity', 'sae_password_id',
	-- how the station authenticated, which the client page shows in words:
	-- auth_alg 3 is SAE, AKMSuiteSelector 00-0f-ac-9 is FT-SAE, sae_group 19
	-- is P-256. sae_rejected_groups is normally empty and is worth seeing when
	-- it is not - it names the curves the station refused before settling.
	'auth_alg', 'sae_group', 'sae_rejected_groups',
	'AKMSuiteSelector', 'dot11RSNAStatsSelectedPairwiseCipher',
	'hostapdWPAPTKState', 'hostapdWPAPTKGroupState', 'hostapdMFPR',
	'capability', 'listen_interval', 'supported_rates', 'timeout_next',
	'dot11RSNAStatsTKIPLocalMICFailures', 'dot11RSNAStatsTKIPRemoteMICFailures',
	'wpa', 'ht_caps_info', 'vht_caps_info', 'he_caps_info',
}
-- Commands the controller may send. Everything here either reads state or does
-- something the ubus interface cannot do at all. Deliberately absent:
-- DISASSOCIATE, DEAUTHENTICATE, DENY_ACL/ACCEPT_ACL add/del, RELOAD, DISABLE —
-- they either exist over ubus already or cut clients off, and a command
-- channel without authentication should not offer them by default.
-- 'option ctrl_allow_all 1' lifts this, 'list ctrl_allow <VERB>' extends it.
ctrl.allowed = {
	['STATUS'] = true, ['STATUS-DRIVER'] = true, ['GET_CONFIG'] = true,
	['MIB'] = true, ['STA'] = true, ['STA-FIRST'] = true, ['STA-NEXT'] = true,
	['SIGNATURE'] = true, ['SHOW_NEIGHBOR'] = true, ['GET_CAPABILITY'] = true,
	['DENY_ACL'] = true, ['ACCEPT_ACL'] = true,
	['RELOAD_WPA_PSK'] = true, ['BSS_TM_REQ'] = true,
	-- withdrawing a key needs this: a station that was deauthenticated
	-- comes back through its cached PMKSA without running SAE or the four
	-- way handshake again, and would keep using the key that was just
	-- taken away (measured 2026-08-21, auth_alg=open on an SAE bss)
	['PMKSA_FLUSH'] = true,
	['WPS_PIN'] = true, ['WPS_PBC'] = true, ['WPS_CANCEL'] = true,
	['REQ_BEACON'] = true, ['REQ_LINK_MEASUREMENT'] = true,
}
ctrl.allowed_default = ctrl.allowed

-- The hostapd control channel, proxied.
--
-- hostapd listens on a unix DATAGRAM socket per bss (plus a global one) even
-- though the ubus interface is up — the two are independent and several
-- clients may talk at once, which is how hostapd_cli and wpa_cli coexist. It
-- reaches things ubus does not expose: RELOAD_WPA_PSK (reload the psk file
-- without touching associations), WPS_PIN with an argument, and BSS_TM_REQ
-- whose response event carries the transition status as text instead of the
-- u8 that libubox renders as a boolean.
--
-- Two traps, both found the hard way:
--
--  * hostapd runs inside a ujail as user 'network'. A reply socket in /tmp is
--    invisible to it and the request simply times out. It has to live in
--    ctrl_dir, which the jail has read-write.
--  * a socket bound by root is 0755, so hostapd may not write back. It needs
--    to be world writable before the request goes out.
function ctrl.verb(command)
	local verb = string.match(tostring(command), '^%s*([%w_-]+)')
	return verb and string.upper(verb) or nil
end

function ctrl.permitted(command)
	if ctrl.allow_all then
		return true
	end
	local verb = ctrl.verb(command)
	return verb ~= nil and ctrl.allowed[verb] == true
end

-- ask one bss and call back with the raw answer; never blocks the uloop
function ctrl.request(iface, command, callback)
	if not ctrl.enabled then
		return callback(nil, { code = 8, message = 'control channel proxy disabled' })
	end
	if not have_unix then
		return callback(nil, { code = 8, message = 'luasocket without unix socket support' })
	end
	if type(iface) ~= 'string' or iface == '' or string.find(iface, '[/%s]') ~= nil then
		return callback(nil, { code = 2, message = 'invalid interface name' })
	end
	if type(command) ~= 'string' or command == '' then
		return callback(nil, { code = 2, message = 'command must be a non empty string' })
	end
	if not ctrl.permitted(command) then
		return callback(nil, { code = 6, message = 'command not allowed: ' ..
			tostring(ctrl.verb(command)) })
	end

	local target = ctrl.dir .. '/' .. iface
	ctrl.seq = ctrl.seq + 1
	local path = string.format('%s/apman-%d-%d', ctrl.dir, ctrl.opts.pid or 0, ctrl.seq)

	local sock = unix.dgram()
	if sock == nil then
		return callback(nil, { code = 11, message = 'cannot create socket' })
	end

	local done = false
	local ufd, timer
	local function cleanup()
		if ufd ~= nil then pcall(function() ufd:delete() end) end
		if timer ~= nil then pcall(function() timer:cancel() end) end
		pcall(function() sock:close() end)
		os.remove(path)
	end
	local function finish(reply, err)
		if done then
			return
		end
		done = true
		cleanup()
		callback(reply, err)
	end

	local ok, err = sock:bind(path)
	if not ok then
		cleanup()
		return callback(nil, { code = 13, message = 'bind failed: ' .. tostring(err) })
	end
	-- hostapd is not root, it has to be able to answer
	os.execute("chmod 0777 '" .. path .. "' 2>/dev/null")

	ok, err = sock:connect(target)
	if not ok then
		cleanup()
		return callback(nil, { code = 4, message = 'no control socket for ' .. iface })
	end
	sock:settimeout(0)

	ok, err = sock:send(command)
	if not ok then
		cleanup()
		return callback(nil, { code = 13, message = 'send failed: ' .. tostring(err) })
	end

	ufd = uloop.fd_add(sock, function()
		local reply = sock:receive(65536)
		if reply == nil then
			return		-- spurious wakeup, keep waiting for the deadline
		end
		finish(reply, nil)
	end, uloop.ULOOP_READ)

	timer = uloop.timer(function()
		finish(nil, { code = 7, message = 'no answer from hostapd within ' ..
			ctrl.timeout .. ' s' })
	end, ctrl.timeout * 1000)
end

-- hostapd answers in "key=value" lines, sometimes with a bare first line (the
-- station address in a STA dump). Both forms are handed on: the raw text so
-- nothing is lost, and the parsed pairs so a consumer does not have to.
function ctrl.parse(reply)
	local values, lines = {}, {}
	for line in string.gmatch(reply, '[^\n]+') do
		lines[#lines + 1] = line
		local key, value = string.match(line, '^([^=]+)=(.*)$')
		if key ~= nil then
			values[key] = value
		end
	end

	return { raw = reply, values = values, lines = lines }
end

-- One line of the control channel event stream.
--
--   <3>AP-STA-CONNECTED 00:11:22:33:44:55 auth_alg=open keyid=17-anna vlanid=7
--
-- The number in brackets is the syslog priority, then the event name, then an
-- optional station address and free "key=value" fields.
function ctrl.event_parse(msg)
	local line = string.gsub(msg, '\n+$', '')
	local priority, rest = string.match(line, '^<(%d+)>(.*)$')
	if rest == nil then
		priority, rest = nil, line
	end
	local name, tail = string.match(rest, '^(%S+)%s*(.*)$')
	if name == nil then
		return nil
	end

	local event = {
		event = name,
		priority = priority and tonumber(priority) or nil,
		fields = {},  -- replaced below; kept so an early return still has it
		raw = rest,
		timestamp = socket.gettime(),
	}
	local address = string.match(tail, '^(%x%x:%x%x:%x%x:%x%x:%x%x:%x%x)')
	if address ~= nil then
		event['address'] = string.lower(address)
	end
	-- apman-parse owns the splitting: since the SAE-over-RADIUS patches a
	-- value may be quoted and contain spaces, which the old inline gmatch
	-- could not carry, and a pure function is testable without a device
	event['fields'] = parse.event_fields(tail)

	return event
end

function ctrl.event_wanted(name)
	return ctrl.event_all or ctrl.event_allow[name] == true
end

-- read whatever is queued on a monitor socket and forward it
function ctrl.monitor_read(iface)
	local monitor = ctrl.monitors[iface]
	if monitor == nil then
		return
	end
	for _ = 1, 32 do
		local msg = monitor.sock:receive(8192)
		if msg == nil then
			return
		end
		local event = ctrl.event_parse(msg)
		-- A station that (re)associates may have used a different key than the
		-- one we cached for it, and the cached entry would otherwise stand for
		-- up to sta_ctrl_interval seconds. Dropping it here is what keeps the
		-- reported identity honest: the next status cycle asks hostapd again.
		if event ~= nil and event['address'] ~= nil
				and (event['event'] == 'AP-STA-CONNECTED'
					or event['event'] == 'AP-STA-DISCONNECTED') then
			local cache = ctrl.sta_ctrl_cache[iface]
			if cache ~= nil then
				cache[event['address']] = nil
			end
		end
		if event ~= nil and ctrl.event_wanted(event['event']) then
			event['ifname'] = iface
			ctrl.opts.publish(
				ctrl.opts.ap_topic('notifications/hostapd/' .. iface .. '/ctrl/' .. event['event']),
				cjson.encode(event))
		end
	end
end

-- Sockets of an earlier run of this agent. The file name carries the pid, so a
-- restart leaves one orphan per bss behind — harmless, but they pile up in the
-- directory hostapd uses and it keeps sending to them until the writes fail.
function ctrl.cleanup_stale()
	if ctrl.opts.pid == nil then
		return
	end
	os.execute(string.format(
		"for f in %s/apman-*; do case \"$f\" in *-%d-*) ;; *) rm -f \"$f\";; esac; done 2>/dev/null",
		ctrl.dir, ctrl.opts.pid))
end

-- attach to one bss; the reply socket has to live where the ujail can write
function ctrl.monitor_attach(iface)
	if ctrl.monitors[iface] ~= nil then
		return true
	end
	if not ctrl.events or not ctrl.enabled or not have_unix then
		return false
	end

	local path = string.format('%s/apman-mon-%d-%s', ctrl.dir, ctrl.opts.pid or 0, iface)
	os.remove(path)
	local sock = unix.dgram()
	if sock == nil then
		return false
	end
	local ok = sock:bind(path)
	if not ok then
		pcall(function() sock:close() end)
		return false
	end
	os.execute("chmod 0777 '" .. path .. "' 2>/dev/null")
	if not sock:connect(ctrl.dir .. '/' .. iface) then
		pcall(function() sock:close() end)
		os.remove(path)
		return false
	end
	sock:settimeout(0)
	if not sock:send('ATTACH') then
		pcall(function() sock:close() end)
		os.remove(path)
		return false
	end

	ctrl.monitors[iface] = { sock = sock, path = path }
	ctrl.monitors[iface].ufd = uloop.fd_add(sock, function()
		ctrl.monitor_read(iface)
	end, uloop.ULOOP_READ)
	print(string.format('Attached to the control channel of %s', iface))

	return true
end

function ctrl.monitor_drop(iface)
	local monitor = ctrl.monitors[iface]
	if monitor == nil then
		return
	end
	ctrl.monitors[iface] = nil
	if monitor.ufd ~= nil then
		pcall(function() monitor.ufd:delete() end)
	end
	-- DETACH is a courtesy: hostapd drops a monitor that stops answering
	pcall(function() monitor.sock:send('DETACH') end)
	pcall(function() monitor.sock:close() end)
	os.remove(monitor.path)
	print(string.format('Detached from the control channel of %s', iface))
end

-- let go of every bss and take the reply sockets with us.
--
-- procd sends SIGTERM on stop and lua ends there, so without this the sockets
-- of the dying process stay in ctrl_dir until the next start sweeps them up in
-- ctrl_cleanup_stale(). They do not pile up across restarts, but they do
-- outlive the service, and hostapd is left holding a monitor that will never
-- answer again instead of being told we are going.
function ctrl.shutdown()
	for iface in pairs(ctrl.monitors) do
		ctrl.monitor_drop(iface)
	end
end

-- Deliberately no signal handler here.
--
-- uloop.signal(callback, signum) does register on this build and returns a
-- handle, but the callback is never invoked — and registering it stops the
-- default action too, so a process with a "handler" survives SIGTERM instead
-- of dying. Measured: a test that registers for SIGTERM, gets sent SIGTERM,
-- and runs on to its own timeout. Using it would leave an agent that cannot be
-- stopped, which is a great deal worse than a few socket files.
--
-- So the sockets are removed by the init script when the service stops, and
-- ctrl_cleanup_stale() sweeps whatever survived that on the next start.

-- called whenever the bss list changed: attach to what is new, let go of what
-- disappeared. hostapd forgets its monitors when it restarts, and the same
-- bss.reload notification that triggers the ubus resubscribe brings us here.
function ctrl.monitor_sync(wanted)
	if not ctrl.stale_cleaned then
		ctrl.stale_cleaned = true
		ctrl.cleanup_stale()
	end
	if not ctrl.events then
		for iface in pairs(ctrl.monitors) do
			ctrl.monitor_drop(iface)
		end
		return
	end
	for iface in pairs(ctrl.monitors) do
		if wanted[iface] ~= true then
			ctrl.monitor_drop(iface)
		end
	end
	for iface in pairs(wanted) do
		ctrl.monitor_attach(iface)
	end
end

-- keep only the interesting keys of a control channel answer
function ctrl.pick(values, fields)
	local out, found = {}, false
	for _, key in ipairs(fields) do
		if values[key] ~= nil then
			out[key] = values[key]
			found = true
		end
	end
	if not found then
		return nil
	end

	return out
end

-- refresh the cached MIB of a bss if it aged out; the answer lands in the
-- cache and is published with the next status message
function ctrl.refresh_mib(ifname)
	if ctrl.mib_interval <= 0 or not ctrl.enabled or not have_unix then
		return
	end
	local now = socket.gettime()
	local entry = ctrl.mib_cache[ifname]
	if entry ~= nil and (now - entry.ts) < ctrl.mib_interval then
		return
	end
	-- mark first, so a slow hostapd does not collect a queue of requests
	ctrl.mib_cache[ifname] = { ts = now, values = entry and entry.values or nil }
	ctrl.request(ifname, 'MIB', function(reply, err)
		if err ~= nil then
			return
		end
		local parsed = ctrl.parse(reply)
		ctrl.mib_cache[ifname] = {
			ts = socket.gettime(),
			values = ctrl.pick(parsed.values, ctrl.mib_fields),
		}
	end)
end

-- same for the per station detail, but only for stations we do not know yet
function ctrl.refresh_sta_ctrl(ifname, macs)
	if ctrl.sta_ctrl_interval <= 0 or not ctrl.enabled or not have_unix then
		return
	end
	local now = socket.gettime()
	local cache = ctrl.sta_ctrl_cache[ifname]
	if cache == nil then
		cache = {}
		ctrl.sta_ctrl_cache[ifname] = cache
	end

	local present = {}
	for _, mac in ipairs(macs) do
		local key = string.lower(mac)
		present[key] = true
		local entry = cache[key]
		-- A station that has no identity yet is asked again far more often:
		-- hostapd only assigns the keyid at authentication time, so a client
		-- that just (re)joined would otherwise stay anonymous for a whole
		-- interval — which is exactly the moment somebody is watching to see
		-- whether a key they handed out works.
		local interval = ctrl.sta_ctrl_interval
		if entry ~= nil and (entry.values == nil or entry.values['keyid'] == nil) then
			interval = math.min(interval, ctrl.sta_ctrl_retry)
		end
		if entry == nil or (now - entry.ts) >= interval then
			cache[key] = { ts = now, values = entry and entry.values or nil }
			ctrl.request(ifname, 'STA ' .. key, function(reply, err)
				if err ~= nil then
					return
				end
				local parsed = ctrl.parse(reply)
				cache[key] = {
					ts = socket.gettime(),
					values = ctrl.pick(parsed.values, ctrl.sta_ctrl_fields),
				}
			end)
		end
	end
	-- a station that left must not linger in the next status message
	for key in pairs(cache) do
		if not present[key] then
			cache[key] = nil
		end
	end
end

-- the cached values as they go into the status payload
function ctrl.sta_ctrl_values(ifname)
	local cache = ctrl.sta_ctrl_cache[ifname]
	if cache == nil then
		return nil
	end
	local out, found = {}, false
	for mac, entry in pairs(cache) do
		if entry.values ~= nil then
			out[mac] = entry.values
			found = true
		end
	end

	return found and out or nil
end


return ctrl
