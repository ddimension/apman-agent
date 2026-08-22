#!/usr/bin/env lua

--[[
  A demo of ubus subscriber binding. Should be run after publisher.lua
--]]

require "ubus"
require "uloop"
local cjson = require "cjson"
local socket = require("socket")
local mqtt = require("mosquitto")
-- luasocket ships socket/unix.so in OpenWrt, but a build without it would only
-- fail once a control channel request is made — so check for the datagram
-- constructor here and let the feature report itself as unavailable instead
local have_unix, unix = pcall(require, "socket.unix")
have_unix = have_unix and type(unix) == 'table' and type(unix.dgram) == 'function'
-- the optional minimal radius server (apman-radius.lua) answering hostapd
-- wpa_psk_radius / sae psk mac queries; the feature reports itself absent
-- when the module is not installed
local apman_parse = require('apman-parse')
local have_ctrl, apman_ctrl = pcall(require, 'apman-ctrl')
have_ctrl = have_ctrl and type(apman_ctrl) == 'table'
local have_radius, apman_radius = pcall(require, 'apman-radius')
have_radius = have_radius and type(apman_radius) == 'table'

local apman = {}
apman.version = '60-1'			-- set by contrib/release.sh, do not edit
apman.started_at = nil
apman.conn = nil
apman.hostname = nil
apman.config = {}
apman.mqtt_hostname = 'app1.kalnet.hooya.de'
apman.topic_prefix = 'apman/'
apman.client = nil
apman.count = 0
apman.timers = {}
apman.ubus_session = {}

-- runtime defaults, overridable from uci (see apman.apply_config)
apman.status_interval = 10000		-- ms between full status publishes
apman.ubus_check_interval = 1000	-- ms between hostapd object list checks
apman.ubus_settle = 5000		-- ms to wait before resubscribing ubus
apman.mqtt_loop_interval = 200		-- ms between mosquitto loop ticks
apman.mqtt_retry_min = 2		-- s, first reconnect backoff step
apman.mqtt_retry_max = 120		-- s, backoff ceiling
apman.station_dump = true		-- publish raw 'iw station dump' text
apman.command_topic_global = true	-- subscribe the fleet-wide command topic
apman.ubus_check_interval_slow = 30000	-- ms, used once hostapd bss.* events work
apman.hostapd_status = true		-- publish the global hostapd status object
-- extra ubus objects whose notifications are forwarded, and ubus broadcast
-- events that are forwarded. Both are additive, they use their own topics.
apman.subscribe_objects = { 'network.interface', 'network.device' }
apman.listen_events = { 'network.interface' }
apman.have_bss_events = false
-- resend suppression: a payload that did not change is republished only after
-- max_age seconds, so a consumer that lost its state still resyncs
apman.property_republish = 300		-- s, retained properties
apman.wireless_republish = 60		-- s, wireless status
apman.probe_interval = 10		-- s per station, 0 = forward every probe
apman.log_payload_len = 200		-- chars of a payload to log, 0 = full
apman.survey_interval = 300		-- s between channel surveys, 0 = off
apman.survey_last = 0

-- minimal radius server answering hostapd wpa_psk_radius / sae psk queries
-- (see apman-radius.lua); started from apman.init when enabled. The keys are
-- the wifi-station sections of the wireless config, reloaded on hostapd-auth
-- notifications and checked by a digest timer as a safety net
apman.radius_enabled = false
apman.radius_port = 1812
apman.radius_secret = ''
apman.radius_wifi_config = '/etc/config/wireless'
apman.radius_reload_interval = 10	-- s between config change checks, 0 = off
apman.radius_active = false
apman.radius_server = nil
apman.radius_bss_vlans = {}		-- bssid -> the vlan the bss lives on
apman.radius_bss_ifaces = {}		-- bssid -> uci wifi-iface section name
apman.radius_bss_digest = nil		-- gate for the bss map watchdog in radius_reload
apman.radius_bss_ticks = 0		-- full map refreshes every 30 ticks (5 min)
apman.config_digest = nil		-- /etc/config/apman content the watch saw last

-- ubus status codes, so a consumer gets a reason instead of a bare null
apman.ubus_status_text = {
	[0] = 'ok', [1] = 'invalid command', [2] = 'invalid argument',
	[3] = 'method not found', [4] = 'not found', [5] = 'no data',
	[6] = 'permission denied', [7] = 'timeout', [8] = 'not supported',
	[9] = 'unknown error', [10] = 'connection failed', [11] = 'no memory',
	[12] = 'parse error', [13] = 'system error',
}
apman.published = {}			-- topic -> { payload, ts }
apman.probe_seen = {}			-- object/address -> ts
apman.probe_count = 0

-- mqtt connection state (never block the uloop, see apman.mqttCallback)
apman.mqtt_connected = false
apman.mqtt_started = false
apman.mqtt_backoff = 0
apman.mqtt_next_attempt = 0
apman.mqtt_attempts = 0
apman.ubus_subscribed = false
apman.ubus_resubscribe = nil

function apman.starts_with(str, start)
	return str:sub(1, #start) == start
end

-- uci leaves unset options as empty strings, treat those as absent
function apman.cfg(name, default)
	local value = apman.config[name]
	if value == nil or value == '' then
		return default
	end
	return value
end

function apman.cfg_num(name, default)
	local value = tonumber(apman.cfg(name, false))
	if value == nil then
		return default
	end
	return value
end

-- uci lists arrive as a table, a single option as a string
function apman.cfg_list(name, default)
	local value = apman.config[name]
	if type(value) == 'table' then
		return value
	end
	if type(value) == 'string' and value ~= '' then
		return { value }
	end
	return default
end

-- equality key for cfg_list values, so a config change can be told from the
-- running values
function apman.list_key(list)
	local parts = {}
	for i, value in ipairs(list) do
		parts[#parts + 1] = tostring(value)
	end
	table.sort(parts)
	return table.concat(parts, '|')
end

function apman.cfg_bool(name, default)
	local value = apman.cfg(name, nil)
	if value == nil then
		return default
	end
	return value == '1' or value == 'true' or value == 'yes' or value == 'on'
end

-- command payloads are several kB each and used to be logged in full on every
-- call, which dominated the syslog on a busy ap
function apman.trunc(str)
	if type(str) ~= 'string' then
		str = tostring(str)
	end
	if apman.log_payload_len <= 0 or #str <= apman.log_payload_len then
		return str
	end
	return string.sub(str, 1, apman.log_payload_len) .. string.format('...(%d bytes)', #str)
end

function apman.ap_topic(suffix)
	return apman.topic_prefix .. 'ap/' .. apman.hostname .. '/' .. suffix
end

function apman.getOutput(cmd)
	local f = io.popen (cmd)
	local output = f:read("*a") or ""
	f:close()
	return output
end

-- probe requests are by far the highest volume notification and carry no state,
-- so only one per station and probe_interval is forwarded
function apman.probe_throttled(object, msg)
	if apman.probe_interval <= 0 or type(msg) ~= 'table' or msg['address'] == nil then
		return false
	end

	local now = socket.gettime()
	local key = object .. '/' .. msg['address']
	local last = apman.probe_seen[key]
	if last ~= nil and (now - last) < apman.probe_interval then
		return true
	end
	apman.probe_seen[key] = now

	apman.probe_count = apman.probe_count + 1
	if apman.probe_count > 500 then
		apman.probe_count = 0
		local cutoff = now - (apman.probe_interval * 4)
		for k, ts in pairs(apman.probe_seen) do
			if ts < cutoff then
				apman.probe_seen[k] = nil
			end
		end
	end
	return false
end

function apman.createUbusCallback(object, topic)
	return {
		notify = function( msg, method )
			local ltopic = topic .. '/' .. method
			if method == 'probe' and apman.probe_throttled(object, msg) then
				return
			end
			if type(msg) == 'table' then
				msg['timestamp'] = socket.gettime()
			end
			apman.publish_mqtt( ltopic, cjson.encode(msg))
			--print(string.format("Published from object '%s' to mqtt topic '%s', payload: %s", object, ltopic, cjson.encode(msg)))
			-- the ucode based hostapd announces bss changes on its global
			-- object, no need to poll the object list for them
			if object == 'hostapd' and apman.starts_with(method, 'bss.') then
				apman.schedule_resubscribe(method)
			end
		end
	}
end

-- forwards a ubus broadcast event (ubus listen) to its own mqtt topic
function apman.createEventCallback(event)
	local topic = apman.ap_topic('events/' .. event:gsub('%.', '/'))
	return function(msg)
		if type(msg) ~= 'table' then
			msg = { ['message'] = msg }
		end
		msg['event'] = event
		msg['timestamp'] = socket.gettime()
		apman.publish_mqtt(topic, cjson.encode(msg))
	end
end

function apman.schedule_resubscribe(reason)
	if apman.ubus_resubscribe ~= nil then
		return
	end
	print(string.format("hostapd reported '%s', resubscribing in %ds.", tostring(reason), apman.ubus_settle / 1000))
	apman.ubus_resubscribe = 1
	apman.timers['ubus_check']:set(apman.ubus_settle)
end

-- drives the mosquitto client and owns the (non blocking) reconnect schedule
function apman.mqttCallback()
	if apman.mqtt_started then
		apman.client:loop(0)
	end
	if not apman.mqtt_connected and socket.gettime() >= apman.mqtt_next_attempt then
		apman.connect_mqtt()
	end
	apman.timers['mqtt']:set(apman.mqtt_loop_interval)
end

function apman.ubusCheckCallback()
	local c2 = 0
	-- the connection can be gone right after boot; the poll must stay armed
	-- or the whole resubscribe machinery dies quietly
	local objects = apman.conn and apman.conn:objects()
	if not objects then
		apman.timers['ubus_check']:set(apman.ubus_check_interval)
		return
	end
	for key, object in pairs(objects) do
		if apman.starts_with(object, "hostapd") then
			c2 = c2 + 1
		end
	end
	if apman.ubus_resubscribe ~= nil then
		-- the settle delay has passed, pick up the new object list
		apman.ubus_resubscribe = nil
		print('Restarting ubus connection and subscriptions.')
		if apman.reconnect_ubus() then
			apman.subscribeCallback()
		else
			print('ubus reconnect failed, keeping the poll armed.')
			apman.timers['ubus_check']:set(apman.ubus_check_interval)
			return
		end
	elseif apman.count ~= c2 then
		print(string.format('Ubus object list changed, waiting %ds before resubscribing.', apman.ubus_settle / 1000))
		apman.ubus_resubscribe = 1
		apman.timers['ubus_check']:set(apman.ubus_settle)
		return
	end
	-- with bss.* notifications this poll is only a safety net
	if apman.have_bss_events then
		apman.timers['ubus_check']:set(apman.ubus_check_interval_slow)
	else
		apman.timers['ubus_check']:set(apman.ubus_check_interval)
	end
end

-- merge the assoclist of 'device' into 'target', tagging every entry with the
-- interface it was seen on (VLAN slaves report their own device)
function apman.merge_assoclist(target, device)
	local list = apman.conn:call("iwinfo", "assoclist", { device = device })
	if type(list) ~= 'table' or type(list['results']) ~= 'table' then
		return target
	end
	for key, entry in pairs(list['results']) do
		if type(entry) == 'table' then
			entry['device'] = device
		end
	end
	if type(target) ~= 'table' or type(target['results']) ~= 'table' then
		return list
	end
	for key, entry in pairs(list['results']) do
		table.insert(target['results'], entry)
	end
	return target
end

-- one 'iw' invocation for all devices instead of one per device: the station
-- dump tags every station with '(on <dev>)', so a single combined run can be
-- split up again afterwards
function apman.collect_station_dumps(devlist)
	local dumps = {}
	local cmd = {}

	for key, device in pairs(devlist) do
		dumps[device] = {}
		table.insert(cmd, "iw dev " .. device .. " station dump")
	end
	if #cmd == 0 then
		return dumps
	end

	local output = apman.getOutput(table.concat(cmd, "; "))
	local pos, len, current = 1, #output, nil
	while pos <= len do
		local line
		local nl = string.find(output, "\n", pos, true)
		if nl then
			line = string.sub(output, pos, nl - 1)
			pos = nl + 1
		else
			line = string.sub(output, pos)
			pos = len + 1
		end
		local device = string.match(line, "^Station %S+ %(on (%S+)%)")
		if device ~= nil then
			current = device
			if dumps[current] == nil then
				dumps[current] = {}
			end
		end
		if current ~= nil then
			table.insert(dumps[current], line)
		end
	end

	local result = {}
	for device, lines in pairs(dumps) do
		if #lines > 0 then
			result[device] = table.concat(lines, "\n") .. "\n"
		else
			result[device] = ""
		end
	end
	return result
end

-- timer entry: the cycle below runs in a pcall, so a hiccup in one ubus
-- answer (or a connection that died mid-call) cannot take the whole agent
-- down, and a cycle that runs longer than the interval is logged instead of
-- silently pushing the publishes apart. The calls themselves stay
-- synchronous — the ubus lua binding has no async call — so a slow hostapd
-- does delay the other uloop work (mqtt, radius, control channel) until the
-- cycle ends; the log line is how that becomes visible.
function apman.statusCallback()
	local t0 = socket.gettime()
	local ok, err = pcall(apman.status_cycle)
	if not ok then
		print(string.format('status cycle failed: %s', tostring(err)))
	end
	local took = socket.gettime() - t0
	if took > apman.status_interval / 1000 then
		print(string.format('status cycle took %.1fs, longer than the %ds interval.',
			took, apman.status_interval / 1000))
	end
	apman.timers['status']:set(apman.status_interval)
end

-- the synchronous collection itself, unchanged in behaviour; the guard and
-- the timing log live in the wrapper above
function apman.status_cycle()
	local topic, data
	local devices = apman.conn:call("iwinfo", "devices", {})
	data = {}
	data['devices'] = {}
	local iwinfo = {}
	local slaves = {}
	local masters = {}
	local dumpdevs = {}
	local hostapd_status = nil

	-- global hostapd object (ucode based hostapd): authoritative bss/radio
	-- topology including mld links. Published as its own topic and mirrored
	-- into every device payload, the existing keys stay untouched.
	if apman.hostapd_status then
		hostapd_status = apman.conn:call("hostapd", "status", {})
		if type(hostapd_status) == 'table' then
			hostapd_status['timestamp'] = socket.gettime()
			apman.publish_mqtt(apman.ap_topic('hostapd/status'), cjson.encode(hostapd_status))
		end
	end

	-- a bss can disappear between the two calls — hostapd tearing an
	-- interface down leaves it in the device list while info already
	-- answers nil — and an unchecked index there kills the whole agent
	local devlist = {}
	if type(devices) == 'table' and type(devices['devices']) == 'table' then
		devlist = devices['devices']
	end

	for key, value in pairs(devlist) do
		local info = apman.conn:call("iwinfo", "info", { device = value })
		if type(info) == 'table' then
			iwinfo[value] = info
			local is_master = 1
			if info['mode'] ~= nil and info['mode'] == 'Master (VLAN)' then
				-- vlan slave devices are named <master>.<vid> (e.g. phy0-ap0.7
				-- under phy0-ap0), so a match needs the dot separator and the
				-- longest matching master wins: sibling prefixes (ap1 / ap10)
				-- cannot claim each other's slaves, and the assignment no
				-- longer depends on the pairs() order of devlist
				local master = nil
				for k2, v2 in pairs(devlist) do
					if value ~= v2 and value:sub(1, #v2 + 1) == v2 .. '.' then
						if master == nil or #v2 > #master then
							master = v2
						end
					end
				end
				if master ~= nil then
					is_master = 0
					if slaves[master] == nil then
						slaves[master] = {}
					end
					table.insert(slaves[master], value)
					--print('added slave '..value..' to master '..master)
				end
			end
			if is_master then
				--print('Add master '..value)
				table.insert(masters, value)
			end
		end
	end

	for key, value in pairs(masters) do
		data['devices'][value] = {}
		data['devices'][value]['timestamp'] = socket.gettime()
		data['devices'][value]['info'] = iwinfo[value]
		data['devices'][value]['clients'] = apman.conn:call("hostapd."..value, "get_clients", {})
		data['devices'][value]['assoclist'] = apman.merge_assoclist(nil, value)
		if slaves[value] ~= nil then
			for k2, subdevice in pairs(slaves[value]) do
				--print('queried slave '..subdevice)
				data['devices'][value]['assoclist'] = apman.merge_assoclist(data['devices'][value]['assoclist'], subdevice)
			end
		end
		data['devices'][value]['status'] = apman.conn:call("network.device", "status", { name = value })
		data['devices'][value]['ap_status'] = apman.conn:call("hostapd."..value, "get_status", {})
		if type(hostapd_status) == 'table' and type(hostapd_status['interfaces']) == 'table' then
			data['devices'][value]['hostapd_status'] = hostapd_status['interfaces'][value]
		end
		-- dump every interface, not only those with entries in the assoclist:
		-- p2p/mesh peers never show up there
		if apman.station_dump then
			table.insert(dumpdevs, value)
			if slaves[value] ~= nil then
				for k2, subdevice in pairs(slaves[value]) do
					table.insert(dumpdevs, subdevice)
				end
			end
		end
	end

	local dumps = {}
	if apman.station_dump then
		dumps = apman.collect_station_dumps(dumpdevs)
	end

	apman.publish_survey(masters)

	for key, value in pairs(masters) do
		data['devices'][value]['v'] = 2
		if apman.station_dump then
			local stations = dumps[value] or ""
			if slaves[value] ~= nil then
				for k2, subdevice in pairs(slaves[value]) do
					stations = stations .. "\n" .. (dumps[subdevice] or "")
				end
			end
			data['devices'][value]['stations'] = apman_parse.station_dump(stations)
		end

		-- control channel detail: what is cached goes out now, what aged out
		-- is fetched asynchronously and is in the next message
		local macs = {}
		local assoclist = data['devices'][value]['assoclist']
		if type(assoclist) == 'table' and type(assoclist['results']) == 'table' then
			for _, entry in ipairs(assoclist['results']) do
				if type(entry) == 'table' and entry['mac'] ~= nil then
					macs[#macs + 1] = entry['mac']
				end
			end
		end
		apman_ctrl.refresh_mib(value)
		apman_ctrl.refresh_sta_ctrl(value, macs)
		local mib = apman_ctrl.mib_cache[value]
		if mib ~= nil and mib.values ~= nil then
			data['devices'][value]['mib'] = mib.values
		end
		data['devices'][value]['sta_ctrl'] = apman_ctrl.sta_ctrl_values(value)

		topic = apman.ap_topic('device/hostapd/' .. value .. '/status')
		apman.publish_mqtt( topic , cjson.encode(data['devices'][value]))
		--print("Published data to mqtt topic '"..topic.."'.")
	end

        topic = apman.ap_topic('online')
	apman.publish_mqtt(topic, cjson.encode({['status'] = 'online', ["timestamp"] = socket.gettime()}))

	data = apman.conn:call("system", "info", {})
	if type(data) == 'table' then
		data['timestamp'] = socket.gettime()
	end
	topic = apman.ap_topic('properties/system/info')
	apman.publish_mqtt( topic , cjson.encode(data))

	-- by far the largest single payload and almost always identical: publish
	-- it on change, plus a periodic refresh so a consumer can resync
	data = apman.conn:call("network.wireless", "status", {})
	topic = apman.ap_topic('wireless/status')
	if type(data) == 'table' then
		local unchanged = cjson.encode(data)
		local last = apman.published[topic]
		if last == nil or last.payload ~= unchanged
		   or (socket.gettime() - last.ts) >= apman.wireless_republish then
			data['timestamp'] = socket.gettime()
			if apman.publish_mqtt( topic , cjson.encode(data)) ~= nil then
				apman.published[topic] = { payload = unchanged, ts = socket.gettime() }
			end
		end
	else
		apman.publish_mqtt( topic , cjson.encode(data))
	end

end

-- reconnect from the ubus poll timer: a transient ubus failure must not kill
-- the agent (an error inside a uloop callback ends uloop.run), so the result
-- is handed back and the caller keeps the poll armed instead. The fatal
-- variant stays at the explicit call sites (init, collectd) where dying is
-- the right answer.
function apman.reconnect_ubus()
	if apman.conn ~= nil then
		apman.conn:close()
	end
	apman.connect_ubus()
	return apman.conn ~= nil
end

function apman.connect_ubus()
	apman.conn = ubus.connect()
end

function apman.mqtt_log(level, message)
	-- print('mosquitto ' .. level .. ':' .. message)
end

-- registers the configured ubus broadcast events; has to be redone after every
-- ubus reconnect, the handlers die with the connection
function apman.listen_ubus()
	local handlers = {}
	local count = 0

	for key, event in pairs(apman.listen_events) do
		handlers[event] = apman.createEventCallback(event)
		count = count + 1
	end
	if count < 1 then
		return
	end

	local ok, err = pcall(function()
		apman.conn:listen(handlers)
	end)
	if ok then
		for event in pairs(handlers) do
			print(string.format("Listening for ubus event '%s'.", event))
		end
	else
		print(string.format("Failed to listen for ubus events: %s", tostring(err)))
	end
end

-- retries the subscription until hostapd shows up on ubus, driven by a timer
-- instead of a sleep loop so mqtt and the status publishes keep running
function apman.subscribeCallback()
	if not apman.subscribe_ubus() then
		apman.timers['subscribe']:set(1000)
	end
end

-- one pass over the ubus object list; returns false while no hostapd object
-- is present yet
function apman.subscribe_ubus()
	local topic, devices, data
	-- gone right after boot; the caller retries a second later
	local objects = apman.conn and apman.conn:objects()
	if not objects then
		return false
	end
	local available = {}

	apman.count = 0
	for key, object in pairs(objects) do
		available[object] = true
		if apman.starts_with(object, "hostapd") then
			-- the topic segment is the object name with the hostapd. (or
			-- hostapd-) prefix stripped, as documented in
			-- docs/controller-api.md: hostapd.wlan0 -> wlan0,
			-- hostapd-auth -> auth, the bare hostapd stays hostapd
			local topic = apman.ap_topic('notifications/hostapd/' .. object:gsub('^hostapd[%.%-]', ''))
			print(string.format("Adding subscription for object '%s', assigning to topic '%s'.", object, topic))
			apman.conn:subscribe(object, apman.createUbusCallback(object, topic))
			apman.count = apman.count + 1
		end
	end
	if apman.count < 1 then
		return false
	end
	-- the same list drives the control channel monitors; hostapd loses them on
	-- every restart, and this runs again on bss.add/bss.remove/bss.reload
	local monitored = {}
	for object in pairs(available) do
		if apman.starts_with(object, 'hostapd.') then
			monitored[object:gsub('^hostapd%.', '')] = true
		end
	end
	apman_ctrl.monitor_sync(monitored)
	-- the global 'hostapd' object only exists with the ucode based hostapd;
	-- its bss.add/bss.remove/bss.reload notifications replace the poll
	apman.have_bss_events = available['hostapd'] == true

	-- hostapd-auth announces every applied wifi config (config_set ->
	-- reload). The radius keys come from the wifi-station sections of that
	-- config, so re-read them on the spot instead of waiting for the digest
	-- timer. This is a second subscription to the same object, on top of the
	-- generic one above: the binding registers a separate subscriber per call
	-- (ubus.c: ubus_register_subscriber), so both callbacks fire — the
	-- generic one keeps forwarding sta_auth/sta_connected under
	-- notifications/hostapd/auth/, this one only acts on reload.
	if available['hostapd-auth'] and apman.radius_active then
		local ok, err = pcall(function()
			apman.conn:subscribe('hostapd-auth', {
				notify = function(msg, method)
					if method == 'reload' then
						apman.radius_reload()
					end
				end
			})
		end)
		if ok then
			print('Subscribing to hostapd-auth for radius key reloads.')
		else
			print(string.format('Failed to subscribe hostapd-auth: %s', tostring(err)))
		end
	end

	-- additional objects (netifd and friends), published below their own
	-- topic so nothing that exists today changes
	for key, object in pairs(apman.subscribe_objects) do
		if available[object] then
			local topic = apman.ap_topic('notifications/' .. object:gsub('%.', '/'))
			local ok, err = pcall(function()
				apman.conn:subscribe(object, apman.createUbusCallback(object, topic))
			end)
			if ok then
				print(string.format("Adding subscription for object '%s', assigning to topic '%s'.", object, topic))
			else
				print(string.format("Failed to subscribe object '%s': %s", object, tostring(err)))
			end
		else
			print(string.format("Skipping subscription for absent object '%s'.", object))
		end
	end

	apman.listen_ubus()

	-- add rrm information; a bss can disappear between the object list and
	-- these calls, and an unchecked index kills the whole agent (the same
	-- guard statusCallback uses)
	local devlist = {}
	local devices = apman.conn:call("iwinfo", "devices", {})
	if type(devices) == 'table' and type(devices['devices']) == 'table' then
		devlist = devices['devices']
	end
	for key, value in pairs(devlist) do
		local rrm = apman.conn:call("hostapd."..value, "rrm_nr_get_own", {})
		if type(rrm) == 'table' then
			topic = apman.ap_topic('properties/hostapd/' .. value .. '/rrm_nr_get_own')
			-- resubscribes happen often, the neighbour report almost never
			-- changes: do not republish it every time
			apman.publish_property( topic , cjson.encode(rrm), 1, true, apman.property_republish)
		end
		-- static bss configuration (ssid, encryption, hw mode), ucode
		-- based hostapd only
		if available['hostapd'] then
			local info = apman.conn:call("hostapd", "bss_info", { iface = value })
			if type(info) == 'table' then
				topic = apman.ap_topic('properties/hostapd/' .. value .. '/bss_info')
				apman.publish_property( topic , cjson.encode(info), 1, true, apman.property_republish)
			end
		end
	end
	-- send session
	data = apman.get_rpc_session_ubus()
	if type(data) == 'table' then
		data['timestamp'] = socket.gettime()
	end
	topic = apman.ap_topic('properties/session/create')
	apman.publish_mqtt( topic , cjson.encode(data))
	apman.publish_agent()
	apman.publish_radius()
	-- this also runs after every bss.* change (wifi reloads, hostapd
	-- restarts): the radius store picks up whatever the config change was
	-- about, the digest guard keeps the common no-op cheap
	apman.radius_reload()
	return true
end

function apman.get_rpc_session_ubus()
	local topic, session, opts
	if not apman.conn then
		return nil
	end
	session = apman.conn:call("session", "create", { timeout = 0 })
	if type(session) ~= 'table' or session['ubus_rpc_session'] == nil then
		-- the caller drops a nil answer; indexing a half answer must not
		-- take the agent down at boot
		print("Result of session create: not usable")
		return nil
	end

	-- rpcd expects each entry as an array [object, function] and silently
	-- skips anything else, so a map here granted nothing at all
	opts = { scope = 'file',  objects = {}, ubus_rpc_session = session['ubus_rpc_session']}
	table.insert(opts['objects'], {'/*', 'read'})
	table.insert(opts['objects'], {'/*', 'write'})
	table.insert(opts['objects'], {'/*', 'exec'})
	local result, status = apman.conn:call("session", "grant", opts)
	if status ~= nil and status ~= 0 then
		print(string.format("Result of session grant (file scope): failed (%s)", tostring(status)))
	end

	-- rpcd checks uci access in its own scope, not in 'file'. Without this the
	-- session can read and write files but every uci call comes back as
	-- permission denied, which also rules out the rollback safe
	-- uci apply/confirm that needs a session.
	opts = { scope = 'uci', objects = {}, ubus_rpc_session = session['ubus_rpc_session']}
	table.insert(opts['objects'], {'*', 'read'})
	table.insert(opts['objects'], {'*', 'write'})
	result, status = apman.conn:call("session", "grant", opts)
	if status ~= nil and status ~= 0 then
		print(string.format("Result of session grant (uci scope): failed (%s)", tostring(status)))
	end

	-- The session id itself is a root-equivalent bearer token — the grants
	-- above are full file and uci access — and is deliberately not logged:
	-- syslog is forwarded off the device in most deployments. It is
	-- published on properties/session/create, which is the documented
	-- handover to the controller; the broker is the security boundary.
	apman.session = session
	return session
end

-- builds the client (credentials, tls, last will). Does not connect: the
-- connection itself is driven by apman.mqttCallback / apman.connect_mqtt.
function apman.setup_mqtt()
	local topic
	local mqtt_host, mqtt_port, mqtt_keepalive, mqtt_clientid

	-- mqtt setup
	if apman.config['mqtt_clientid'] then
		apman.client = mqtt.new(apman.config['mqtt_clientid'], false)
	else
		apman.client = mqtt.new(apman.hostname, false)
	end
	-- assign MQTT client event handlers

	apman.client.ON_LOG = apman.mqtt_log

	apman.client.ON_MESSAGE = apman.on_mqtt_message
	apman.client.ON_CONNECT = apman.on_mqtt_connect
	apman.client.ON_DISCONNECT = apman.on_mqtt_disconnect
	if apman.config['mqtt_username'] then
		local mqtt_password
		if apman.config['mqtt_password'] then
			mqtt_password = apman.config['mqtt_password']
		end
		apman.client:login_set(apman.config['mqtt_username'], mqtt_password)
	end
	local cafile, capath, certfile, keyfile
	if apman.config['cafile'] then
		cafile = apman.config['cafile']
	end
	if apman.config['capath'] then
		capath = apman.config['capath']
	end
	if apman.config['certfile'] then
		certfile = apman.config['certfile']
	end
	if apman.config['keyfile'] then
		keyfile = apman.config['keyfile']
	end
	if cafile or capath or certfile or keyfile then
		apman.client:tls_set(cafile, capath, certfile, keyfile)
	end
	local cert, tls_version, ciphers
	if apman.config['cert'] then
		cert = apman.config['cert']
	end
	if apman.config['tls_version'] then
		tls_version = apman.config['tls_version']
	end
	if apman.config['ciphers'] then
		ciphers = apman.config['ciphers']
	end
	if cert and (tls_version or ciphers) then
		apman.client:tls_opts_set(cert, tls_version, ciphers)
	end

	if type(apman.config['tls_insecure']) == 'string' then
		apman.client:tls_insecure_set(apman.config['tls_insecure'])
	end

	mqtt_host = apman.mqtt_hostname
	if apman.config['mqtt_host'] then
		mqtt_host = apman.config['mqtt_host']
	end
	if apman.config['mqtt_port'] then
		mqtt_port = apman.config['mqtt_port']
	end
	if apman.config['mqtt_keepalive'] then
		mqtt_keepalive = apman.config['mqtt_keepalive']
	end
	apman.mqtt_host = mqtt_host
	apman.mqtt_port = tonumber(mqtt_port)
	apman.mqtt_keepalive = tonumber(mqtt_keepalive)

	-- set last will (must be done before connection)
	topic = apman.ap_topic('online')
	apman.client:will_set(topic, cjson.encode({['status']='offline'}), 1, false)
end

-- exponential backoff with jitter, so a whole fleet does not hammer the
-- broker in lockstep after it comes back
function apman.mqtt_backoff_next()
	local delay = apman.mqtt_backoff * 2
	if delay < apman.mqtt_retry_min then
		delay = apman.mqtt_retry_min
	end
	if delay > apman.mqtt_retry_max then
		delay = apman.mqtt_retry_max
	end
	apman.mqtt_backoff = delay
	return delay / 2 + math.random() * (delay / 2)
end

-- single non blocking connection attempt; the handshake completes in
-- apman.mqttCallback and lands in apman.on_mqtt_connect
function apman.connect_mqtt()
	local ok, errno, err

	apman.mqtt_attempts = apman.mqtt_attempts + 1
	if apman.mqtt_started then
		ok, errno, err = apman.client:reconnect_async()
	else
		ok, errno, err = apman.client:connect_async(apman.mqtt_host, apman.mqtt_port, apman.mqtt_keepalive)
		apman.mqtt_started = true
	end

	local delay = apman.mqtt_backoff_next()
	apman.mqtt_next_attempt = socket.gettime() + delay
	if not ok then
		print(string.format("Mqtt connection attempt %d failed (%s), retrying in %.1fs.",
			apman.mqtt_attempts, tostring(err), delay))
	end
end

function apman.on_mqtt_connect(success, rc, str)
	if not success then
		apman.mqtt_connected = false
		print(string.format("Mqtt connection refused: %s", tostring(str)))
		return
	end

	local topic, data
	apman.mqtt_connected = true
	apman.mqtt_backoff = 0
	apman.mqtt_attempts = 0
	-- a fresh session may have lost our retained state, resend everything once
	apman.published = {}
	print(string.format("Mqtt connected to %s.", tostring(apman.mqtt_host)))

	topic = apman.ap_topic('online')
	apman.publish_mqtt(topic, cjson.encode({['status'] = 'online', ["timestamp"] = socket.gettime()}))

	-- subscribe command topics
	if apman.command_topic_global then
		topic = apman.topic_prefix .. 'command'
		apman.client:subscribe(topic, 1)
		print("Waiting for commands on topic: ", topic)
	end
	topic = apman.ap_topic('command')
	apman.client:subscribe(topic, 1)
	print("Waiting for commands on topic: ", topic)
	topic = apman.ap_topic('command/bulk')
	apman.client:subscribe(topic, 1)
	print("Waiting for commands on topic: ", topic)

	-- initial publish
	--- system.board
	data = apman.conn:call("system", "board", {})
	if type(data) == 'table' then
		data['timestamp'] = socket.gettime()
	end
	topic = apman.ap_topic('properties/system/board')
	apman.publish_mqtt( topic , cjson.encode(data), 1, true)
	--- system.info
	data = apman.conn:call("system", "info", {})
	if type(data) == 'table' then
		data['timestamp'] = socket.gettime()
	end
	topic = apman.ap_topic('properties/system/info')
	apman.publish_mqtt( topic , cjson.encode(data))

	apman.publish_agent()
	apman.publish_radius()

	if not apman.ubus_subscribed then
		apman.ubus_subscribed = true
		-- inform about boot up
		apman.publish_mqtt(apman.ap_topic('booted'), cjson.encode({}))
		apman.subscribeCallback()
		apman.statusCallback()
	end
end

-- validates a jsonrpc request, returns nil or an error object
function apman.validate_rpc(cmd)
	if type(cmd) ~= 'table' then
		return { code = 12, message = 'payload is not an object' }
	end
	if cmd['jsonrpc'] ~= '2.0' then
		return { code = 2, message = 'jsonrpc must be "2.0"' }
	end
	if cmd['method'] ~= 'call' and cmd['method'] ~= 'ctrl' then
		return { code = 1, message = 'method must be "call" or "ctrl"' }
	end
	if type(cmd['params']) ~= 'table' then
		return { code = 2, message = 'params must be an array' }
	end
	if type(cmd['params'][2]) ~= 'string' or type(cmd['params'][3]) ~= 'string' then
		if cmd['method'] == 'ctrl' then
			return { code = 2, message = 'params must be [session, interface, command]' }
		end

		return { code = 2, message = 'params must be [session, object, method, args]' }
	end
	return nil
end

-- executes one request and always produces a response: either result plus
-- ubus_status 0, or an error object. Both are needed because a successful call
-- can legitimately return nothing (rrm_nr_set), which used to be
-- indistinguishable from a failure.
-- 'done' is only used by the asynchronous ctrl path: that one returns nil here
-- and hands the response to the callback once hostapd answered. Every other
-- request is still answered synchronously through the return value.
function apman.execute_rpc(cmd, done)
	local response = { jsonrpc = '2.0', id = cmd and cmd['id'], ts = socket.gettime() }
	local err = apman.validate_rpc(cmd)
	if err ~= nil then
		response['error'] = err
		print(string.format("rejected jsonrpc message: %s", err.message))
		return response
	end

	if cmd['method'] == 'ctrl' then
		local iface, command = cmd['params'][2], cmd['params'][3]
		print(string.format("ctrl %s: %s", iface, apman.trunc(command)))
		apman_ctrl.request(iface, command, function(reply, cerr)
			if cerr ~= nil then
				response['error'] = {
					code = cerr.code,
					message = cerr.message,
					object = iface,
					method = apman_ctrl.verb(command),
				}
				print(string.format("ctrl %s failed: %s", iface, cerr.message))
			else
				response['result'] = apman_ctrl.parse(reply)
				response['ubus_status'] = 0
				print(string.format("ctrl %s ok: %s", iface, apman.trunc(reply)))
			end
			response['ts'] = socket.gettime()
			if done ~= nil then
				done(response)
			else
				apman.publish_rpc_response(response)
			end
		end)

		return nil
	end

	local object, method, args = cmd['params'][2], cmd['params'][3], cmd['params'][4]
	if type(args) ~= 'table' then
		args = {}
	end
	-- the agent's own object: the radius keystore, one complete set per
	-- ssid, answered with the versions in force (see radius.apply_keys)
	if object == 'apman' then
		if not apman.radius_active then
			response['error'] = { code = 8, message = 'radius server not running', object = object, method = method }
		elseif method == 'keys' then
			local result, kerr = apman_radius.apply_keys(apman.radius_server, args)
			if result == nil then
				apman_radius.note_error(apman.radius_server, 'key set refused: ' .. tostring(kerr))
				response['error'] = { code = 4, message = tostring(kerr), object = object, method = method }
			else
				response['result'] = result
				response['ubus_status'] = 0
			end
			-- the key set is what the controller changed; say what it did
			-- to this server before the next status tick would
			apman.publish_radius()
		elseif method == 'keys_status' then
			response['result'] = { versions = apman.radius_server.store.versions or {},
				source = apman.radius_server.store.source,
				keys = apman_radius.store_count(apman.radius_server.store) }
			response['ubus_status'] = 0
		else
			response['error'] = { code = 2, message = 'unknown method', object = object, method = method }
		end
		return response
	end
	print(string.format("calling %s %s with %s", object, method, apman.trunc(cjson.encode(args))))

	local result, status = apman.conn:call(object, method, args)
	if result == nil and type(status) == 'number' and status ~= 0 then
		response['error'] = {
			code = status,
			message = apman.ubus_status_text[status] or 'ubus error',
			object = object,
			method = method,
		}
		print(string.format("call %s %s failed: %s (%d)", object, method, response['error'].message, status))
	else
		response['result'] = result
		response['ubus_status'] = 0
		print(string.format("call %s %s ok: %s", object, method, apman.trunc(cjson.encode(result))))
	end
	return response
end

-- correlation topic, so several commands in flight do not overwrite each
-- other in the retained slot of the shared result topic
function apman.publish_rpc_response(response, suffix)
	local topic = apman.ap_topic('command_result' .. (suffix or ''))
	local payload = cjson.encode(response)
	-- not retained: consumers correlate through command_result/<id>, and a
	-- retained value here only hands every reconnecting consumer a stale
	-- result and loses one of two concurrent answers
	apman.publish_mqtt(topic, payload, 1, false)
	if response['id'] ~= nil then
		local id = string.gsub(tostring(response['id']), '[^%w%-_.]', '')
		if id ~= '' then
			apman.publish_mqtt(topic .. '/' .. id, payload, 1, false)
		end
	end
end

function apman.on_mqtt_message(mid, topic, payload)
	print(string.format("Received message. topic: '%s', message: '%s'", topic, apman.trunc(payload)))
	if topic == apman.ap_topic('command/bulk') then
		return apman.bulk_command(mid, topic, payload)
	end
	local ok, cmd = pcall(cjson.decode, payload)
	if not ok then
		cmd = nil
	end
	-- nil means the request is in flight and answers itself later
	local response = apman.execute_rpc(cmd)
	if response ~= nil then
		apman.publish_rpc_response(response)
	end
end

function apman.bulk_command(mid, topic, payload)
	local commands = {}
	local results = {}
	print(string.format("Received command list. topic: '%s', message: '%s'", topic, apman.trunc(payload)))
	if topic ~= apman.ap_topic('command/bulk') then
		print("msg checks fail0")
		return
	end
	local ok
	ok, commands = pcall(cjson.decode, payload)
	if not ok or type(commands) ~= 'table' or type(commands['list']) ~= "table" then
		print("no list found.")
		apman.publish_rpc_response({
			jsonrpc = '2.0',
			error = { code = 2, message = 'bulk payload needs a "list" array' },
			ts = socket.gettime(),
		}, '/bulk')
		return
	end
	-- one bad entry no longer discards the whole batch silently, every
	-- command gets its own result or error
	--
	-- A ctrl entry answers later, so the batch is published once the last
	-- one is in. Every ctrl request carries its own deadline, so a silent
	-- hostapd delays the batch but cannot lose it.
	local pending, published = 0, false
	local function publish_bulk()
		if published or pending > 0 then
			return
		end
		published = true
		apman.publish_mqtt(apman.ap_topic('command_result/bulk'),
			cjson.encode(results), 1, true)
	end

	for key, cmd in pairs(commands['list']) do
		pending = pending + 1
		local response = apman.execute_rpc(cmd, function(async)
			results[key] = async
			pending = pending - 1
			publish_bulk()
		end)
		if response ~= nil then
			results[key] = response
			pending = pending - 1
		end
	end
	publish_bulk()
end

-- retained inventory of what this agent is and can do, so the controller can
-- gate features per ap instead of guessing from firmware versions
function apman.publish_agent()
	local features = {}
	local function feature(name, enabled)
		if enabled then
			table.insert(features, name)
		end
	end
	feature('command_v2', true)
	feature('resend_suppression', true)
	feature('bss_events', apman.have_bss_events)
	feature('hostapd_status', apman.hostapd_status and apman.have_bss_events)
	feature('bss_info', apman.have_bss_events)
	feature('netifd_notifications', #apman.subscribe_objects > 0)
	feature('ubus_events', #apman.listen_events > 0)
	feature('station_dump', apman.station_dump)
	feature('survey', apman.survey_interval > 0)
	feature('assoclist_device', true)
	feature('ctrl_proxy', apman_ctrl.enabled and have_unix)
	feature('radius_psk', apman.radius_active)
	feature('mib', apman_ctrl.enabled and have_unix and apman_ctrl.mib_interval > 0)
	feature('sta_ctrl', apman_ctrl.enabled and have_unix and apman_ctrl.sta_ctrl_interval > 0)
	feature('ctrl_events', apman_ctrl.events and apman_ctrl.enabled and have_unix)

	local info = {
		agent = 'apman',
		version = apman.version,
		hostname = apman.hostname,
		started = apman.started_at,
		features = features,
		hostapd = { ucode = apman.have_bss_events },
		intervals = {
			status = apman.status_interval / 1000,
			wireless_republish = apman.wireless_republish,
			property_republish = apman.property_republish,
			probe = apman.probe_interval,
			survey = apman.survey_interval,
		},
	}
	apman.publish_property(apman.ap_topic('properties/agent'), cjson.encode(info),
		1, true, apman.property_republish)
end

-- The state of the on-ap radius server, retained, so the controller can show
-- it without asking. Published even when the server is off: "not running, and
-- here is why" is the answer that matters most, and a topic that simply stays
-- absent cannot carry it. Same reason the last error is kept after a recovery
-- — an error that scrolled out of the log never happened, as far as anyone
-- looking at the fleet later is concerned.
function apman.publish_radius()
	local info
	if apman.radius_active and apman.radius_server ~= nil then
		local ok, status = pcall(apman_radius.status, apman.radius_server)
		info = ok and status or { running = true, error = tostring(status) }
	else
		info = {
			running = false,
			enabled = apman.radius_enabled and true or false,
			reason = apman.radius_last_error or
				(apman.radius_enabled and 'not started' or 'not enabled in /etc/config/apman'),
		}
	end
	info.hostname = apman.hostname
	info.ts = socket.gettime()
	-- ts changes on every call, so the payload always differs and
	-- publish_property would lose its point: compare without it
	local compare = cjson.encode(info)
	apman.publish_property(apman.ap_topic('properties/radius'), compare,
		1, true, apman.property_republish)
end

-- per channel noise and busy time, the input a controller needs for fleet wide
-- channel planning. Rate limited, the payload is sizeable and slow moving.
function apman.publish_survey(devices)
	if apman.survey_interval <= 0 then
		return
	end
	local now = socket.gettime()
	if (now - apman.survey_last) < apman.survey_interval then
		return
	end
	apman.survey_last = now

	for key, device in pairs(devices) do
		local survey = apman.conn:call("iwinfo", "survey", { device = device })
		if type(survey) == 'table' then
			survey['device'] = device
			survey['timestamp'] = now
			apman.publish_mqtt(apman.ap_topic('survey/' .. device), cjson.encode(survey))
		end
	end
end

-- publishes only when the payload changed or the last publish is older than
-- max_age. Retained topics keep working for late subscribers, and a consumer
-- that lost its state resyncs within max_age.
function apman.publish_property(topic, payload, qos, retain, max_age)
	local last = apman.published[topic]
	if last ~= nil and last.payload == payload then
		if max_age == nil or (socket.gettime() - last.ts) < max_age then
			return true
		end
	end
	local result = apman.publish_mqtt(topic, payload, qos, retain)
	if result ~= nil then
		apman.published[topic] = { payload = payload, ts = socket.gettime() }
	end
	return result
end

function apman.publish_mqtt(topic, payload, qos, retain)
	local maxlen = 90
	-- dropping is intentional: while offline the broker cannot take anything
	-- anyway, and the next connect republishes the retained properties
	if not apman.mqtt_connected then
		return nil
	end
--	if type(payload) == 'string' then
--		if string.len(payload) > maxlen then 
--			print(string.format("Publish to mqtt topic '%s', payload: %s...", topic, string.sub(payload,0, maxlen-3)))
--		else
--			print(string.format("Publish to mqtt topic '%s', payload: %s", topic, payload))
--		end
--	else 
--		print(string.format("Publish binary payload to mqtt topic '%s'.", topic))
--	end
	return apman.client:publish(topic, payload, qos, retain)
end

-- the vlan a bss lives on itself: its wifi interface as a bridge port with
-- a pvid (netifd spells the ports "wlan1:*" in bridge-vlans). A station on
-- that vlan must not get tunnel attributes back — hostapd would only put it
-- where it already is.
function apman.refresh_radius_bss_vlans()
	local iface_map = {}
	local wireless = apman.conn:call("network.wireless", "status", {})
	if type(wireless) ~= 'table' then
		apman.radius_bss_vlans = {}
		apman.radius_bss_ifaces = {}
		return
	end
	for _, radio in pairs(wireless) do
		if type(radio) == 'table' and type(radio['interfaces']) == 'table' then
			for section, iface in pairs(radio['interfaces']) do
				if type(iface) == 'table' and iface['ifname'] ~= nil then
					local entry = iface_map[iface['ifname']]
					if entry == nil then
						-- netifd's wireless status carries the uci section
						-- name in the 'section' field; the map key is the
						-- ifname and only a fallback
						entry = { section = tostring(iface['section'] or section) }
						iface_map[iface['ifname']] = entry
					end
				if iface['network'] ~= nil then
					local st = apman.conn:call("network.interface", "status",
						{ name = iface['network'] })
					local bridge = type(st) == 'table' and st['device'] or nil
					if bridge ~= nil and bridge ~= '' then
						local dev = apman.conn:call("network.device", "status",
							{ name = bridge })
						if type(dev) == 'table' and type(dev['bridge-vlans']) == 'table' then
							for _, vlan in ipairs(dev['bridge-vlans']) do
								if type(vlan) == 'table' and vlan['id'] ~= nil
										and type(vlan['ports']) == 'table' then
									for _, port in ipairs(vlan['ports']) do
										local p = tostring(port)
										if string.match(p, '^[^:]+') == iface['ifname']
												and string.find(p, '*', 1, true) ~= nil then
											entry.vlan = vlan['id']
										end
									end
								end
							end
						end
					end
				end
				end
			end
		end
	end

	-- map the bssid of every wifi interface onto its vlan and its uci
	-- section name — the radius key store is keyed by the latter
	apman.radius_bss_vlans = {}
	apman.radius_bss_ifaces = {}
	for ifname, entry in pairs(iface_map) do
		local info = apman.conn:call("iwinfo", "info", { device = ifname })
		if type(info) == 'table' and type(info['bssid']) == 'string' then
			local bssid = info['bssid']:gsub('[^%x]', ''):lower()
			if #bssid == 12 then
				apman.radius_bss_ifaces[bssid] = entry.section
				if entry.vlan ~= nil then
					apman.radius_bss_vlans[bssid] = tostring(entry.vlan)
				end
			end
		end
	end
end

-- one 'name:up' line per wireless interface, sorted and joined: the change
-- gate for the bss map watchdog. Any interface going up or down changes the
-- string, which is all the map cares about.
function apman.radius_bss_status_digest()
	local lines = {}
	local wireless = apman.conn:call("network.wireless", "status", {})
	if type(wireless) == 'table' then
		for _, radio in pairs(wireless) do
			if type(radio) == 'table' and type(radio['interfaces']) == 'table' then
				for _, iface in pairs(radio['interfaces']) do
					if type(iface) == 'table' and iface['ifname'] ~= nil then
						lines[#lines + 1] = string.format('%s:%s',
							tostring(iface['ifname']), tostring(iface['up']))
					end
				end
			end
		end
	end
	table.sort(lines)
	return table.concat(lines, '|')
end

-- re-read the radius keys from the wireless config; a no-op when nothing
-- changed (one read plus a digest comparison).
--
-- The bss map must follow the radios themselves, not just the config: BSSes
-- that were down when the map was last built (boot churn, DFS CAC after a
-- radar event) would otherwise answer every query with 'no key' forever.
-- Every tick therefore re-checks the wireless status and rebuilds the map
-- when an interface went up or down; the digest keeps the steady state at
-- one ubus call per tick.
function apman.radius_reload()
	if apman.radius_server ~= nil then
		if apman_radius.reload(apman.radius_server) then
			apman.publish_radius()
		end
		local dig = apman.radius_bss_status_digest()
		apman.radius_bss_ticks = (apman.radius_bss_ticks or 0) + 1
		-- The status digest reacts to interfaces going up and down, but a
		-- map that was built wrong once (iwinfo hiccup at boot, radios still
		-- calibrating) can stay wrong forever because the status never
		-- changes. A full rebuild every 30 ticks (~5 min) bounds the damage.
		if dig ~= apman.radius_bss_digest or apman.radius_bss_ticks % 30 == 0 then
			apman.radius_bss_digest = dig
			apman.refresh_radius_bss_vlans()
		end
	end
end

-- a radius accept/reject/drop. Accepts and rejects go to the broker, one
-- topic per bss: the controller can match the event against the bss it
-- configured, and Called-Station-Id gives us the bssid for free. The key
-- field names the wifi-station section the answer came from. Events from
-- sources that do not carry a bssid (radtest, non hostapd clients) land on
-- the bare topic. Drops (unauthenticated or malformed) only go to the log:
-- they are not trustable enough to act on and a hostile source must not be
-- able to flood the topic.
function apman.on_radius_event(event)
	-- built with plain concatenations on purpose: an and/or chain around
	-- string.format once evaluated to nil for events without a vid and
	-- killed every event (print, and with it the publish) silently
	local line = 'radius ' .. tostring(event.decision) .. ' '
		.. tostring(event.mac and apman_parse.format_mac(event.mac) or '?')
	if event.key then line = line .. ' key=' .. tostring(event.key) end
	if event.key_source then line = line .. ' from=' .. tostring(event.key_source) end
	if event.bssid then line = line .. ' bss=' .. tostring(apman_parse.format_mac(event.bssid)) end
	if event.ssid then line = line .. ' ssid=' .. tostring(event.ssid) end
	if event.akm then line = line .. ' akm=' .. tostring(event.akm) end
	if event.vid then
		line = line .. ' vid=' .. tostring(event.vid)
		if event.vlan_suppressed then line = line .. ' (bss vlan, not sent)' end
	end
	if event.reason then line = line .. ' (' .. tostring(event.reason) .. ')' end
	print(line)
	-- Only one key can ever be offered, so several unbound keys on one network
	-- means the ones behind the first cannot be enrolled until it binds. The
	-- access point cannot decide that; say it plainly here and let it travel
	-- to the controller in the event below.
	if event.unbound_keys ~= nil then
		print('radius-error ' .. tostring(event.unbound_keys) .. ' unbound keys on ssid='
			.. tostring(event.ssid) .. ', ' .. tostring(event.mac and apman_parse.format_mac(event.mac) or '?')
			.. ' was offered ' .. tostring(event.key)
			.. ' — the others cannot enrol until it binds')
	end
	if event.decision == 'accept' or event.decision == 'reject' then
		local topic = apman.ap_topic('radius/auth' ..
			(event.bssid ~= nil and ('/' .. event.bssid) or ''))
		apman.publish_mqtt(topic, cjson.encode(event), 1, false)
	end
end

function apman.on_mqtt_disconnect(success, rc, str)
	print(string.format("Mqtt disconnected: %s", tostring(str)))
	apman.mqtt_connected = false
	-- reconnect promptly on the first loss, backoff grows from there
	apman.mqtt_backoff = 0
	apman.mqtt_next_attempt = socket.gettime() + apman.mqtt_backoff_next()
	return
end

function apman.init()
	apman.connect_ubus()
	if not apman.conn then
		error("Failed to connect to ubus")
	end

	-- config
	result = apman.conn:call("uci", "get", {["config"] = "system",["section"] = "@system[0]",["option"] = "hostname"})
	if type(result) ~= 'table' or result.value == nil then
		print("Failed to get hostname")
		os.exit(1)
	end
	apman.hostname = result.value
	result = apman.conn:call("uci", "get", {["config"] = "apman",["section"] = "main"})
	if type(result.values) ~= 'table' then
		print("Failed to get apman config")
		os.exit(1)
	end
	apman.config = result.values

	if apman.config['enabled'] ~= "1" then
		print("apman is not enabled")
		os.exit(1)
	end

	if apman.config['hostname'] ~= nil then
		apman.hostname = apman.config['hostname']
	end

	apman.started_at = socket.gettime()
	apman.apply_config()
	cjson.encode_invalid_numbers("null")

	-- start loop
	uloop.init()

	-- prepare the mqtt client, the connection is established from the timer
	apman.setup_mqtt()

	apman.timers['ubus_check'] = uloop.timer(apman.ubusCheckCallback)
	apman.timers['status'] = uloop.timer(apman.statusCallback)
	apman.timers['subscribe'] = uloop.timer(apman.subscribeCallback)
	apman.timers['mqtt'] = uloop.timer(apman.mqttCallback)

	apman.timers['ubus_check']:set(apman.ubus_check_interval)
	apman.timers['status']:set(apman.status_interval)

	-- radius server for hostapd wpa_psk_radius / sae per station psk queries
	apman.radius_apply()

	-- the controller provisions the radius server by writing /etc/config/
	-- apman; watch it so no restart is needed to pick the change up
	if (apman.radius_reload_interval or 10) > 0 then
		apman.timers['config'] = uloop.timer(apman.configCallback)
		apman.timers['config']:set(apman.radius_reload_interval * 1000)
	end

	-- first connection attempt; ubus subscription and the initial status
	-- publish follow from apman.on_mqtt_connect
	apman.mqttCallback()

	uloop.run()
end

-- start or stop the radius server to match the config; also runs when the
-- config watch picks up a change
function apman.radius_apply()
	if not have_radius then
		if apman.radius_enabled then
			print('Radius server requested but the apman-radius module is not installed.')
		end
		return
	end
	if apman.radius_enabled and apman.radius_active
		and (apman.radius_secret ~= apman.radius_server.secret
			or apman.radius_port ~= apman.radius_server.opts.port
			or apman.radius_bind ~= apman.radius_server.opts.bind) then
		-- the secret changed: keep answering with the old one would strand
		-- hostapd, so stop first and fall through to a fresh start
		apman_radius.stop(apman.radius_server)
		apman.radius_server = nil
		apman.radius_active = false
	end
	if apman.radius_enabled and not apman.radius_active then
		-- a failing start (bad socket, missing module) must never take the
		-- whole agent down — radius is an add-on, not the reason to live
		local ok, server, err = pcall(function()
			return apman_radius.start({
				port = apman.radius_port,
				bind = apman.radius_bind,
				secret = apman.radius_secret,
				wifi_config = apman.radius_wifi_config,
				keystore = apman.radius_keystore,
				reload_interval = apman.radius_reload_interval,
				-- B4: the periodic tick rebuilds the bssid map too, not
				-- just the key store — a map built wrong once (iwinfo
				-- hiccup at boot) otherwise rejects everybody forever
				tick = apman.radius_reload,
				onevent = apman.on_radius_event,
				bss_vlan = function(bssid) return apman.radius_bss_vlans[bssid] end,
				bss_iface = function(bssid) return apman.radius_bss_ifaces[bssid] end,
			})
		end)
		if not ok then
			apman.radius_last_error = tostring(server)
			print(string.format('Radius server failed to start: %s', tostring(server)))
			apman.publish_radius()
			return
		end
		if server == nil then
			apman.radius_last_error = tostring(err)
			print(string.format('Radius server not started: %s', tostring(err)))
			apman.publish_radius()
		else
			apman.radius_server = server
			apman.radius_active = true
			apman.radius_last_error = nil
			apman.refresh_radius_bss_vlans()
			print(string.format('Radius server listening on %s:%d, %d keys from %s.',
				apman.radius_bind, apman.radius_port,
				apman_radius.store_count(server.store), tostring(server.store.source)))
		end
	elseif not apman.radius_enabled and apman.radius_active then
		apman_radius.stop(apman.radius_server)
		apman.radius_server = nil
		apman.radius_active = false
		print('Radius server stopped.')
		apman.publish_radius()
	end
end

-- re-read /etc/config/apman when it changes, so a controller that provisions
-- the radius server over uci needs no restart command to take effect
function apman.configCallback()
	if apman.timers['config'] ~= nil then
		apman.timers['config']:set(math.max(apman.radius_reload_interval, 1) * 1000)
	end
	local f = io.open('/etc/config/apman', 'r')
	local content = f and f:read('*a') or ''
	if f then f:close() end
	if content == apman.config_digest then
		return
	end
	apman.config_digest = content
	-- apply_config() reads apman.config, which init() filled once: without
	-- this re-read the change on disk would never reach the running values
	local result = apman.conn:call("uci", "get", {["config"] = "apman", ["section"] = "main"})
	if type(result) ~= 'table' or type(result.values) ~= 'table' then
		print('apman config changed but uci would not hand it over, keeping the running values')
		return
	end
	apman.config = result.values
	print('apman config changed, re-applying.')
	apman.apply_config()
	apman.radius_apply()
end

function apman.apply_config()
	apman.topic_prefix = apman.cfg('topic_prefix', apman.topic_prefix)
	if apman.topic_prefix:sub(-1) ~= '/' then
		apman.topic_prefix = apman.topic_prefix .. '/'
	end

	apman.status_interval = apman.cfg_num('status_interval', 10) * 1000
	apman.ubus_check_interval = apman.cfg_num('ubus_check_interval', 1) * 1000
	apman.ubus_settle = apman.cfg_num('ubus_settle', 5) * 1000
	apman.mqtt_loop_interval = apman.cfg_num('mqtt_loop_interval', 200)
	apman.mqtt_retry_min = apman.cfg_num('mqtt_retry_min', 2)
	apman.mqtt_retry_max = apman.cfg_num('mqtt_retry_max', 120)
	apman.ubus_check_interval_slow = apman.cfg_num('ubus_check_interval_slow', 30) * 1000
	apman.station_dump = apman.cfg_bool('station_dump', true)
	apman.command_topic_global = apman.cfg_bool('command_topic_global', true)
	apman.hostapd_status = apman.cfg_bool('hostapd_status', true)
	local old_subscribe = apman.subscribe_objects
	local old_events = apman.listen_events
	apman.subscribe_objects = apman.cfg_list('subscribe', apman.subscribe_objects)
	apman.listen_events = apman.cfg_list('listen_event', apman.listen_events)
	-- the ubus subscriptions live until the next resubscribe; a config change
	-- that alters them needs one now. At init the timer does not exist yet,
	-- the first subscribe picks the new values up anyway.
	if apman.timers['ubus_check'] ~= nil and
			(apman.list_key(apman.subscribe_objects) ~= apman.list_key(old_subscribe)
			 or apman.list_key(apman.listen_events) ~= apman.list_key(old_events)) then
		apman.schedule_resubscribe('config change')
	end
	apman.property_republish = apman.cfg_num('property_republish', 300)
	apman.wireless_republish = apman.cfg_num('wireless_republish', 60)
	apman.probe_interval = apman.cfg_num('probe_interval', 10)
	apman.log_payload_len = apman.cfg_num('log_payload_len', 200)
	apman.survey_interval = apman.cfg_num('survey_interval', 300)

	apman.radius_enabled = apman.cfg_bool('radius_enabled', false)
	apman.radius_port = apman.cfg_num('radius_port', 1812)
	apman.radius_bind = apman.cfg('radius_bind', '127.0.0.1')
	-- /etc/apman/apman.keys, not /var: this is the store the agent starts from
	-- after a reboot, and the package lists it as a conffile so a sysupgrade
	-- carries it over. The old name is taken along once, so an access point
	-- that has been running does not come up with an empty store.
	apman.radius_keystore = apman.cfg('radius_keystore', '/etc/apman/apman.keys')
	do
		local legacy = '/etc/apman/keys.json'
		if apman.radius_keystore ~= legacy then
			local new_f = io.open(apman.radius_keystore, 'r')
			if new_f == nil then
				local old_f = io.open(legacy, 'r')
				if old_f ~= nil then
					old_f:close()
					if os.rename(legacy, apman.radius_keystore) then
						print(string.format('radius keystore: moved %s to %s', legacy, apman.radius_keystore))
					end
				end
			else
				new_f:close()
			end
		end
	end
	apman.radius_secret = apman.cfg('radius_secret', '')
	apman.radius_wifi_config = apman.cfg('radius_wifi_config', '/etc/config/wireless')
	apman.radius_reload_interval = apman.cfg_num('radius_reload_interval', 10)

	apman_ctrl.bind({ ap_topic = apman.ap_topic, publish = apman.publish_mqtt })
	apman_ctrl.configure({
		enabled = apman.cfg_bool('ctrl_enabled', true),
		allow_all = apman.cfg_bool('ctrl_allow_all', false),
		timeout = apman.cfg_num('ctrl_timeout', 3),
		dir = apman.cfg('ctrl_dir', apman_ctrl.dir),
		events = apman.cfg_bool('ctrl_events', true),
		event_all = apman.cfg_bool('ctrl_event_all', false),
		mib_interval = apman.cfg_num('mib_interval', 60),
		sta_ctrl_interval = apman.cfg_num('sta_ctrl_interval', 300),
		sta_ctrl_retry = apman.cfg_num('sta_ctrl_retry', 30),
		event_allow_add = apman.cfg_list('ctrl_event_allow', {}),
		event_allow_drop = apman.cfg_list('ctrl_event_deny', {}),
		allow_add = apman.cfg_list('ctrl_allow', {}),
	})
	-- the reply socket name has to be unique per process and request
	local stat = io.open('/proc/self/stat')
	if stat ~= nil then
		apman.pid = tonumber(string.match(stat:read('*l') or '', '^(%d+)'))
		stat:close()
	end
	-- after the pid is known, not with the rest of the binding above: the
	-- control channel names its reply sockets with it, and a nil there puts
	-- two processes on the same path
	apman_ctrl.opts.pid = apman.pid

	-- seed per host, otherwise every ap of a fleet draws the same backoff
	local seed = math.floor(socket.gettime() * 1000) % 2147483647
	for i = 1, #apman.hostname do
		seed = (seed + string.byte(apman.hostname, i) * i) % 2147483647
	end
	math.randomseed(seed)
	math.random()
	math.random()
end

return apman
