-- The collectd read callback.
--
-- This lives here and not in apman.lua because it runs in a different process:
-- collectd loads it, the agent daemon never calls it. Kept in the shared
-- module it was 258 lines every daemon start paid for and never used, in the
-- file everyone reads to understand the agent. What it borrows from apman is
-- four things — the hostname, the ubus connection and how to open it, and it
-- brings its own plugin name.
--
-- It opens and closes its own ubus connection per read on purpose: collectd
-- reads on its own interval and must not hold a socket the daemon owns.

apman = require "apman"

local PLUGIN = 'apman'

local function read_stats()
	apman.connect_ubus()
	if not apman.conn then
		error("Failed to connect to ubus")
		return 1
	end

	-- config
	if not apman.hostname then
		print("Resolving Hostname")
		result = apman.conn:call("uci", "get", {["config"] = "system",["section"] = "main",["option"] = "hostname"})
		if type(result) ~= 'table' or result.value == nil then
			result = apman.conn:call("uci", "get", {["config"] = "system",["section"] = "@system[0]",["option"] = "hostname"})
		end
		if type(result) ~= 'table' or result.value == nil then
			print("Failed to get hostname")
			apman.conn:close()
			return 1
		end
		apman.hostname = result.value
	end


        local network_wireless_status = apman.conn:call("network.wireless", "status", {})
	local dev2radio = {}
	local radio_stats = {}
	if type(network_wireless_status) ~= 'table' then
		print("collectd: network.wireless status not available, skipping this read")
		apman.conn:close()
		return 1
	end
        for radio, value in pairs(network_wireless_status) do
		if type(value) ~= 'table' then
			radio_stats[ radio ] = { stations = 0 }
		else
			radio_stats[ radio ] = {}
			radio_stats[ radio ][ 'stations' ] = 0
			radio_stats[ radio ][ 'up' ] = value['up']

			if type(value['interfaces']) == 'table' then
				for interface, ifconfig in pairs(value['interfaces']) do
					if type(ifconfig) == 'table' and ifconfig['ifname'] ~= nil then
						dev2radio[ ifconfig['ifname'] ] = radio
					end
				end
			end
		end
	end

        local devices = apman.conn:call("iwinfo", "devices", {})
        local slaves = {}
        local masters = {}
	if type(devices) ~= 'table' or type(devices['devices']) ~= 'table' then
		print("collectd: iwinfo device list not available, skipping this read")
		apman.conn:close()
		return 1
	end
        for key, value in pairs(devices['devices']) do
                local i,j, masterdev
		masterdev = value
                i, j = string.find(value, '.sta')
                if i ~= nil then
                        local master = string.sub(value, 0, i-1)
                        if slaves[master] == nil then
                                slaves[master] = {}
                        end
			masterdev = master
                        table.insert(slaves[master], value)
                else
                        table.insert(masters, value)
                end
		if dev2radio[masterdev] ~= nil then
			local radio = dev2radio[masterdev]
			status = apman.conn:call("network.device", "status", {name = value})
			if type(status) == 'table' and type(status['statistics']) == 'table' then
				if radio_stats[radio]['statistics'] == nil then
					radio_stats[radio]['statistics'] = status['statistics']
				else
					for k2, v2 in pairs(status['statistics']) do
						if radio_stats[radio]['statistics'][k2] == nil then
							radio_stats[radio]['statistics'][k2] = v2
						else
							radio_stats[radio]['statistics'][k2] = radio_stats[radio]['statistics'][k2] + v2
						end
					end
				end
			end
		end
        end

--	collectd.log_info('debug radiostats: '..cjson.encode(radio_stats))
        for key, value in pairs(masters) do
                status = apman.conn:call("hostapd."..value, "get_status", {})
		radio = dev2radio[ value ]
		if type(status) == 'table' then
			if status['airtime'] and type(status['airtime']) == 'table' then
				if status['airtime']['time'] ~= nil
						and status['airtime']['time_busy'] ~= nil
						and status['airtime']['utilization'] ~= nil then
					local t = {
						host = apman.hostname,
						plugin = PLUGIN,
						plugin_instance = value,
						type = 'wifi_airtime',
						values = {status['airtime']['time'], status['airtime']['time_busy'], status['airtime']['utilization']}
					}
					collectd.dispatch_values(t)
					if radio ~= nil and radio_stats[radio] ~= nil then
						radio_stats[radio]['airtime'] = t.values
					end

				end
			end

			if status['dfs'] and type(status['dfs']) == 'table' then
				if status['dfs']['cac_seconds'] ~= nil
						and status['dfs']['cac_seconds_left'] ~= nil
						and status['dfs']['cac_active'] ~= nil then
					local t = {
						host = apman.hostname,
						plugin = PLUGIN,
						plugin_instance = value,
						type = 'wifi_dfs',
						values = {status['dfs']['cac_seconds'], status['dfs']['cac_seconds_left'], status['dfs']['cac_active']}
					}
					collectd.dispatch_values(t)
					if radio ~= nil and radio_stats[radio] ~= nil then
						radio_stats[radio]['dfs'] = t.values
					end
				end
			end

			if status['channel'] and status['freq'] and status['status'] then
				local chan_stat = 0
				if status['status'] == 'ENABLED' then
					chan_stat = 1
				end
				local t = {
					host = apman.hostname,
					plugin = PLUGIN,
					plugin_instance = value,
					type = 'wifi_channel',
					values = {status['channel'], status['freq'], chan_stat}
				}
				collectd.dispatch_values(t)
				if radio ~= nil and radio_stats[radio] ~= nil then
					radio_stats[radio]['wifi_channel'] = t.values
				end
			end
		end

                clients = apman.conn:call("hostapd."..value, "get_clients", {})
		if radio ~= nil and type(clients) == 'table' and type(clients['clients']) == 'table' then
			for a3, b3 in pairs(clients['clients']) do
				radio_stats[radio]['stations'] = radio_stats[radio]['stations'] + 1
			end
		end
        end

	for radio, stats in pairs(radio_stats) do
		if stats['airtime'] ~= nil then
			local t = {
				host = apman.hostname,
				plugin = PLUGIN,
				plugin_instance = radio,
				type = 'wifi_airtime',
				values = stats['airtime']
			}
			collectd.dispatch_values(t)
		end
		if stats['dfs'] ~= nil then
			local t = {
				host = apman.hostname,
				plugin = PLUGIN,
				plugin_instance = radio,
				type = 'wifi_dfs',
				values = stats['dfs']
			}
			collectd.dispatch_values(t)
		end
		if stats['wifi_channel'] ~= nil then
			local t = {
				host = apman.hostname,
				plugin = PLUGIN,
				plugin_instance = radio,
				type = 'wifi_channel',
				values = stats['wifi_channel']
			}
			collectd.dispatch_values(t)
		end
		if stats['stations'] ~= nil then
			local t = {
				host = apman.hostname,
				plugin = PLUGIN,
				plugin_instance = radio,
				type = 'stations',
				values = {stats['stations']}
			}
			collectd.dispatch_values(t)
		end
		if stats['statistics'] ~= nil then
			-- every counter pair is dispatched on its own: a key netifd does
			-- not report must not take the whole read down with it
			local rx, tx = stats['statistics']['rx_bytes'], stats['statistics']['tx_bytes']
			if rx ~= nil and tx ~= nil then
				local t = {
					host = apman.hostname,
					plugin = PLUGIN,
					plugin_instance = radio,
					type = 'if_octets',
					values = {rx % 1073741824, tx % 1073741824}
				}
				collectd.dispatch_values(t)
			end

			rx, tx = stats['statistics']['rx_packets'], stats['statistics']['tx_packets']
			if rx ~= nil and tx ~= nil then
				local t = {
					host = apman.hostname,
					plugin = PLUGIN,
					plugin_instance = radio,
					type = 'if_packets',
					values = {rx, tx}
				}
				collectd.dispatch_values(t)
			end

			rx, tx = stats['statistics']['rx_dropped'], stats['statistics']['tx_dropped']
			if rx ~= nil and tx ~= nil then
				local t = {
					host = apman.hostname,
					plugin = PLUGIN,
					plugin_instance = radio,
					type = 'if_dropped',
					values = {rx, tx}
				}
				collectd.dispatch_values(t)
			end

			rx, tx = stats['statistics']['rx_errors'], stats['statistics']['tx_errors']
			if rx ~= nil and tx ~= nil then
				local t = {
					host = apman.hostname,
					plugin = PLUGIN,
					plugin_instance = radio,
					type = 'if_errors',
					values = {rx, tx}
				}
				collectd.dispatch_values(t)
			end
		end
	end

	apman.conn:close()
	return 0

end

collectd.register_read(read_stats)
