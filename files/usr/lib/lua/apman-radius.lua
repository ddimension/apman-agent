-- apman-radius: minimal RADIUS server answering hostapd per station PSK queries.
--
-- hostapd's wpa_psk_radius (1/2/3) and sae_password_psk modes authenticate a
-- station by asking the configured RADIUS server for its PSK at association
-- time (and, with wpa_psk_radius=3, again during the 4-way handshake). The
-- Access-Request carries the station MAC as User-Name and Calling-Station-Id,
-- the WLAN-AKM-Suite tells the PSK flavour apart (WPA-PSK vs SAE), and the
-- server answers Access-Accept with the PSK in an encrypted Tunnel-Password
-- attribute or Access-Reject.
--
-- Only the wire contract hostapd implements in
--   src/ap/ieee802_11_auth.c  (hostapd_radius_acl_query, decode_tunnel_passwords)
--   src/radius/radius.c       (radius_msg_finish_srv, radius_msg_get_tunnel_password)
-- is spoken: every request must carry a valid Message-Authenticator (HMAC-MD5
-- with the shared secret), which is also what keeps a packet from a wrong
-- secret out; anything else is dropped without an answer. The shared secret
-- has to match hostapd's auth_server_shared_secret.
--
-- The keys come from the uci wireless config, one wifi-station section per
-- station (or group of stations sharing a key) — the same sections the
-- firmware's hostapd.sh turns into the per bss psk/sae files:
--
--   config wifi-station 'anna'
--           list mac '00:11:22:33:44:55'
--           list mac 'aa:bb:cc:dd:ee:ff'
--           option key 'passphrase'
--           option vid '7'
--
-- The section name identifies the key (it shows up as 'key' in the event and
-- matches the keyid the controller knows), 'mac' is a list (absent = every
-- station, like hostapd's 00:00:00:00:00:00 wildcard), 'key' the passphrase,
-- 'vid' an optional vlan handed back to hostapd as tunnel attributes.
--
-- The config is re-read when its content changes, driven twice: apman
-- subscribes the hostapd-auth ubus object and reloads on its 'reload'
-- notification (every wifi config application), and a digest timer catches
-- everything that slips through.

local radius = {}

-------------------------------------------------------------- md5 (RFC 1321)
-- From the lua-md5 package, which this one depends on.
--
-- There was a pure Lua implementation here, arithmetic only, because the
-- device had no crypto module and none was wanted as a dependency. It was
-- correct and it cost 9 ms per hash on an ipq60xx: this lua has no bit
-- library, so every and/or/xor went through 16x16 nibble tables. One
-- Access-Accept needs three to five hashes, which was the 40-60 ms round trip
-- hostapd reported — and with macaddr_acl=2 the access point stays silent
-- until the answer is in, while the station gives up on the authentication
-- frame after three tries in ~330 ms. Those milliseconds decide whether a roam
-- is a fast transition or a full reauthentication. lua-md5 does the same hash
-- in 4 us, so what was left of the fallback was a slow way to fail.

local guard = require('apman-guard')
local native = require('md5')
local md5 = native.sum
radius.native_md5 = true

local function xor_str(x, y)
	if #x == #y then
		return native.exor(x, y)
	end
	-- md5.exor insists on equal lengths. Nothing calls this with a short
	-- tail today; hmac below needs it to keep working if anything ever does.
	local out = {}
	for i = 1, #x do
		out[i] = string.char(native.exor(x:sub(i, i), y:sub(i, i)):byte())
	end
	return table.concat(out)
end

-- hmac-md5 (RFC 2104), key and message are raw strings
local function hmac_md5(key, message)
	if #key > 64 then
		key = md5(key)
	end
	local kp = key .. string.rep('\0', 64 - #key)
	return md5(xor_str(kp, string.rep(string.char(0x5c), 64)) ..
		md5(xor_str(kp, string.rep(string.char(0x36), 64)) .. message))
end


local hexdigits = '0123456789abcdef'
local function tohex(s)
	return (s:gsub('.', function(c)
		local b = c:byte()
		return hexdigits:sub(math.floor(b / 16) + 1, math.floor(b / 16) + 1) ..
			hexdigits:sub(b % 16 + 1, b % 16 + 1)
	end))
end

----------------------------------------------------------------- radius
-- attribute type numbers spoken here (RFC 2865/2868/7268)
local ATTR_USER_NAME = 1
local ATTR_CALLED_STATION_ID = 30
local ATTR_CALLING_STATION_ID = 31
local ATTR_TUNNEL_TYPE = 64
local ATTR_TUNNEL_MEDIUM_TYPE = 65
local ATTR_TUNNEL_PASSWORD = 69
local ATTR_MESSAGE_AUTHENTICATOR = 80
local ATTR_TUNNEL_PRIVATE_GROUP_ID = 81
local ATTR_WLAN_AKM_SUITE = 188

-- RFC 2868: tag byte plus a 24 bit big endian integer, as
-- radius_msg_get_vlanid() reads it
local function tunnel_int24(v)
	return string.char(0, math.floor(v / 65536) % 256,
		math.floor(v / 256) % 256, v % 256)
end

-- WLAN-AKM-Suite (RSN suite selector) values, IEEE 802.11 table 9-151
local AKM_NAMES = {
	['000fac01'] = 'WPA-802.1X',
	['000fac02'] = 'WPA-PSK',
	['000fac06'] = 'WPA-PSK-SHA256',
	['000fac08'] = 'SAE',
	['000fac09'] = 'FT-SAE',
	['000fac0f'] = 'WPA-EAP-SUITE-B',
	['000fac10'] = 'WPA-PSK-SUITE-B',
}

-- parse a RADIUS packet. Unknown attributes are skipped, including the
-- RFC 6929 extended ones hostapd may send (wire types 241-246 carry the
-- extended type in a third header byte, 249/250 a two byte length).
-- Returns nil on anything malformed.
function radius.parse(data)
	if type(data) ~= 'string' or #data < 20 then
		return nil
	end
	local length = data:byte(3) * 256 + data:byte(4)
	if length < 20 or length > #data then
		return nil
	end

	local attrs = {}
	local pos = 21
	while pos <= length do
		local atype, alen, vpos = data:byte(pos), nil, nil
		if atype >= 241 and atype <= 246 then
			if pos + 2 > length then return nil end
			alen = data:byte(pos + 1)
			vpos = pos + 3
			if alen < 3 or pos + alen - 1 > length then return nil end
		elseif atype == 249 or atype == 250 then
			if pos + 3 > length then return nil end
			alen = data:byte(pos + 1) * 256 + data:byte(pos + 2)
			vpos = pos + 4
			if alen < 4 or pos + alen - 1 > length then return nil end
		else
			if pos + 1 > length then return nil end
			alen = data:byte(pos + 1)
			vpos = pos + 2
			if alen < 2 or pos + alen - 1 > length then return nil end
		end
		attrs[#attrs + 1] = {
			type = atype,
			value = data:sub(vpos, pos + alen - 1),
			vpos = vpos,
		}
		pos = pos + alen
	end

	return {
		code = data:byte(1),
		id = data:byte(2),
		length = length,
		auth = data:sub(5, 20),
		attrs = attrs,
	}
end

-- verify the Message-Authenticator: HMAC-MD5(secret, packet) over the packet
-- with the attribute value zeroed. Requests without a valid one are dropped
-- without an answer.
function radius.verify(pkt, data, secret)
	local ma
	for _, attr in ipairs(pkt.attrs) do
		if attr.type == ATTR_MESSAGE_AUTHENTICATOR and #attr.value == 16 then
			ma = attr
		end
	end
	if ma == nil then
		return nil, 'no message-authenticator'
	end
	local zeroed = data:sub(1, ma.vpos - 1) .. string.rep('\0', 16) ..
		data:sub(ma.vpos + 16)
	if hmac_md5(secret, zeroed) ~= ma.value then
		return nil, 'message-authenticator mismatch'
	end
	return true
end

-- the station the query is about: Calling-Station-Id, falling back to
-- User-Name. hostapd sends the bare MAC in both for a macaddr_acl=2 query, so
-- the order makes no difference to what this fleet asks today - but it does
-- to what it may ask next. With sae_password_radius=1 (the SAE-over-RADIUS
-- patches) hostapd puts the SAE Password Identifier in User-Name and leaves
-- the station in Calling-Station-Id, and a password identifier is chosen by
-- whoever is connecting. Reading User-Name first would let one shaped like
-- twelve hex characters name a *different* station and be answered with that
-- station's key. Calling-Station-Id is the access point's word for who is
-- asking; User-Name is the asker's. Take the access point's.
--
-- Other sources are tolerated by taking the first 12 hex characters.
-- Called-Station-Id is
-- "<bssid>:<ssid>" (add_common_radius_attr), so the event can be attributed
-- to the bss a controller knows.
-- Returns mac, bssid (12 lowercase hex), ssid, akm name, raw suite.
function radius.station(pkt)
	local user, csid, called, suite
	for _, attr in ipairs(pkt.attrs) do
		if attr.type == ATTR_USER_NAME then
			user = attr.value
		elseif attr.type == ATTR_CALLING_STATION_ID then
			csid = attr.value
		elseif attr.type == ATTR_CALLED_STATION_ID then
			called = attr.value
		elseif attr.type == ATTR_WLAN_AKM_SUITE and #attr.value == 4 then
			suite = tohex(attr.value)
		end
	end

	local mac
	for _, v in ipairs({ csid, user }) do
		if type(v) == 'string' then
			-- a mac is at most 17 characters ('aa:bb:cc:dd:ee:ff'); only the
			-- hex characters of that window count, so a user name like
			-- 'anna-00:11:22:33:44:55' cannot shift the address and one with
			-- a different shape fails closed instead of answering a wrong mac
			local hex = v:sub(1, 17):gsub('[^%x]', ''):lower()
			if #hex == 12 then
				mac = hex
				break
			end
		end
	end

	local bssid, ssid
	if type(called) == 'string' then
		local hex = called:gsub('[^%x]', ''):lower()
		if #hex >= 12 then
			bssid = hex:sub(1, 12)
		end
		local colon = called:find(':', 1, true)
		if colon ~= nil then
			ssid = called:sub(colon + 1)
		end
	end

	-- the raw User-Name comes back too: for a macaddr_acl=2 query it is the
	-- station's own address and says nothing new, but with
	-- sae_password_radius=1 it is the SAE Password Identifier, and only the
	-- caller can tell which of the two it is looking at
	return mac, bssid, ssid,
		AKM_NAMES[suite] or suite and ('0x' .. suite) or nil, suite, user
end

-- encrypt a Tunnel-Password value: tag, two byte salt, then the plaintext
-- ([length byte][psk], zero padded to 16) with the first block XORed against
-- MD5(secret + request authenticator + salt) and every later block against
-- MD5(secret + previous ciphertext block). This is the scheme
-- radius_msg_get_tunnel_password() decrypts.
function radius.tunnel_password(psk, secret, req_auth)
	local salt = string.char(math.random(0, 255), math.random(0, 255))
	local plain = string.char(#psk) .. psk
	local pad = (16 - (#plain % 16)) % 16
	if pad > 0 then
		plain = plain .. string.rep('\0', pad)
	end

	local cipher = {}
	local prev = md5(secret .. req_auth .. salt)
	for i = 1, #plain, 16 do
		cipher[#cipher + 1] = xor_str(prev, plain:sub(i, i + 15))
		prev = md5(secret .. cipher[#cipher])
	end

	return '\0' .. salt .. table.concat(cipher)
end

-- build a signed response (Access-Accept 2 / Access-Reject 3) to a request.
-- The Message-Authenticator is computed over the packet with the request
-- authenticator in place and the attribute value zeroed, then the response
-- authenticator MD5(code+id+length+request auth+attributes+secret) takes
-- over the authenticator field — the radius_msg_finish_srv() order.
function radius.build_response(req, code, attrs, secret)
	local chunks = {}
	for _, attr in ipairs(attrs) do
		chunks[#chunks + 1] = string.char(attr.type, #attr.value + 2) .. attr.value
	end
	local body = table.concat(chunks)
	local ma_attr = string.char(ATTR_MESSAGE_AUTHENTICATOR, 18) ..
		string.rep('\0', 16)
	local length = 20 + #body + 18

	local header = string.char(code, req.id,
		math.floor(length / 256), length % 256)
	local ma = hmac_md5(secret, header .. req.auth .. body .. ma_attr)
	local ma_val = string.char(ATTR_MESSAGE_AUTHENTICATOR, 18) .. ma
	local resp_auth = md5(header .. req.auth .. body .. ma_val .. secret)

	return header .. resp_auth .. body .. ma_val
end

-- strip uci quoting off a value: 'x', "x" or a bare word. Escapes are the
-- uci ones (backslash before the quote or a backslash).
local cjson = require('cjson')

local function readfile(path)
	local f = path and io.open(path, 'rb')
	if f == nil then
		return nil
	end
	local content = f:read('*a')
	f:close()
	return content
end

local function uci_unquote(v)
	if v:sub(1, 1) == "'" and v:sub(-1) == "'" then
		return v:sub(2, -2):gsub("\\'", "'"):gsub('\\\\', '\\')
	elseif v:sub(1, 1) == '"' and v:sub(-1) == '"' then
		return v:sub(2, -2):gsub('\\"', '"'):gsub('\\\\', '\\')
	end
	return v
end

-- the key store, read from the uci wireless config: every wifi-station
-- section becomes one key entry under each of its macs (the section name is
-- the key id), or the wildcard entry when it has no mac list. Sections
-- without a key or a mac that is no mac address are skipped and counted.
function radius.load_wireless(path)
	-- keys are stored per wireless interface (uci section name): a station
	-- asking on one SSID must never get the key of another. The lookup side
	-- maps the request's bssid to the section name (bss_iface callback).
	local store = { ifaces = {}, errors = 0, error_lines = {} }
	local lineno = 0
	local f = io.open(path, 'r')
	if f == nil then
		return store
	end

	local section_type, section_name, section_line
	local key, vid, macs, iface
	local function commit()
		if section_type ~= 'wifi-station' then
			return
		end
		if section_name == nil or section_name == '' or key == nil
				or #key < 8 or #key > 64
				or iface == nil or iface == '' then
			store.errors = store.errors + 1
			store.error_lines[#store.error_lines + 1] = string.format(
				'line %d: section %q, keylen=%d, iface=%s',
				section_line or 0, section_name or '<anonymous>',
				key and #key or -1, tostring(iface or ''))
			return
		end
		local entry = { psk = key, name = section_name }
		if vid ~= nil and vid ~= '' then
			entry.vid = vid
		end
		local bucket = radius.bucket(store, iface)
		if macs == nil or #macs == 0 then
			bucket.wildcards[#bucket.wildcards + 1] = entry
			radius.index_name(bucket, entry, nil)
			return
		end
		for _, mac in ipairs(macs) do
			local hex = mac:gsub('[^%x]', ''):lower()
			if hex == '000000000000' then
				bucket.wildcards[#bucket.wildcards + 1] = entry
				radius.index_name(bucket, entry, nil)
			elseif #hex == 12 then
				bucket.entries[hex] = entry
				radius.index_name(bucket, entry, hex)
			else
				store.errors = store.errors + 1
				store.error_lines[#store.error_lines + 1] = string.format(
					'line %d: bad mac %q in section %s',
					section_line or 0, mac, section_name or '<anonymous>')
			end
		end
	end

	for line in f:lines() do
		lineno = lineno + 1
		line = line:gsub('^%s+', ''):gsub('%s+$', '')
		if line == '' or line:sub(1, 1) == '#' then
			-- skip
		elseif line:sub(1, 7) == 'config ' then
			commit()
			section_line = lineno
			section_type, section_name = line:match('^config%s+(%S+)%s+(.+)$')
			if section_type == nil then
				section_type = line:match('^config%s+(%S+)%s*$')
			end
			section_name = section_name ~= nil and uci_unquote(section_name) or nil
			key, vid, macs, iface = nil, nil, nil, nil
		else
			local kind, what, value = line:match('^(%S+)%s+(%S+)%s+(.+)$')
			if kind ~= nil and section_type == 'wifi-station' then
				value = uci_unquote(value)
				if what == 'key' then
					key = value
				elseif what == 'vid' then
					vid = value
				elseif what == 'mac' and (kind == 'list' or kind == 'option') then
					macs = macs or {}
					macs[#macs + 1] = value
				elseif what == 'iface' and (kind == 'list' or kind == 'option') then
					if iface == nil then
						iface = value
					end
				end
			end
		end
	end
	commit()
	f:close()
	return store
end

-- Index one key under its name, and remember which stations it is bound to.
--
-- The name is what the controller calls keyid, and it is also what an SAE
-- Password Identifier is: hostapd with sae_password_radius=1 asks "what is the
-- password called X", where X is a name out of this very store. Without this
-- index the store can only answer "what may this MAC use".
--
-- The binding is recorded because handing a key out by name has to stay as
-- narrow as handing it out by address. An entry that names no station is the
-- onboarding case and may go to whoever asks for it by name; one that is bound
-- belongs to those stations and to nobody else.
function radius.index_name(bucket, entry, hex)
	if type(entry.name) ~= 'string' or entry.name == '' then
		return
	end
	if hex ~= nil then
		entry.bound = entry.bound or {}
		entry.bound[hex] = true
	end
	bucket.by_name[entry.name] = entry
end

-- Is this User-Name a Password Identifier, or is it just the station again?
--
-- hostapd with sae_password_radius=1 puts the SAE Password Identifier in
-- User-Name and leaves the station in Calling-Station-Id. In a macaddr_acl=2
-- query it puts the same address in both. So the two differing is the whole
-- signal, and there is no new attribute to look for - deliberate on the
-- hostapd side, because hostap has no private enterprise number.
--
-- Returns the identifier, or nil when User-Name is only saying the address
-- again (or saying nothing).
function radius.password_id(user, mac)
	if type(user) ~= 'string' or user == '' then
		return nil
	end
	local as_mac = user:sub(1, 17):gsub('[^%x]', ''):lower()
	if #as_mac == 12 and as_mac == mac then
		return nil
	end
	return user
end

-- May the key called `name` go to the station `mac`?
--
-- Returns entry, nil on yes; nil, reason on no. A key that names no station is
-- the onboarding case - the identifier is the only thing its holder has, and
-- answering is the point. A key that is bound belongs to those stations and to
-- nobody else: a password identifier is chosen by whoever is connecting, so
-- answering by name alone would hand a station's key to anyone who guessed it.
function radius.named_key(bucket, name, mac)
	if bucket == nil or bucket.by_name == nil then
		return nil, 'no keys for this bss'
	end
	local entry = bucket.by_name[name]
	if entry == nil then
		return nil, 'unknown password id'
	end
	if entry.bound ~= nil and (mac == nil or not entry.bound[mac]) then
		return nil, 'belongs to another station'
	end
	return entry, nil
end

function radius.bucket(store, iface)
	local bucket = store.ifaces[iface]
	if bucket == nil then
		bucket = { entries = {}, wildcards = {}, by_name = {} }
		store.ifaces[iface] = bucket
	end
	return bucket
end

-- The key store as the controller ships it: one complete, versioned key set
-- per ssid, written to opts.keystore by radius.apply_keys(). It replaces the
-- wifi-station sections (and with them wpa_psk_file/sae_password_file, which
-- wifi-scripts only renders when such sections exist) — hostapd then takes
-- every key from the Access-Accept, for WPA2 and SAE alike.
--
--   { "ssids": { "<ssid>": { "version": 12, "ifaces": ["<wifi-iface section>", ...],
--       "network_key": "optional passphrase offered to unknown stations",
--       "keys": [ { "name": "ppsk_<ssid id>_<row id>", "mac": "aabbccddeeff" | null,
--                   "psk": "...", "vid": "7" | null }, ... ] } } }
function radius.read_keystore(path)
	local content = readfile(path)
	if content == nil then
		return nil
	end
	local ok, data = pcall(cjson.decode, content)
	if not ok or type(data) ~= 'table' or type(data.ssids) ~= 'table' then
		return nil
	end
	return data
end

function radius.load_keystore(data)
	local store = { ifaces = {}, errors = 0, error_lines = {}, versions = {} }
	for ssid, set in pairs(data.ssids) do
		store.versions[ssid] = set.version
		local ifaces = type(set.ifaces) == 'table' and set.ifaces or {}
		for _, iface in ipairs(ifaces) do
			local bucket = radius.bucket(store, iface)
			bucket.ssid = ssid
			-- hostapd does not send WLAN-AKM-Suite in the mac acl
			-- query (measured: akm=nil for both psk and sae bss), so
			-- whether this network speaks SAE has to come from the
			-- controller, which knows the encryption
			bucket.sae = set.sae and true or false
			if type(set.network_key) == 'string' and #set.network_key >= 8 then
				bucket.network_key = set.network_key
			end
			for _, k in ipairs(type(set.keys) == 'table' and set.keys or {}) do
				local psk = type(k.psk) == 'string' and k.psk or ''
				if #psk < 8 or #psk > 64 or type(k.name) ~= 'string' then
					store.errors = store.errors + 1
					store.error_lines[#store.error_lines + 1] = string.format(
						'%s: key %s unusable (len %d)', ssid, tostring(k.name), #psk)
				else
					local entry = { psk = psk, name = k.name }
					if k.vid ~= nil and k.vid ~= cjson.null and tostring(k.vid) ~= '' then
						entry.vid = tostring(k.vid)
					end
					local mac = type(k.mac) == 'string' and k.mac:gsub('[^%x]', ''):lower() or ''
					if #mac == 12 and mac ~= '000000000000' then
						bucket.entries[mac] = entry
						radius.index_name(bucket, entry, mac)
					else
						bucket.wildcards[#bucket.wildcards + 1] = entry
						radius.index_name(bucket, entry, nil)
					end
				end
			end
		end
	end
	return store
end

-- Both sources merged, the keystore winning for the interfaces it names.
-- Not either/or on purpose: an access point carries migrated networks (keys
-- from the controller's keystore) next to ones that still keep their keys in
-- wifi-station sections, and a keystore for one ssid must never blank out
-- the others.
function radius.load_store(opts)
	local store = radius.load_wireless(opts.wifi_config)
	store.source = 'wireless'
	local data = radius.read_keystore(opts.keystore)
	if data ~= nil then
		local ks = radius.load_keystore(data)
		store.source = 'keystore+wireless'
		store.versions = ks.versions
		store.ks_ifaces = {}
		for iface, bucket in pairs(ks.ifaces) do
			store.ifaces[iface] = bucket
			store.ks_ifaces[iface] = true
		end
		store.errors = store.errors + ks.errors
		for _, line in ipairs(ks.error_lines) do
			store.error_lines[#store.error_lines + 1] = line
		end
	end
	return store
end

-- merge one ssid's set into the keystore file (tmp + rename), rebuild the
-- store from it and answer with the versions now in force. payload is the
-- per-ssid object from the format above plus its "ssid" name; a payload
-- with keys == null removes the ssid.
function radius.apply_keys(server, payload)
	if type(payload) ~= 'table' or type(payload.ssid) ~= 'string' or payload.ssid == '' then
		return nil, 'ssid missing'
	end
	local path = server.opts.keystore
	if path == nil or path == '' then
		return nil, 'radius_keystore not set'
	end
	local data = radius.read_keystore(path) or { ssids = {} }
	if payload.keys == nil or payload.keys == cjson.null then
		data.ssids[payload.ssid] = nil
	else
		data.ssids[payload.ssid] = {
			version = payload.version,
			ifaces = payload.ifaces,
			sae = payload.sae,
			network_key = payload.network_key,
			keys = payload.keys,
		}
	end
	-- The directory is there on every run after the first, and mkdir -p forks
	-- a shell for 2 ms to find that out. Try the write, make the directory
	-- only when it actually fails.
	local f, err = io.open(path .. '.tmp', 'w')
	if f == nil then
		local dir = path:match('^(.*)/[^/]+$')
		if dir ~= nil then
			os.execute(string.format("mkdir -p '%s'", dir))
			f, err = io.open(path .. '.tmp', 'w')
		end
	end
	if f == nil then
		return nil, 'cannot write keystore: ' .. tostring(err)
	end
	f:write(cjson.encode(data))
	f:close()
	-- the file carries secrets; keep it to root before it gets its name
	os.execute(string.format("chmod 600 '%s.tmp' && mv '%s.tmp' '%s'", path, path, path))

	-- The running store is what answers RADIUS, and RADIUS is what decides —
	-- the file is only there so a reboot does not start empty. So put the keys
	-- into memory directly instead of writing them out and reading everything
	-- back: load_store() re-parses the whole /etc/config/wireless, 14 ms of it,
	-- for keys we are already holding.
	--
	-- Removing an ssid is the exception. Its interfaces have to fall back to
	-- whatever the wifi-station sections say, and only the wireless config
	-- knows that, so it takes the long way. The same goes for an interface
	-- set that changed: the in-place merge below only overwrites buckets, it
	-- never drops one, and a bucket left behind would keep answering its bss
	-- with stale keys.
	local store
	if payload.keys == nil or payload.keys == cjson.null or server.store == nil
		or type(server.store.ifaces) ~= 'table' then
		store = radius.load_store(server.opts)
	else
		local ks = radius.load_keystore(data)
		local ks_ifaces = {}
		for iface in pairs(ks.ifaces) do
			ks_ifaces[iface] = true
		end
		local changed = server.store.ks_ifaces == nil
		if not changed then
			for iface in pairs(server.store.ks_ifaces) do
				if ks_ifaces[iface] == nil then
					changed = true
					break
				end
			end
			for iface in pairs(ks_ifaces) do
				if server.store.ks_ifaces[iface] == nil then
					changed = true
					break
				end
			end
		end
		if changed then
			store = radius.load_store(server.opts)
		else
			store = server.store
			for iface, bucket in pairs(ks.ifaces) do
				store.ifaces[iface] = bucket
			end
			store.versions = ks.versions
			store.source = 'keystore+wireless'
			store.error_lines = ks.error_lines or {}
			store.ks_ifaces = ks_ifaces
		end
	end
	server.store = store
	server.store_digest = nil
	print(string.format('radius keystore: %s at version %s, %d keys in store (%s)',
		payload.ssid, tostring(payload.version), radius.store_count(store), store.source))
	return { versions = store.versions or {}, keys = radius.store_count(store),
		errors = store.error_lines }
end

function radius.store_count(store)
	local n = 0
	for _, bucket in pairs(store.ifaces) do
		n = n + #bucket.wildcards
		for _ in pairs(bucket.entries) do
			n = n + 1
		end
	end
	return n
end

-- process one datagram: verify, decide, answer, report.
-- One place for "something went wrong in here", so the controller sees the
-- newest one instead of nothing. Not a log: a log on an access point is read
-- when somebody already suspects this server.
function radius.note_error(server, message)
	server.stats.errors = server.stats.errors + 1
	server.stats.last_error = { ts = server.gettime(), message = tostring(message) }
end

function radius.handle(server, data, ip, port)
	local t0 = server.gettime()
	local function report(event)
		-- every path through handle() reports exactly once, so this is the
		-- one place that sees each request end. The duration goes into the
		-- event as well: the controller stores it as duration_ms, which was
		-- NULL for every agent answered request until now.
		local ms = (server.gettime() - t0) * 1000
		local st = server.stats
		st.time_n = st.time_n + 1
		st.time_sum = st.time_sum + ms
		if ms > st.time_max then st.time_max = ms end
		event.ms = ms
		st.last = { ts = event.ts, mac = event.mac, ssid = event.ssid,
			decision = event.decision, reason = event.reason,
			key = event.key, key_source = event.key_source, ms = ms }
		if server.opts.onevent ~= nil then
			-- the answer is already written: a hiccup in the event sink
			-- (mqtt reconnect, serialisation) must not kill the server
			local ok, err = pcall(server.opts.onevent, event)
			if not ok then
				radius.note_error(server, 'event sink: ' .. tostring(err))
				-- diagnostic: the caller discards this, so a failing
				-- event sink stays invisible without it
				local df = io.open('/tmp/radius-events.log', 'a')
				if df then
					df:write(string.format('onevent error: %s\n', tostring(err)))
					df:close()
				end
			end
		end
	end

	local pkt = radius.parse(data)
	if pkt == nil or pkt.code ~= 1 then
		server.stats.dropped = server.stats.dropped + 1
		return report({
			decision = 'drop',
			reason = pkt == nil and 'malformed packet' or 'not an access-request',
			src = ip,
			ts = server.gettime(),
		})
	end

	local ok, reason = radius.verify(pkt, data:sub(1, pkt.length), server.secret)
	if not ok then
		server.stats.dropped = server.stats.dropped + 1
		return report({
			decision = 'drop',
			reason = reason,
			src = ip,
			ts = server.gettime(),
		})
	end

	local mac, bssid, ssid, akm, suite, user = radius.station(pkt)
	-- resolve the wireless interface the request came from and look the key
	-- up inside it only: a station asking on one SSID must never get the key
	-- of another (the wildcard of the wrong SSID was answering fleet wide)
	local iface = nil
	if bssid ~= nil and server.opts.bss_iface ~= nil then
		iface = server.opts.bss_iface(bssid)
	end
	local bucket = iface ~= nil and server.store.ifaces[iface] or nil

	-- Exactly one key goes out, in this order: the station's own key, then a
	-- wildcard key, then the network passphrase.
	--
	-- One, because a second one is at best dead weight and at worst hides the
	-- first. hostapd's sae_get_password() walks sta->psk but breaks on the
	-- first passphrase unless use_sta_psk is set, and use_sta_psk is only set
	-- from the ucode sta_auth hook, which the RADIUS ACL path never reaches:
	--
	--     for (psk = sta->psk; psk; psk = psk->next) {
	--             if (!psk->is_passphrase) continue;
	--             password = psk->passphrase;
	--             if (!sta->use_sta_psk) break;
	--
	-- Measured 2026-08-21 on kalclients: a station was sent its own key plus
	-- the network key, hostapd tried only the first, the confirm failed and
	-- the station walked away — which the access point reports as nothing more
	-- helpful than "did not acknowledge authentication response". WPA2 would
	-- iterate the list, but sending one key there too keeps both paths
	-- answering the same thing, which is the whole point of the key store.
	--
	-- SAE needs a passphrase: a 64 hex raw psk (what WPS enrolment produces)
	-- is a key for WPA2 only, so it is skipped rather than handed to a station
	-- that cannot use it.
	local sae = suite == '000fac08' or suite == '000fac09'
		or (bucket ~= nil and bucket.sae == true)
	local function usable(e)
		return e ~= nil and not (sae and #e.psk == 64 and e.psk:match('^%x+$'))
	end

	-- Is this a Password Identifier query rather than a MAC one?
	--
	-- hostapd with sae_password_radius=1 puts the SAE Password Identifier in
	-- User-Name and leaves the station in Calling-Station-Id. In a
	-- macaddr_acl=2 query it puts the same address in both. So the two
	-- differing is the whole signal, and there is no new attribute to look
	-- for - which was deliberate on the hostapd side: hostap has no PEN.
	local pw_id = bucket ~= nil and radius.password_id(user, mac) or nil

	local entry, from, wildcards = nil, nil, {}
	if pw_id ~= nil then
		-- Answered from the name and from nothing else. hostapd asked what the
		-- password called X is; a wildcard key or the network passphrase is
		-- not an answer to that question, and offering one would hand out a
		-- credential nobody asked for.
		local named, why = radius.named_key(bucket, pw_id, mac)
		if named ~= nil and not usable(named) then
			named, why = nil, 'not usable for SAE'
		end
		if named == nil then
			print(string.format(
				'radius-error password id %q not answered for %s on ssid=%s: %s',
				pw_id, mac or '-', tostring(ssid or '-'), why or '?'))
		else
			entry, from = named, 'password-id'
		end
	elseif mac ~= nil and bucket ~= nil then
		if usable(bucket.entries[mac]) then
			entry, from = bucket.entries[mac], 'per-mac'
		else
			for _, e in ipairs(bucket.wildcards) do
				if usable(e) then
					wildcards[#wildcards + 1] = e
				end
			end
			if wildcards[1] ~= nil then
				entry, from = wildcards[1], 'wildcard'
			elseif bucket.network_key ~= nil then
				entry, from = { psk = bucket.network_key, name = 'network' }, 'network'
			end
		end
	end

	-- More than one unbound key on the same network is not decidable here:
	-- only one can be offered, so the others cannot be enrolled until this one
	-- binds itself. Say so loudly — in the log and, through the event, to the
	-- controller, which is the only place that can resolve it.
	local ambiguous = (from == 'wildcard') and #wildcards > 1 or false
	if ambiguous then
		local names = {}
		for _, e in ipairs(wildcards) do
			names[#names + 1] = tostring(e.name or '?')
		end
		print(string.format(
			'radius-error %d unbound keys on ssid=%s, only %s can be offered to %s — '
			.. 'the others cannot enrol until it binds: %s',
			#wildcards, tostring(ssid or '-'), tostring(entry.name or '?'),
			mac or '-', table.concat(names, ' ')))
	end

	if entry ~= nil then
		-- the key id and origin are logged, the psk itself is not: it is a
		-- credential, and syslog is forwarded off the device more often than
		-- anyone remembers
		print(string.format('radius-debug key=%s from=%s mac=%s bssid=%s ssid=%s akm=%s%s',
			tostring(entry.name or '?'), from, mac or '-', bssid or '-', ssid or '-',
			tostring(akm), ambiguous and (' AMBIGUOUS(' .. #wildcards .. ')') or ''))
	end

	local own_vlan, answered_vlan, vlan_suppressed
	local code, attrs = 3, {}
	if entry ~= nil then
		code = 2
		-- one Tunnel-Password, see the decision above
		attrs[#attrs + 1] = {
			type = ATTR_TUNNEL_PASSWORD,
			value = radius.tunnel_password(entry.psk, server.secret, pkt.auth),
		}
		-- Which key answered, by name. hostapd reads User-Name out of an
		-- Access-Accept into sta->identity (ieee802_11_auth.c, the ACL reply
		-- handler) and reports it in STA info, so this is what makes
		-- "identity=660-heinzpixel" appear next to a station instead of
		-- nothing. Without it the field the hostapd patch adds stays empty and
		-- looks like the patch is broken, which it is not.
		--
		-- 253 is the most an attribute can carry; a key name is far shorter,
		-- but a truncated one would be a wrong answer rather than a long one.
		if type(entry.name) == 'string' and entry.name ~= ''
			and #entry.name <= 253 then
			attrs[#attrs + 1] = { type = ATTR_USER_NAME, value = entry.name }
		end
		-- the vlan trio radius_msg_get_vlanid() decodes back — unless the
		-- station lives on the bss's own vlan, then hostapd would only put
		-- it back where it already is
		if entry.vid ~= nil and bssid ~= nil and server.opts.bss_vlan ~= nil then
			own_vlan = server.opts.bss_vlan(bssid)
		end
		if entry.vid ~= nil and own_vlan ~= entry.vid then
			attrs[#attrs + 1] = { type = ATTR_TUNNEL_TYPE, value = tunnel_int24(13) }
			attrs[#attrs + 1] = { type = ATTR_TUNNEL_MEDIUM_TYPE, value = tunnel_int24(6) }
			attrs[#attrs + 1] = { type = ATTR_TUNNEL_PRIVATE_GROUP_ID,
				value = '\0' .. entry.vid }
			answered_vlan = entry.vid
		elseif entry.vid ~= nil then
			vlan_suppressed = true
		end
	end

	server.sock:sendto(radius.build_response(pkt, code, attrs, server.secret),
		ip, port)

	if code == 2 then
		server.stats.accepted = server.stats.accepted + 1
	else
		server.stats.rejected = server.stats.rejected + 1
	end
	report({
		decision = code == 2 and 'accept' or 'reject',
		reason = entry == nil and 'no key for this station' or nil,
		mac = mac,
		bssid = bssid,
		ssid = ssid,
		akm = akm,
		akm_suite = suite,
		key = entry and entry.name or nil,
		key_source = from or nil,
		-- the controller is the only place that can resolve two unbound keys
		-- competing for the same station, so the count travels with the event
		unbound_keys = ambiguous and #wildcards or nil,
		vid = entry and entry.vid or nil,
		vlan = answered_vlan or nil,
		vlan_suppressed = vlan_suppressed or nil,
		src = ip,
		ts = server.gettime(),
	})
end

-- drain whatever is queued on the socket, capped like the control channel
-- monitors so a burst cannot starve the rest of the uloop
function radius.step(server)
	for _ = 1, 32 do
		local data, ip, port = server.sock:receivefrom(4096)
		if data == nil then
			return
		end
		radius.handle(server, data, ip, port)
	end
end

-- re-read the store when the config content changed; the digest keeps the
-- common unchanged case to one read and one md5 per check. Returns true when
-- the store was replaced (the caller refreshes its bss vlan map then).
function radius.reload(server)
	-- uloop timers are one-shot: without re-arming, the digest would run
	-- exactly once after the start and every later key change made through
	-- the uci command line (no hostapd-auth event) would go unnoticed
	if server.timer ~= nil then
		server.timer:set((server.opts.reload_interval or 10) * 1000)
	end
	-- Both files are watched: apply_keys() loads the keystore right away,
	-- but a key change made through the uci command line (or a keystore
	-- written by hand) has no event and would go unnoticed otherwise.
	local content = readfile(server.opts.wifi_config)
	if content == nil then
		return false
	end
	local digest = tohex(md5(content .. '\0' ..
		(readfile(server.opts.keystore) or '')))
	if digest == server.store_digest then
		return false
	end
	local next_store = radius.load_store(server.opts)
	-- bad sections are skipped one by one (the loaders count them); an
	-- empty result on top of a filled store is the torn write case
	if radius.store_count(next_store) == 0 and radius.store_count(server.store) > 0 then
		radius.note_error(server, 'key sources unreadable, kept the previous store')
		print('radius key sources unreadable right now, keeping the previous store')
		return false
	end
	for i, detail in ipairs(next_store.error_lines) do
		if i > 5 then
			print(string.format('radius bad section: ... and %d more', #next_store.error_lines - 5))
			break
		end
		print('radius bad section (skipped): ' .. detail)
	end
	if #next_store.error_lines > 0 then
		radius.note_error(server, string.format('%d unusable key section(s), newest: %s',
			#next_store.error_lines, next_store.error_lines[1]))
	end
	server.store_digest = digest
	server.store = next_store
	server.stats.reloads = server.stats.reloads + 1
	server.stats.last_reload = server.gettime()
	print(string.format('radius keys reloaded: %d keys (%s)',
		radius.store_count(server.store), next_store.source))
	return true
end

-- start the server on udp/1812 (or opts.port), bound to every address, never
-- blocking the uloop. Requires opts.secret and opts.wifi_config;
-- opts.onevent receives accept/reject/drop reports, opts.reload_interval is
-- the config re-read timer in seconds (0 disables it).
function radius.start(opts)
	local socket = require('socket')
	local uloop = require('uloop')

	if opts == nil or opts.secret == nil or opts.secret == '' then
		return nil, 'radius_secret not set'
	end
	if opts.wifi_config == nil or opts.wifi_config == '' then
		return nil, 'radius_wifi_config not set'
	end

	local sock = socket.udp()
	sock:setoption('reuseaddr', true)
	-- LuaSocket udp objects have no bind() — binding goes through
	-- setsockname (verified on the fleet's LuaSocket build)
	-- loopback unless told otherwise: hostapd asks at 127.0.0.1, and every
	-- packet from elsewhere would cost a pure lua hmac in the main loop
	local ok, err = sock:setsockname(opts.bind or '127.0.0.1', opts.port or 1812)
	if not ok then
		pcall(function() sock:close() end)
		return nil, 'bind failed: ' .. tostring(err)
	end
	sock:settimeout(0)

	local server = {
		sock = sock,
		opts = opts,
		secret = opts.secret,
		store = radius.load_store(opts),
		-- Everything a controller can ask about this server without a
		-- second round trip. The counters are cheap; what earns its place
		-- is last_error, because a radius server that answers nothing looks
		-- exactly like one nobody asked, and the difference decides whether
		-- somebody has to drive out to the site.
		stats = { accepted = 0, rejected = 0, dropped = 0, errors = 0,
			reloads = 0, started = socket.gettime(),
			time_n = 0, time_sum = 0, time_max = 0 },
		gettime = socket.gettime,
	}
	server.store_digest = tohex(md5((readfile(opts.wifi_config) or '') .. '\0' ..
		(readfile(opts.keystore) or '')))
	-- guarded: every RADIUS packet hostapd sends arrives here, parsed from
	-- the wire. A throw would end uloop and take the whole agent with it, and
	-- an access point whose RADIUS server is gone admits nobody.
	server.ufd = uloop.fd_add(sock, guard.wrap('radius.step', function()
		radius.step(server)
	end), uloop.ULOOP_READ)
	if server.ufd == nil then
		pcall(function() sock:close() end)
		return nil, 'uloop fd_add failed'
	end
	if (opts.reload_interval or 10) > 0 then
		-- opts.tick lets the host hook its own periodic work (bss map
		-- refresh) onto the same timer; it must call radius.reload itself
		-- guarded WITH a recover: this timer is re-armed inside reload()
		-- (radius.reload, the server.timer:set there), so a throw before that
		-- point would stop the reload cycle for good and the key store would
		-- silently stop following the controller.
		server.timer = uloop.timer(guard.wrap('radius.reload', function()
			if opts.tick ~= nil then opts.tick() else radius.reload(server) end
		end, function()
			if server.timer ~= nil then
				server.timer:set((opts.reload_interval or 10) * 1000)
			end
		end), (opts.reload_interval or 10) * 1000)
	end

	return server
end

-- What the controller shows on its RADIUS page. Flat on purpose: it is read
-- by a template, and a template that has to reach three levels deep gets the
-- reaching wrong on the day the field is missing.
function radius.status(server)
	local st = server.stats
	local versions = {}
	for name, v in pairs(server.store.versions or {}) do versions[name] = v end
	return {
		running = true,
		bind = server.opts.bind or '127.0.0.1',
		port = server.opts.port or 1812,
		started = st.started,
		reload_interval = server.opts.reload_interval or 10,
		store = {
			source = server.store.source,
			keys = radius.store_count(server.store),
			ssids = versions,
			reloads = st.reloads,
			last_reload = st.last_reload,
		},
		stats = {
			accepted = st.accepted,
			rejected = st.rejected,
			dropped = st.dropped,
			errors = st.errors,
			requests = st.time_n,
			avg_ms = st.time_n > 0 and (st.time_sum / st.time_n) or nil,
			max_ms = st.time_n > 0 and st.time_max or nil,
		},
		last = st.last,
		last_error = st.last_error,
	}
end

function radius.stop(server)
	if server.timer ~= nil then
		pcall(function() server.timer:cancel() end)
		server.timer = nil
	end
	if server.ufd ~= nil then
		pcall(function() server.ufd:delete() end)
		server.ufd = nil
	end
	pcall(function() server.sock:close() end)
end

radius.md5 = md5
radius.hmac_md5 = hmac_md5
radius.tohex = tohex

return radius
