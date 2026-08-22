-- What the key store has to do, asserted without hardware. Copy this file and
-- apman-radius.lua to /tmp on an access point and run:
--
--   lua /tmp/keystore-merge.lua
--
-- The one it exists for is case 2: a key set pushed for one network must not
-- take another network's keys with it. It did once, and every station whose
-- key still lived in a wifi-station section stopped being answered.
package.path='/tmp/?.lua;'..package.path
local R=require('apman-radius'); local cjson=require('cjson')
local function w(p,c) local f=io.open(p,'w'); f:write(c); f:close() end
-- a wireless config like the production one: kalclients keeps its keys in
-- wifi-station sections
w('/tmp/t-wireless', [[
config wifi-station 'ppsk_radio0_kc_1'
	list mac 'aa:bb:cc:dd:ee:01'
	option key 'oldstyle-key-1'
	option iface 'radio0_kalclients'

config wifi-station 'ppsk_broken'
	option key 'short'
	option iface 'radio0_kalclients'

config wifi-station 'ppsk_radio0_kc_wild'
	option key 'kalclients-shared'
	option iface 'radio0_kalclients'
]])
os.remove('/tmp/t-keys.json')
local opts={wifi_config='/tmp/t-wireless', keystore='/tmp/t-keys.json'}
local st=R.load_store(opts)
print('1 wireless only: source='..st.source..' count='..R.store_count(st)..' errors='..st.errors)
assert(st.ifaces['radio0_kalclients'].entries['aabbccddee01'].psk=='oldstyle-key-1')
assert(#st.ifaces['radio0_kalclients'].wildcards==1)
assert(st.errors==1, 'the broken section must be counted, not fatal')

-- now the controller ships a keystore for a DIFFERENT ssid
-- the fields radius.reload/note_error expect on a started server
local srv={opts=opts, store=st, stats={errors=0, reloads=0}, gettime=os.time}
local res,err=R.apply_keys(srv,{ssid='apmantest', version='v1',
  ifaces={'radio1_apmantest'}, network_key='netzwerkpassphrase',
  keys={{name='ppsk_9_1', mac='aa:bb:cc:dd:ee:02', psk='eigener-key-02'},
        {name='ppsk_9_2', mac=nil, psk='wildcard-key', vid='26'},
        {name='ppsk_9_3', mac='aa:bb:cc:dd:ee:03', psk=('a'):rep(64)}}})
assert(res, tostring(err))
print('2 after keystore: source='..srv.store.source..' count='..R.store_count(srv.store)..' ack='..cjson.encode(res.versions))
assert(srv.store.ifaces['radio0_kalclients'].entries['aabbccddee01'], 'MERGE: wireless ssid must survive a keystore push')
assert(srv.store.ifaces['radio1_apmantest'].entries['aabbccddee02'].psk=='eigener-key-02')
assert(srv.store.ifaces['radio1_apmantest'].network_key=='netzwerkpassphrase')
assert(res.versions['apmantest']=='v1')

-- reload must not lose either source
srv.store_digest=nil
R.reload(srv)
assert(srv.store.ifaces['radio0_kalclients'].entries['aabbccddee01'], 'reload lost the wireless ssid')
assert(srv.store.ifaces['radio1_apmantest'].entries['aabbccddee02'], 'reload lost the keystore ssid')
print('3 reload merged: source='..srv.store.source..' count='..R.store_count(srv.store))

-- moving the ssid to another interface must drop the old bucket: the
-- in-place merge only overwrites, a bucket left behind would keep
-- answering its bss with stale keys
res, err = R.apply_keys(srv, {ssid='apmantest', version='v2',
  ifaces={'radio1_apmantest2'}, keys={{name='ppsk_9_1', mac='aa:bb:cc:dd:ee:02', psk='eigener-key-02'}}})
assert(res, tostring(err))
assert(srv.store.ifaces['radio1_apmantest'] == nil, 'stale bucket survived an iface move')
assert(srv.store.ifaces['radio1_apmantest2'], 'new iface bucket missing')
assert(srv.store.ifaces['radio0_kalclients'], 'wireless ssid lost on iface move')

-- a version bump on the same interfaces keeps the in-place merge path
res, err = R.apply_keys(srv, {ssid='apmantest', version='v3',
  ifaces={'radio1_apmantest2'}, keys={{name='ppsk_9_1', mac='aa:bb:cc:dd:ee:02', psk='eigener-key-02'}}})
assert(res, tostring(err))
assert(srv.store.ifaces['radio1_apmantest2'], 'in-place merge lost the bucket')
assert(srv.store.ifaces['radio0_kalclients'], 'in-place merge lost the wireless ssid')

-- removing the ssid again
R.apply_keys(srv,{ssid='apmantest', keys=cjson.null})
assert(srv.store.ifaces['radio1_apmantest2']==nil, 'ssid not removed')
assert(srv.store.ifaces['radio0_kalclients'], 'removal took the other ssid with it')
print('4 removal ok, count='..R.store_count(srv.store))
print('KEYSTORE FILE:', io.open('/tmp/t-keys.json'):read('*a'))
