-- The SAE Password Identifier lookup, without hardware.
--
--   lua tests/sae-password-id.lua        (from the repository root)
--
-- hostapd with sae_password_radius=1 asks "what is the password called X",
-- where X is chosen by whoever is connecting. Everything asserted here is
-- about telling that question apart from "what may this MAC use", and about
-- not answering it with somebody else's key.
--
-- apman-radius pulls in md5 and cjson at load time, which is why the older
-- keystore test only runs on an access point. Neither is used by anything
-- below, so a stub is enough and the test runs anywhere lua does.
package.preload['md5'] = function()
	return { sum = function() return string.rep('\0', 16) end }
end
package.preload['cjson'] = function()
	return { null = setmetatable({}, { __tostring = function() return 'null' end }) }
end
package.path = 'files/usr/lib/lua/?.lua;' .. package.path
local R = require('apman-radius')

-- password_id: is User-Name the identifier, or the station saying its own
-- address again?
local MAC = 'aabbccddeeff'
assert(R.password_id('aa:bb:cc:dd:ee:ff', MAC) == nil, 'a macaddr_acl query names the station')
assert(R.password_id('aabbccddeeff', MAC) == nil, 'the bare form too')
assert(R.password_id('AA:BB:CC:DD:EE:FF', MAC) == nil, 'case does not make it an identifier')
assert(R.password_id('guest-week33', MAC) == 'guest-week33', 'an identifier is an identifier')
assert(R.password_id('ppsk_140_621', MAC) == 'ppsk_140_621', 'and so is a key name')
-- the hazard: an identifier shaped like a *different* address must not be
-- mistaken for "the station named itself" and slip through as a mac query
assert(R.password_id('001122334455', MAC) == '001122334455',
	'an address that is not this station is still an identifier')
assert(R.password_id('', MAC) == nil, 'nothing is not an identifier')
assert(R.password_id(nil, MAC) == nil, 'nor is nil')
print('1 password_id ok')

-- index_name: the store learns the names, and what each name is bound to
local bucket = R.bucket({ ifaces = {} }, 'wap-kc0')
assert(type(bucket.by_name) == 'table', 'a bucket carries a name index')

local free = { psk = 'onboardingpass', name = 'enrol-1' }
local bound = { psk = 'annaspassword', name = 'ppsk_140_621' }
R.index_name(bucket, free, nil)
R.index_name(bucket, bound, MAC)
assert(bucket.by_name['enrol-1'] == free, 'an unbound key is indexed')
assert(bucket.by_name['ppsk_140_621'] == bound, 'a bound one too')
assert(free.bound == nil, 'and the unbound one stays unbound')
assert(bound.bound[MAC] == true, 'while the bound one remembers its station')
R.index_name(bucket, { psk = 'x', name = '' }, nil)
assert(bucket.by_name[''] == nil, 'a nameless key is not indexed under nothing')
print('2 index_name ok')

-- named_key: who may have it
local e, why = R.named_key(bucket, 'enrol-1', MAC)
assert(e == free and why == nil, 'an unbound key goes to whoever asks by name')
e, why = R.named_key(bucket, 'enrol-1', 'ffffffffffff')
assert(e == free, 'that is the onboarding case, so any station may have it')

e, why = R.named_key(bucket, 'ppsk_140_621', MAC)
assert(e == bound and why == nil, 'a bound key goes to its own station')

-- the one that matters: guessing a name must not buy somebody else's key
e, why = R.named_key(bucket, 'ppsk_140_621', '001122334455')
assert(e == nil and why == 'belongs to another station', 'refused, got ' .. tostring(why))
e, why = R.named_key(bucket, 'ppsk_140_621', nil)
assert(e == nil, 'and refused when the station is unknown')

e, why = R.named_key(bucket, 'no-such-id', MAC)
assert(e == nil and why == 'unknown password id', 'an unknown name is not an answer')
e, why = R.named_key(nil, 'enrol-1', MAC)
assert(e == nil and why == 'no keys for this bss', 'and neither is a bss we hold nothing for')
print('3 named_key ok')

-- a key may be bound to more than one station
local shared = { psk = 'twodevices', name = 'ppsk_140_999' }
R.index_name(bucket, shared, MAC)
R.index_name(bucket, shared, '001122334455')
assert(R.named_key(bucket, 'ppsk_140_999', MAC) == shared, 'first station')
assert(R.named_key(bucket, 'ppsk_140_999', '001122334455') == shared, 'second station')
assert(R.named_key(bucket, 'ppsk_140_999', 'ffffffffffff') == nil, 'and nobody else')
print('4 several stations on one key ok')

print('sae-password-id tests passed')
