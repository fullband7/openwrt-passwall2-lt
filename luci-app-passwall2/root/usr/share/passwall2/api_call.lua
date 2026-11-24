local api = require "luci.passwall2.api"
local allowed = {
	get_domain_from_url = true,
	is_ip = true,
	iprange = true,
	ip_or_mac = true
}
local name = arg[1]
local func = allowed[name] and api[name]
if type(func) == "function" then
	print(func(unpack(arg, 2)))
end
