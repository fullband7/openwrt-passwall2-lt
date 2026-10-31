local api = require "luci.passwall2.api"
local func = api[arg[1]]
if type(func) == "function" then
	print(func(unpack(arg, 2)))
end
