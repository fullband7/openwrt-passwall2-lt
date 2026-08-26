local api = require "luci.passwall2.api"
local appname = api.appname

m = Map(appname)
api.set_apply_on_parse(m)

m:append(Template(appname .. "/rule/rule_list"))

return m
