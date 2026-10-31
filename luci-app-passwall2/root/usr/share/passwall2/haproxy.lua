#!/usr/bin/lua

local api = require ("luci.passwall2.api")
local appname = "passwall2"
local fs = api.fs
local uci = api.uci
local sys = api.sys

local log = api.log

local function gsub_safe(s)
	return (tostring(s or ""):gsub("%%", "%%%%"))
end

local function clean_token(s)
	return (tostring(s or ""):gsub("[^%w%.%-_:%[%]]", ""))
end

local function clean_secret(s)
	return (tostring(s or ""):gsub("[%s%c\"'\\#$]", ""))
end

local function get_ip_port_from(str)
	str = tostring(str or "")
	local host, port = str:match("^(.*)[:#](%d*)$")
	if not host then
		return str, ""
	end
	return host, port
end

local var = api.get_args(arg)
local haproxy_path = var["-path"]
local haproxy_conf = var["-conf"]
local haproxy_dns = (var["-dns"] or "119.29.29.29:53,223.5.5.5:53"):gsub("[^%w%.%-:#,%[%]]", "")

local cpu_thread = sys.exec('echo -n $(cat /proc/cpuinfo | grep "processor" | wc -l)') or "1"
local health_check_type = uci:get(appname, "@global_haproxy[0]", "health_check_type") or "tcp"
local health_check_inter = tonumber(uci:get(appname, "@global_haproxy[0]", "health_check_inter")) or 10
local console_port = tonumber(uci:get(appname, "@global_haproxy[0]", "console_port"))
if console_port and (console_port < 1 or console_port > 65535 or console_port % 1 ~= 0) then
	console_port = nil
end
local bind_local = uci:get(appname, "@global_haproxy[0]", "bind_local") or "0"
local bind_address = "0.0.0.0"
if bind_local == "1" then bind_address = "127.0.0.1" end

log(0, "HAProxy: ")
log(1, api.i18n.translatef("Console Port: %s", console_port or ""))
fs.mkdir(haproxy_path)
local haproxy_file = haproxy_path .. "/" .. haproxy_conf

local f_out = io.open(haproxy_file, "a")

local haproxy_config = [[
global
	daemon
	log         127.0.0.1 local2
	maxconn     60000
	stats socket  {{path}}/haproxy.sock
	nbthread {{nbthread}}
	external-check
	insecure-fork-wanted

defaults
	mode                    tcp
	log                     global
	option                  tcplog
	option                  dontlognull
	option http-server-close
	option                  redispatch
	retries                 2
	timeout http-request    10s
	timeout queue           1m
	timeout connect         10s
	timeout client          1m
	timeout server          1m
	timeout http-keep-alive 10s
	timeout check           10s
	maxconn                 3000

resolvers mydns
	resolve_retries       1
	timeout resolve       5s
	hold valid           600s
{{dns}}
]]

haproxy_config = haproxy_config:gsub("{{path}}", gsub_safe(haproxy_path))
haproxy_config = haproxy_config:gsub("{{nbthread}}", gsub_safe(cpu_thread))

local mydns = ""
local index = 0
string.gsub(haproxy_dns, '[^,]+', function(w)
	index = index + 1
	local s = w:gsub("#", ":")
	if not s:find(":") then
		s = s .. ":53"
	end
	mydns = mydns .. (index > 1 and "\n" or "") .. "	" .. string.format("nameserver dns%s %s", index, s)
end)
haproxy_config = haproxy_config:gsub("{{dns}}", gsub_safe(mydns))

f_out:write(haproxy_config)

local listens = {}

uci:foreach(appname, "haproxy_config", function(t)
	if t.enabled == "1" then
		local server_remark
		local server_address
		local server_port
		local lbss = t.lbss
		local listen_port = tonumber(t.haproxy_port) or 0
		local server_node = uci:get_all(appname, lbss)
		if server_node and server_node.address and server_node.port then
			server_address = clean_token(server_node.address)
			server_port = clean_token(server_node.port)
			server_remark = server_address .. ":" .. server_port
			t.origin_address = server_address
			t.origin_port = server_port
			if health_check_type == "passwall_logic" then
				if server_node.type ~= "Socks" then
					local new_port = tonumber(api.get_new_port())
					local config_file = string.format("haproxy_%s_%s.json", clean_token(t[".name"]), new_port)
					sys.call(string.format("/usr/share/%s/app.sh run_socks %s > /dev/null",
						appname,
						api.util.shellquote(string.format("flag=%s node=%s bind=%s socks_port=%s config_file=%s",
							new_port,
							clean_token(server_node[".name"]),
							"127.0.0.1",
							new_port,
							config_file
						))
					))
					server_address = "127.0.0.1"
					server_port = tostring(new_port)
				end
			end
		else
			server_address, server_port = get_ip_port_from(lbss)
			server_address = clean_token(server_address)
			server_port = clean_token(server_port)
			server_remark = server_address .. ":" .. server_port
			t.origin_address = server_address
			t.origin_port = server_port
		end
		if server_address ~= "" and tonumber(server_port) and listen_port > 0 and listen_port < 65536 then
			if not listens[listen_port] then
				listens[listen_port] = {}
			end
			t.server_remark = server_remark
			t.server_address = server_address
			t.server_port = server_port
			table.insert(listens[listen_port], t)
		else
			log(1, api.i18n.translate("Discard one obviously invalid node."))
		end
	end
end)

local sortTable = {}
for i in pairs(listens) do
	table.insert(sortTable, i)
end
table.sort(sortTable, function(a,b) return (a < b) end)

for _, port in ipairs(sortTable) do
	log(1, api.i18n.translatef("Entrance %s:%s", bind_address, port))

	f_out:write("\n" .. string.format([[
listen %s
	bind %s:%s
	mode tcp
	balance roundrobin
]], port, bind_address, port))

	if health_check_type == "passwall_logic" then
		f_out:write([[
	option external-check
	external-check command "/usr/share/passwall2/haproxy_check.sh"
]])
	end

	local count_M, count_B = 1, 1
	for _, o in ipairs(listens[port]) do
		local remark = clean_token(o.server_remark)

		if tostring(o.backup) ~= "1" then
			remark = "M" .. count_M .. "-" .. remark
			count_M = count_M + 1
		else
			remark = "B" .. count_B .. "-" .. remark
			count_B = count_B + 1
		end
		local server = o.server_address .. ":" .. o.server_port
		local server_conf = "server {{remark}} {{server}} weight {{weight}} {{resolvers}} check inter {{inter}} rise 1 fall 3 {{backup}}"
		server_conf = server_conf:gsub("{{remark}}", gsub_safe(remark))
		server_conf = server_conf:gsub("{{server}}", gsub_safe(server))
		server_conf = server_conf:gsub("{{weight}}", gsub_safe(tonumber(o.lbweight) or 1))
		local resolvers = "resolvers mydns"
		if api.is_ip(o.server_address) then
			resolvers = ""
		end
		server_conf = server_conf:gsub("{{resolvers}}", resolvers)
		server_conf = server_conf:gsub("{{inter}}", gsub_safe(health_check_inter .. "s"))
		server_conf = server_conf:gsub("{{backup}}", tostring(o.backup) == "1" and "backup" or "")

		f_out:write("	" .. server_conf .. "\n")

		if o.export ~= "0" then
			sys.call(". /usr/share/passwall2/utils.sh ; add_ip2route " .. api.util.shellquote(o.origin_address) .. " " .. api.util.shellquote(o.export))
		end

		log(2, api.i18n.translatef("Node: %s:%s, Weight: %s", o.origin_address, o.origin_port, o.lbweight))
	end
end

if console_port then
	local console_user = clean_secret(uci:get(appname, "@global_haproxy[0]", "console_user"))
	local console_password = clean_secret(uci:get(appname, "@global_haproxy[0]", "console_password"))
	f_out:write("\n" .. string.format([[
listen console
	bind %s:%s
	mode http
	stats refresh 30s
	stats uri /
]], bind_address, console_port))
	if console_user ~= "" and console_password ~= "" then
		f_out:write(string.format("\tstats auth %s:%s\n\tstats admin if TRUE\n", console_user, console_password))
	end
end

f_out:close()

if health_check_type == "passwall_logic" then
	local probeUrl = uci:get(appname, "@global_haproxy[0]", "health_probe_url") or ""
	if not probeUrl:match("^https?://[%w%.%-_:/%?=&%%~+@,;!*()%[%]#]+$") then
		probeUrl = "https://www.google.com/generate_204"
	end
	local f_url = io.open(haproxy_path .. "/Probe_URL", "w")
	f_url:write(probeUrl)
	f_url:close()
end
