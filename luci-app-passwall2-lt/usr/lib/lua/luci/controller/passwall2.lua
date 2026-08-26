


module("luci.controller.passwall2", package.seeall)
local api = require "luci.passwall2.api"
local appname = api.appname
local uci = api.uci
local http = require "luci.http"
local util = require "luci.util"
local i18n = require "luci.i18n"
local fs = api.fs
local jsonStringify = luci.jsonc.stringify
local jsonParse = luci.jsonc.parse

function index()
	if not nixio.fs.access("/etc/config/passwall2") then
		if nixio.fs.access("/usr/share/passwall2/0_default_config") then
			luci.sys.call('cp -f /usr/share/passwall2/0_default_config /etc/config/passwall2')
		else return end
	end
	local api = require "luci.passwall2.api"
	local appname = api.appname
	local uci = api.uci
	entry({"admin", "services", appname}).dependent = true
	entry({"admin", "services", appname, "reset_config"}, call("reset_config")).leaf = true
	entry({"admin", "services", appname, "show"}, call("show_menu")).leaf = true
	entry({"admin", "services", appname, "hide"}, call("hide_menu")).leaf = true
	local e
	if uci:get(appname, "@global[0]", "hide_from_luci") ~= "1" then
		e = entry({"admin", "services", appname}, alias("admin", "services", appname, "settings"), _("PassWall 2"), 0)
	else
		e = entry({"admin", "services", appname}, alias("admin", "services", appname, "settings"), nil, 0)
	end
	e.dependent = true
	e.acl_depends = { "luci-app-passwall2" }

	entry({"admin", "services", appname, "settings"}, cbi(appname .. "/client/global"), _("Basic Settings"), 1).dependent = true
	entry({"admin", "services", appname, "node_list"}, cbi(appname .. "/client/node_list"), _("Node List"), 2).dependent = true
	entry({"admin", "services", appname, "node_subscribe"}, cbi(appname .. "/client/node_subscribe"), _("Node Subscribe"), 3).dependent = true
	entry({"admin", "services", appname, "proxy_server"}, cbi(appname .. "/client/proxy_server"), _("Proxy Server"), 3).dependent = true
	entry({"admin", "services", appname, "other"}, cbi(appname .. "/client/other", {autoapply = true}), _("Other Settings"), 92).leaf = true
	if nixio.fs.access("/usr/sbin/haproxy") then
		entry({"admin", "services", appname, "haproxy"}, cbi(appname .. "/client/haproxy"), _("Load Balancing"), 93).leaf = true
	end

	entry({"admin", "services", appname, "rule"}, cbi(appname .. "/client/rule"), _("Rule Manage"), 96).leaf = true

	entry({"admin", "services", appname, "node_config"}, cbi(appname .. "/client/node_config")).leaf = true
	entry({"admin", "services", appname, "shunt_rules"}, cbi(appname .. "/client/shunt_rules")).leaf = true
	entry({"admin", "services", appname, "socks_config"}, cbi(appname .. "/client/socks_config")).leaf = true
	entry({"admin", "services", appname, "acl"}, cbi(appname .. "/client/acl"), _("Access control"), 98).leaf = true
	entry({"admin", "services", appname, "acl_config"}, cbi(appname .. "/client/acl_config")).leaf = true
	entry({"admin", "services", appname, "log"}, form(appname .. "/client/log"), _("Watch Logs"), 999).leaf = true





	entry({"admin", "services", appname, "socks_autoswitch_add_node"}, call("socks_autoswitch_add_node")).leaf = true
	entry({"admin", "services", appname, "socks_autoswitch_remove_node"}, call("socks_autoswitch_remove_node")).leaf = true
	entry({"admin", "services", appname, "get_now_use_node"}, call("get_now_use_node")).leaf = true
	entry({"admin", "services", appname, "get_redir_log"}, call("get_redir_log")).leaf = true
	entry({"admin", "services", appname, "get_socks_log"}, call("get_socks_log")).leaf = true
	entry({"admin", "services", appname, "get_log"}, call("get_log")).leaf = true
	entry({"admin", "services", appname, "clear_log"}, call("clear_log")).leaf = true
	entry({"admin", "services", appname, "index_status"}, call("index_status")).leaf = true
	entry({"admin", "services", appname, "haproxy_status"}, call("haproxy_status")).leaf = true
	entry({"admin", "services", appname, "socks_status"}, call("socks_status")).leaf = true
	entry({"admin", "services", appname, "connect_status"}, call("connect_status")).leaf = true
	entry({"admin", "services", appname, "ping_node"}, call("ping_node")).leaf = true
	entry({"admin", "services", appname, "urltest_node"}, call("urltest_node")).leaf = true
	entry({"admin", "services", appname, "add_node"}, call("add_node")).leaf = true
	entry({"admin", "services", appname, "link_add_node"}, call("link_add_node")).leaf = true
	entry({"admin", "services", appname, "update_node"}, call("update_node")).leaf = true
	entry({"admin", "services", appname, "set_node"}, call("set_node")).leaf = true
	entry({"admin", "services", appname, "copy_node"}, call("copy_node")).leaf = true
	entry({"admin", "services", appname, "clear_all_nodes"}, call("clear_all_nodes")).leaf = true
	entry({"admin", "services", appname, "delete_select_nodes"}, call("delete_select_nodes")).leaf = true
	entry({"admin", "services", appname, "reassign_group"}, call("reassign_group")).leaf = true
	entry({"admin", "services", appname, "get_subscribe_list"}, call("get_subscribe_list")).leaf = true
	entry({"admin", "services", appname, "subscribe_add"}, call("subscribe_add")).leaf = true
	entry({"admin", "services", appname, "subscribe_update"}, call("subscribe_update")).leaf = true
	entry({"admin", "services", appname, "subscribe_delete"}, call("subscribe_delete")).leaf = true
	entry({"admin", "services", appname, "subscribe_reassign_group"}, call("subscribe_reassign_group")).leaf = true
	entry({"admin", "services", appname, "get_node"}, call("get_node")).leaf = true
	entry({"admin", "services", appname, "save_node_order"}, call("save_node_order")).leaf = true
	entry({"admin", "services", appname, "save_node_list_opt"}, call("save_node_list_opt")).leaf = true
	entry({"admin", "services", appname, "get_shunt_rules"}, call("get_shunt_rules")).leaf = true
	entry({"admin", "services", appname, "save_shunt_rule_order"}, call("save_shunt_rule_order")).leaf = true
	entry({"admin", "services", appname, "add_shunt_rule"}, call("add_shunt_rule")).leaf = true
	entry({"admin", "services", appname, "del_shunt_rule"}, call("del_shunt_rule")).leaf = true
	entry({"admin", "services", appname, "get_acl_rules"}, call("get_acl_rules")).leaf = true
	entry({"admin", "services", appname, "save_acl_rule_order"}, call("save_acl_rule_order")).leaf = true
	entry({"admin", "services", appname, "add_acl_rule"}, call("add_acl_rule")).leaf = true
	entry({"admin", "services", appname, "del_acl_rule"}, call("del_acl_rule")).leaf = true
	entry({"admin", "services", appname, "toggle_acl_rule"}, call("toggle_acl_rule")).leaf = true
	entry({"admin", "services", appname, "get_socks_list"}, call("get_socks_list")).leaf = true
	entry({"admin", "services", appname, "add_socks"}, call("add_socks")).leaf = true
	entry({"admin", "services", appname, "del_socks"}, call("del_socks")).leaf = true
	entry({"admin", "services", appname, "toggle_socks_enabled"}, call("toggle_socks_enabled")).leaf = true
	entry({"admin", "services", appname, "flush_set"}, call("flush_set")).leaf = true




	entry({"admin", "services", appname, "create_backup"}, call("create_backup")).leaf = true
	entry({"admin", "services", appname, "restore_backup"}, call("restore_backup")).leaf = true


end

local function http_write_json(content)
	http.prepare_content("application/json")
	http.write(jsonStringify(content or {code = 1}))
end

local function http_write_json_ok(data)
	http.prepare_content("application/json")
	http.write(jsonStringify({code = 1, data = data}))
end

local function http_write_json_error(data)
	http.prepare_content("application/json")
	http.write(jsonStringify({code = 0, data = data}))
end

function reset_config()
	luci.sys.call('/etc/init.d/passwall2 stop')
	luci.sys.call('[ -f "/usr/share/passwall2/0_default_config" ] && cp -f /usr/share/passwall2/0_default_config /etc/config/passwall2')
	http.redirect(api.url())
end

function show_menu()
	api.sh_uci_del(appname, "@global[0]", "hide_from_luci", true)
	luci.sys.call("rm -rf /tmp/luci-*")
	luci.sys.call("/etc/init.d/rpcd restart >/dev/null")
	http.redirect(api.url())
end

function hide_menu()
	api.sh_uci_set(appname, "@global[0]", "hide_from_luci", "1", true)
	luci.sys.call("rm -rf /tmp/luci-*")
	luci.sys.call("/etc/init.d/rpcd restart >/dev/null")
	http.redirect(luci.dispatcher.build_url("admin", "status", "overview"))
end

function socks_autoswitch_add_node()
	local id = http.formvalue("id")
	local key = http.formvalue("key")
	if id and id ~= "" and key and key ~= "" then
		uci:set(appname, id, "enable_autoswitch", "1")
		local new_list = uci:get(appname, id, "autoswitch_backup_node") or {}
		for i = #new_list, 1, -1 do
			if (uci:get(appname, new_list[i], "remarks") or ""):find(key) then
				table.remove(new_list, i)
			end
		end
		for k, e in ipairs(api.get_valid_nodes()) do
			if e.node_type == "normal" and e["remark"]:find(key) then
				table.insert(new_list, e.id)
			end
		end
		uci:set_list(appname, id, "autoswitch_backup_node", new_list)
		api.uci_save(uci, appname)
	end
	http.redirect(api.url("socks_config", id))
end

function socks_autoswitch_remove_node()
	local id = http.formvalue("id")
	local key = http.formvalue("key")
	if id and id ~= "" and key and key ~= "" then
		uci:set(appname, id, "enable_autoswitch", "1")
		local new_list = uci:get(appname, id, "autoswitch_backup_node") or {}
		for i = #new_list, 1, -1 do
			if (uci:get(appname, new_list[i], "remarks") or ""):find(key) then
				table.remove(new_list, i)
			end
		end
		uci:set_list(appname, id, "autoswitch_backup_node", new_list)
		api.uci_save(uci, appname)
	end
	http.redirect(api.url("socks_config", id))
end

function get_now_use_node()
	local e = {}
	local node = api.get_cache_var("ACL_GLOBAL_node")
	if node then
		e["global"] = node
	end
	http_write_json(e)
end

function get_redir_log()
	local id = http.formvalue("id")
	local name = http.formvalue("name")
	if not api.is_safe_id(id) or not api.is_safe_id(name) then
		http.write(string.format("<script>alert('%s');window.close();</script>", i18n.translate("Not enabled log")))
		return
	end
	local file_path = "/tmp/etc/passwall2/acl/" .. id .. "/" .. name .. ".log"
	if nixio.fs.access(file_path) then
		local content = luci.sys.exec("tail -n 19999 " .. util.shellquote(file_path))
		content = util.pcdata(content):gsub("\n", "<br />")
		http.write(content)
	else
		http.write(string.format("<script>alert('%s');window.close();</script>", i18n.translate("Not enabled log")))
	end
end

function get_socks_log()
	local name = http.formvalue("name")
	if not api.is_safe_id(name) then
		http.write(string.format("<script>alert('%s');window.close();</script>", i18n.translate("Not enabled log")))
		return
	end
	local path = "/tmp/etc/passwall2/SOCKS_" .. name .. ".log"
	if nixio.fs.access(path) then
		local content = luci.sys.exec("tail -n 5000 " .. util.shellquote(path))
		content = util.pcdata(content):gsub("\n", "<br />")
		http.write(content)
	else
		http.write(string.format("<script>alert('%s');window.close();</script>", i18n.translate("Not enabled log")))
	end
end

function get_log()
	http.write(luci.sys.exec("[ -f '/tmp/log/passwall2.log' ] && cat /tmp/log/passwall2.log"))
end

function clear_log()
	luci.sys.call("echo '' > /tmp/log/passwall2.log")
end

function index_status()
	local e = {}
	e["global_status"] = luci.sys.call("/bin/busybox top -bn1 | grep -v 'grep' | grep '/tmp/etc/passwall2/bin/' | grep 'default' | grep 'global' >/dev/null") == 0
	http_write_json(e)
end

function haproxy_status()
	local e = {}
	e["status"] = luci.sys.call(string.format("/bin/busybox top -bn1 | grep -v grep | grep '%s/bin/' | grep haproxy >/dev/null", appname)) == 0
	http_write_json(e)
end

function socks_status()
	local e = {}
	local index = http.formvalue("index")
	local id = http.formvalue("id")
	e.index = index
	if not api.is_safe_id(id) then
		http_write_json(e)
		return
	end
	e.socks_status = luci.sys.call(string.format("/bin/busybox top -bn1 | grep -v -E 'grep|acl/|acl_' | grep %s | grep %s | grep 'SOCKS_' > /dev/null", util.shellquote(appname .. "/bin/"), util.shellquote(id))) == 0
	local use_http = uci:get(appname, id, "http_port") or 0
	e.use_http = 0
	if tonumber(use_http) > 0 then
		e.use_http = 1
		e.http_status = luci.sys.call(string.format("/bin/busybox top -bn1 | grep -v -E 'grep|acl/|acl_' | grep %s | grep %s | grep -E 'HTTP_|HTTP2SOCKS' > /dev/null", util.shellquote(appname .. "/bin/"), util.shellquote(id))) == 0
	end
	http_write_json(e)
end

function connect_status()
	local e = {}
	e.use_time = ""
	local url = http.formvalue("url") or ""
	local result = luci.sys.exec('curl --connect-timeout 3 -o /dev/null -I -sk -w "%{http_code}:%{time_appconnect}" ' .. util.shellquote(url))
	local code_str, use_time_str = result:match("^(%d*):([%d%.]*)")
	local code = tonumber(code_str) or 0
	if code ~= 0 then
		local use_time = tonumber(use_time_str) or 0
		if use_time_str and use_time_str:find("%.") then
			e.use_time = string.format("%.2f", use_time * 1000)
		else
			e.use_time = string.format("%.2f", use_time / 1000)
		end
		e.ping_type = "curl"
	end
	http_write_json(e)
end

function ping_node()
	local index = http.formvalue("index")
	local address = http.formvalue("address") or ""
	local port = tonumber(http.formvalue("port")) or 0
	local type = http.formvalue("type") or "icmp"
	local e = {}
	e.index = index
	if type == "tcping" and luci.sys.exec("echo -n $(command -v tcping)") ~= "" then
		if api.is_ipv6(address) then
			address = api.get_ipv6_only(address)
		end
		e.ping = luci.sys.exec(string.format("echo -n $(tcping -q -c 1 -i 1 -t 2 -p %d %s 2>&1 | grep -o 'time=[0-9]*' | awk -F '=' '{print $2}') 2>/dev/null", port, util.shellquote(address)))
	else
		e.ping = luci.sys.exec("echo -n $(ping -c 1 -W 1 " .. util.shellquote(address) .. " 2>&1 | grep -o 'time=[0-9]*' | awk -F '=' '{print $2}') 2>/dev/null")
	end
	http_write_json(e)
end

function urltest_node()
	local index = http.formvalue("index")
	local id = http.formvalue("id")
	local e = {}
	e.index = index
	if not api.is_safe_id(id) then
		http_write_json(e)
		return
	end
	local result = luci.sys.exec(string.format("/usr/share/passwall2/test.sh url_test_node %s %s", util.shellquote(id), "urltest_node"))
	local code_str, use_time_str = result:match("^(%d*):([%d%.]*)")
	local code = tonumber(code_str) or 0
	if code ~= 0 then
		local use_time = tonumber(use_time_str) or 0
		if use_time_str and use_time_str:find("%.") then
			e.use_time = string.format("%.2f", use_time * 1000)
		else
			e.use_time = string.format("%.2f", use_time / 1000)
		end
	end
	http_write_json(e)
end

function add_node()
	local redirect = http.formvalue("redirect")

	local uuid = api.gen_short_uuid()
	uci:section(appname, "nodes", uuid)

	local group = http.formvalue("group")
	if group then
		uci:set(appname, uuid, "group", group)
	end

	uci:set(appname, uuid, "type", "Xray")

	if redirect == "1" then
		api.uci_save(uci, appname)
		http.redirect(api.url("node_config", uuid))
	else
		api.uci_save(uci, appname, true, true)
		http_write_json({result = uuid})
	end
end

function update_node()
	local id = http.formvalue("id")
	local data = http.formvalue("data")
	if id and data then
		local data_t = jsonParse(data) or {}
		if next(data_t) then
			for k, v in pairs(data_t) do
				uci:set(appname, id, k, v)
			end
			api.uci_save(uci, appname)
			http_write_json_ok()
			return
		end
	end
	http_write_json_error()
end

function set_node()
	local type = http.formvalue("type")
	local config = http.formvalue("config")
	local section = http.formvalue("section")
	uci:set(appname, type, config, section)
	api.uci_save(uci, appname, true, true)
	http.redirect(api.url("log"))
end

function copy_node()
	local section = http.formvalue("section")
	local uuid = api.gen_short_uuid()
	uci:section(appname, "nodes", uuid)
	for k, v in pairs(uci:get_all(appname, section)) do
		local filter = k:find("%.")
		if filter and filter == 1 then
		else
			xpcall(function()
				uci:set(appname, uuid, k, v)
			end,
			function(e)
			end)
		end
	end
	uci:delete(appname, uuid, "group")
	uci:set(appname, uuid, "add_mode", 1)
	api.uci_save(uci, appname)
	http.redirect(api.url("node_config", uuid))
end

local LINK_ADD_TMP_FILE = "/tmp/passwall2_link_add.tmp"

function link_add_node()
	local chunk = http.formvalue("chunk") or ""
	local chunk_index = tonumber(http.formvalue("chunk_index")) or 0
	local total_chunks = tonumber(http.formvalue("total_chunks")) or 1
	local group = http.formvalue("group") or ""

	local f
	if chunk_index == 0 then
		f = io.open(LINK_ADD_TMP_FILE, "w")
	else
		f = io.open(LINK_ADD_TMP_FILE, "a")
	end
	if f then
		f:write(chunk)
		f:close()
	end

	if chunk_index + 1 < total_chunks then
		http_write_json_ok()
		return
	end

	local full_text = fs.readfile(LINK_ADD_TMP_FILE) or ""
	fs.remove(LINK_ADD_TMP_FILE)

	local link_util = require "luci.passwall2.util_link"
	local added, failed = 0, 0

	for line in full_text:gmatch("[^\r\n]+") do
		line = api.trim(line)
		if line ~= "" then
			local ok, type_name, fields, remark = pcall(link_util.parse_link, line)
			if ok and type_name and fields then
				local uuid = api.gen_short_uuid()
				uci:section(appname, "nodes", uuid)
				uci:set(appname, uuid, "type", type_name)
				uci:set(appname, uuid, "remarks", (remark and remark ~= "") and remark or uuid)
				if group ~= "" then
					uci:set(appname, uuid, "group", group)
				end
				for k, v in pairs(fields) do
					if v ~= nil and v ~= "" then
						uci:set(appname, uuid, k, v)
					end
				end
				added = added + 1
			else
				failed = failed + 1
			end
		end
	end

	if added > 0 then
		api.uci_save(uci, appname, true, true)
	end

	http_write_json({ added = added, failed = failed })
end

function clear_all_nodes()
	uci:set(appname, '@global[0]', "enabled", "0")
	uci:set(appname, '@global[0]', "socks_enabled", "0")
	uci:set(appname, '@haproxy_config[0]', "balancing_enable", "0")
	uci:delete(appname, '@global[0]', "node")
	uci:foreach(appname, "socks", function(t)
		uci:delete(appname, t[".name"])
		uci:set_list(appname, t[".name"], "autoswitch_backup_node", {})
	end)
	uci:foreach(appname, "haproxy_config", function(t)
		uci:delete(appname, t[".name"])
	end)
	uci:foreach(appname, "acl_rule", function(t)
		uci:delete(appname, t[".name"], "node")
	end)
	uci:foreach(appname, "nodes", function(node)
		uci:delete(appname, node['.name'])
	end)
	uci:foreach(appname, "subscribe_list", function(t)
		uci:delete(appname, t[".name"], "md5")
		uci:delete(appname, t[".name"], "chain_proxy")
		uci:delete(appname, t[".name"], "preproxy_node")
		uci:delete(appname, t[".name"], "to_node")
	end)

	api.uci_save(uci, appname, true, true)
end

function delete_select_nodes()
	local ids = http.formvalue("ids")
	local redirect = http.formvalue("redirect")
	string.gsub(ids, '[^' .. "," .. ']+', function(w)
		if (uci:get(appname, "@global[0]", "node") or "") == w then
			uci:delete(appname, '@global[0]', "node")
		end
		uci:foreach(appname, "socks", function(t)
			if t["node"] == w then
				uci:delete(appname, t[".name"])
			end
			local auto_switch_node_list = uci:get(appname, t[".name"], "autoswitch_backup_node") or {}
			for i = #auto_switch_node_list, 1, -1 do
				if w == auto_switch_node_list[i] then
					table.remove(auto_switch_node_list, i)
				end
			end
			uci:set_list(appname, t[".name"], "autoswitch_backup_node", auto_switch_node_list)
		end)
		uci:foreach(appname, "haproxy_config", function(t)
			if t["lbss"] == w then
				uci:delete(appname, t[".name"])
			end
		end)
		uci:foreach(appname, "acl_rule", function(t)
			if t["node"] == w then
				uci:delete(appname, t[".name"], "node")
			end
		end)
		uci:foreach(appname, "nodes", function(t)
			if t["preproxy_node"] == w then
				uci:delete(appname, t[".name"], "preproxy_node")
				uci:delete(appname, t[".name"], "chain_proxy")
			end
			if t["to_node"] == w then
				uci:delete(appname, t[".name"], "to_node")
				uci:delete(appname, t[".name"], "chain_proxy")
			end
			local list_name = t["urltest_node"] and "urltest_node" or (t["balancing_node"] and "balancing_node")
			if list_name then
				local nodes = uci:get_list(appname, t[".name"], list_name)
				if nodes then
					local changed = false
					local new_nodes = {}
					for _, node in ipairs(nodes) do
						if node ~= w then
							table.insert(new_nodes, node)
						else
							changed = true
						end
					end
					if changed then
						uci:set_list(appname, t[".name"], list_name, new_nodes)
					end
				end
			end
			if t["fallback_node"] == w then
				uci:delete(appname, t[".name"], "fallback_node")
			end
		end)
		uci:foreach(appname, "subscribe_list", function(t)
			if t["preproxy_node"] == w then
				uci:delete(appname, t[".name"], "preproxy_node")
				uci:delete(appname, t[".name"], "chain_proxy")
			end
			if t["to_node"] == w then
				uci:delete(appname, t[".name"], "to_node")
				uci:delete(appname, t[".name"], "chain_proxy")
			end
		end)
		if (uci:get(appname, w, "add_mode") or "0") == "2" then
			local group = uci:get(appname, w, "group") or ""
			if group ~= "" then
				uci:foreach(appname, "subscribe_list", function(t)
					if t["remark"] == group then
						uci:delete(appname, t[".name"], "md5")
					end
				end)
			end
		end
		uci:delete(appname, w)
	end)
	if redirect == "1" then
		api.uci_save(uci, appname)
		http.redirect(api.url("node_list"))
	else
		api.uci_save(uci, appname, true, true)
	end
end

function get_node()
	local id = http.formvalue("id")
	local result = {}
	local show_node_info = api.uci_get_type("global_other", "show_node_info", "0")

	local function add_is_ipv6_key(o)
		if o and o.address and show_node_info == "1" then
			local f = api.get_ipv6_full(o.address)
			if f ~= "" then
				o.ipv6 = true
				o.full_address = f
			end
		end
	end

	if id then
		result = uci:get_all(appname, id)
		add_is_ipv6_key(result)
	else
		local default_nodes = {}
		local other_nodes = {}
		uci:foreach(appname, "nodes", function(t)
			add_is_ipv6_key(t)
			if not t.group or t.group == "" then
				default_nodes[#default_nodes + 1] = t
			else
				other_nodes[#other_nodes + 1] = t
			end
		end)
		for i = 1, #default_nodes do result[#result + 1] = default_nodes[i] end
		for i = 1, #other_nodes do result[#result + 1] = other_nodes[i] end
	end
	http_write_json(result)
end

function save_node_order()
	local ids = http.formvalue("ids") or ""
	local new_order = {}
	for id in ids:gmatch("([^,]+)") do
		if api.is_safe_id(id) then
			new_order[#new_order + 1] = id
		end
	end
	for idx, name in ipairs(new_order) do
		luci.sys.call("uci -q reorder " .. util.shellquote(string.format("%s.%s=%d", appname, name, idx - 1)))
	end
	api.sh_uci_commit(appname)
	http_write_json({ status = "ok" })
end

function add_shunt_rule()
	local uuid = api.gen_short_uuid()
	uci:section(appname, "shunt_rules", uuid)
	uci:set(appname, uuid, "remarks", uuid)
	api.uci_save(uci, appname, true)
	http.redirect(api.url("shunt_rules", uuid))
end

function del_shunt_rule()
	local id = http.formvalue("id")
	if api.is_safe_id(id) and uci:get(appname, id) == "shunt_rules" then
		uci:foreach(appname, "nodes", function(s)
			if s["protocol"] and s["protocol"] == "_shunt" then
				uci:delete(appname, s[".name"], id)
			end
		end)
		uci:delete(appname, id)
		uci:set(appname, "@global[0]", "flush_set", "1")
		api.uci_save(uci, appname, true)
	end
	http_write_json({ status = "ok" })
end

function get_socks_list()
	local result = {}
	uci:foreach(appname, "socks", function(e)
		if e[".name"] then
			local node = uci:get_all(appname, e.node or "")
			local node_remarks = node and api.get_node_remarks(node) or ""
			local current_id = api.get_cache_var("socks_" .. e[".name"])
			local current_node = current_id and uci:get_all(appname, current_id)
			result[#result + 1] = {
				id = e[".name"],
				enabled = e.enabled or "0",
				port = e.port or "",
				http_port = e.http_port or "0",
				node_remarks = node_remarks,
				current_remarks = current_node and api.get_node_remarks(current_node) or ""
			}
		end
	end)
	http_write_json(result)
end

function add_socks()
	local uuid = api.gen_short_uuid()
	uci:section(appname, "socks", uuid)
	uci:set(appname, uuid, "enabled", "1")
	local n = 1
	uci:foreach(appname, "socks", function() n = n + 1 end)
	uci:set(appname, uuid, "port", tostring(n + 1080))
	api.uci_save(uci, appname, true)
	http.redirect(api.url("socks_config", uuid))
end

function del_socks()
	local id = http.formvalue("id")
	if api.is_safe_id(id) and uci:get(appname, id) == "socks" then
		uci:delete(appname, id)
		api.uci_save(uci, appname, true)
	end
	http_write_json({ status = "ok" })
end

function toggle_socks_enabled()
	local id = http.formvalue("id")
	local enabled = http.formvalue("enabled") == "1" and "1" or "0"
	if api.is_safe_id(id) and uci:get(appname, id) == "socks" then
		uci:set(appname, id, "enabled", enabled)
		api.uci_save(uci, appname, true)
		http_write_json({ status = "ok" })
	else
		http_write_json({ status = "error" })
	end
end

function get_acl_rules()
	local result = {}
	local mac_t = {}
	pcall(function()
		luci.sys.net.mac_hints(function(e, t)
			mac_t[e] = t
		end)
	end)
	uci:foreach(appname, "acl_rule", function(e)
		if e[".name"] then
			local sources = {}
			if e.sources then
				local src_list = e.sources
				if type(src_list) == "string" then
					local t = {}
					for w in src_list:gmatch("%S+") do
						t[#t + 1] = w
					end
					src_list = t
				end
				for _, w in ipairs(src_list) do
					if mac_t[w] then
						sources[#sources + 1] = w .. " (" .. mac_t[w] .. ")"
					else
						sources[#sources + 1] = w
					end
				end
			end
			result[#result + 1] = {
				id = e[".name"],
				enabled = e.enabled or "0",
				remarks = e.remarks or "",
				sources = sources,
				interface = e.interface or ""
			}
		end
	end)
	http_write_json(result)
end

function save_acl_rule_order()
	local ids = http.formvalue("ids") or ""
	local new_order = {}
	for id in ids:gmatch("([^,]+)") do
		if api.is_safe_id(id) then
			new_order[#new_order + 1] = id
		end
	end
	for idx, name in ipairs(new_order) do
		luci.sys.call("uci -q reorder " .. util.shellquote(string.format("%s.%s=%d", appname, name, idx - 1)))
	end
	api.sh_uci_commit(appname)
	http_write_json({ status = "ok" })
end

function add_acl_rule()
	local uuid = api.gen_short_uuid()
	uci:section(appname, "acl_rule", uuid)
	uci:set(appname, uuid, "enabled", "1")
	uci:set(appname, uuid, "remarks", uuid)
	api.uci_save(uci, appname, true)
	http.redirect(api.url("acl_config", uuid))
end

function del_acl_rule()
	local id = http.formvalue("id")
	if api.is_safe_id(id) and uci:get(appname, id) == "acl_rule" then
		uci:delete(appname, id)
		api.uci_save(uci, appname, true)
	end
	http_write_json({ status = "ok" })
end

function toggle_acl_rule()
	local id = http.formvalue("id")
	local enabled = http.formvalue("enabled") == "1" and "1" or "0"
	if api.is_safe_id(id) and uci:get(appname, id) == "acl_rule" then
		uci:set(appname, id, "enabled", enabled)
		api.uci_save(uci, appname, true)
		http_write_json({ status = "ok" })
	else
		http_write_json({ status = "error" })
	end
end

function get_shunt_rules()
	local result = {}
	uci:foreach(appname, "shunt_rules", function(e)
		if e[".name"] and e.remarks then
			result[#result + 1] = {
				id = e[".name"],
				remarks = e.remarks,
				network = e.network or "",
				protocol = e.protocol or {},
				domain_count = 0,
				ip_count = 0
			}
			local n = #result
			if e.domain_list then
				for _ in e.domain_list:gmatch("[^\r\n]+") do
					result[n].domain_count = result[n].domain_count + 1
				end
			end
			if e.ip_list then
				for _ in e.ip_list:gmatch("[^\r\n]+") do
					result[n].ip_count = result[n].ip_count + 1
				end
			end
		end
	end)
	http_write_json(result)
end

function save_shunt_rule_order()
	local ids = http.formvalue("ids") or ""
	local new_order = {}
	for id in ids:gmatch("([^,]+)") do
		if api.is_safe_id(id) then
			new_order[#new_order + 1] = id
		end
	end
	for idx, name in ipairs(new_order) do
		luci.sys.call("uci -q reorder " .. util.shellquote(string.format("%s.%s=%d", appname, name, idx - 1)))
	end
	api.sh_uci_commit(appname)
	http_write_json({ status = "ok" })
end

function reassign_group()
	local ids = http.formvalue("ids") or ""
	local group = http.formvalue("group") or "default"
	for id in ids:gmatch("([^,]+)") do
		if group ~="" and group ~= "default" then
			api.sh_uci_set(appname, id, "group", group)
		else
			api.sh_uci_del(appname, id, "group")
		end
	end
	api.sh_uci_commit(appname)
	http_write_json({ status = "ok" })
end

local datatypes = api.datatypes
local link_util = require "luci.passwall2.util_link"

local SUB_MAX_BYTES = 2 * 1024 * 1024
local SUB_MAX_LINES = 2000
local SUB_MAX_NODES = 500

local SUB_ADDRESS_FIELD = { Xray = "xray_address", SS = "ss_address", SSR = "ssr_address", Hysteria2 = "hysteria2_address", TUIC = "tuic_address" }
local SUB_PORT_FIELD = { Xray = "xray_port", SS = "ss_port", SSR = "ssr_port", Hysteria2 = "hysteria2_port", TUIC = "tuic_port" }

local function sub_looks_like_links(s)
	if type(s) ~= "string" then return false end
	return s:find("vmess://", 1, true) or s:find("vless://", 1, true)
		or s:find("trojan://", 1, true) or s:find("ss://", 1, true)
		or s:find("ssr://", 1, true) or s:find("hysteria2://", 1, true)
		or s:find("hy2://", 1, true) or s:find("tuic://", 1, true)
end

local function sub_is_valid_url(u)
	if type(u) ~= "string" or u == "" or #u > 2048 then return false end
	if u:find("%c") then return false end
	local rest = u:match("^https?://(.+)$")
	if not rest then return false end
	local host = rest:match("^([^/?#]+)")
	if not host or host == "" then return false end
	if host:find("[%s'\"`$();&|<>\\]") then return false end
	return true
end

local function sub_sanitize_field(v)
	if type(v) ~= "string" then return v end
	v = v:gsub("[\r\n%z]", "")
	if #v > 512 then v = v:sub(1, 512) end
	return v
end

local function sub_sanitize_group(v)
	v = api.trim(v or "")
	v = v:gsub("[%c<>\"'&]", "")
	if #v > 64 then v = v:sub(1, 64) end
	return v
end

local function sub_group_exists(name)
	local exists = false
	uci:foreach(appname, "subscribe_list", function(t)
		if t.group == name then exists = true end
	end)
	return exists
end

local function sub_derive_group(u)
	local host = u:match("^https?://([^/:?#]+)") or ""
	host = host:gsub("^www%.", "")
	host = host:gsub("[^%w%.%-]", "")
	if host == "" then host = "subscription" end
	if #host > 40 then host = host:sub(1, 40) end
	local candidate, n = host, 1
	while sub_group_exists(candidate) do
		n = n + 1
		candidate = host .. "-" .. n
	end
	return candidate
end

local function sub_curl_fetch(url_str, out_file)
	fs.remove(out_file)
	local cmd = "curl -sS -L --max-redirs 5 --connect-timeout 8 --max-time 20"
		.. " --proto " .. util.shellquote("=http,https")
		.. " --proto-redir " .. util.shellquote("=http,https")
		.. " --max-filesize " .. tostring(SUB_MAX_BYTES)
		.. " -A " .. util.shellquote("PassWall2-Foxhound/1.0")
		.. " -o " .. util.shellquote(out_file)
		.. " -w " .. util.shellquote("%{http_code}")
		.. " " .. util.shellquote(url_str)
	local ok, return_code, http_code_str = pcall(api.exec_call, cmd)
	if not ok then
		return false, "No response from the link."
	end
	local http_code = tonumber(http_code_str)
	if not fs.access(out_file) then
		return false, "No response from the link."
	end
	if return_code ~= 0 or not http_code or http_code < 200 or http_code >= 300 then
		return false, "No response from the link."
	end
	return true, nil
end

local function sub_build_nodes(sub_id, group, out_file)
	local raw = fs.readfile(out_file) or ""
	raw = api.trim(raw)
	if raw == "" then
		return 0, 0, "empty subscription content"
	end
	if #raw > SUB_MAX_BYTES then
		raw = raw:sub(1, SUB_MAX_BYTES)
	end
	local content = raw
	if not sub_looks_like_links(content) then
		local ok, decoded = pcall(api.base64Decode, raw)
		if ok and decoded and sub_looks_like_links(decoded) then
			content = decoded
		end
	end
	local old_ids = {}
	uci:foreach(appname, "nodes", function(n)
		if n.subscribe_id == sub_id then
			old_ids[#old_ids + 1] = n[".name"]
		end
	end)
	local added, failed, line_count = 0, 0, 0
	for line in content:gmatch("[^\r\n]+") do
		line_count = line_count + 1
		if line_count > SUB_MAX_LINES or added >= SUB_MAX_NODES then
			break
		end
		line = api.trim(line)
		if line ~= "" then
			local ok, type_name, fields, remark = pcall(link_util.parse_link, line)
			if ok and type_name and fields then
				local addr_key = SUB_ADDRESS_FIELD[type_name]
				local port_key = SUB_PORT_FIELD[type_name]
				local addr = addr_key and fields[addr_key]
				local port = port_key and tonumber(fields[port_key])
				local addr_ok = addr and addr ~= "" and addr ~= "127.0.0.1" and addr ~= "localhost"
					and (datatypes.hostname(addr) or api.is_ip(addr))
				local port_ok = port and port >= 1 and port <= 65535
				if addr_ok and port_ok then
					local uuid = api.gen_short_uuid()
					uci:section(appname, "nodes", uuid)
					uci:set(appname, uuid, "type", type_name)
					uci:set(appname, uuid, "remarks", (remark and remark ~= "") and remark or uuid)
					uci:set(appname, uuid, "group", group)
					uci:set(appname, uuid, "subscribe_id", sub_id)
					uci:set(appname, uuid, "add_mode", "2")
					for k, v in pairs(fields) do
						if v ~= nil and v ~= "" then
							uci:set(appname, uuid, k, sub_sanitize_field(v))
						end
					end
					added = added + 1
				else
					failed = failed + 1
				end
			else
				failed = failed + 1
			end
		end
	end
	for _, id in ipairs(old_ids) do
		uci:delete(appname, id)
	end
	return added, failed, nil
end

function get_subscribe_list()
	local result = {}
	uci:foreach(appname, "subscribe_list", function(t)
		local id = t[".name"]
		local count = 0
		uci:foreach(appname, "nodes", function(n)
			if n.subscribe_id == id then count = count + 1 end
		end)
		result[#result + 1] = {
			id = id,
			url = t.url or "",
			group = t.group or "",
			count = count,
			last_update = t.last_update or ""
		}
	end)
	http_write_json(result)
end

function subscribe_add()
	local url_str = api.trim(http.formvalue("url") or "")
	if not sub_is_valid_url(url_str) then
		http_write_json({ status = "error", message = "Invalid subscription URL." })
		return
	end
	local duplicate = false
	uci:foreach(appname, "subscribe_list", function(t)
		if t.url == url_str then duplicate = true end
	end)
	if duplicate then
		http_write_json({ status = "error", message = "This subscription URL has already been added." })
		return
	end

	local id = api.gen_short_uuid()
	local group = sub_derive_group(url_str)
	uci:section(appname, "subscribe_list", id)
	uci:set(appname, id, "url", url_str)
	uci:set(appname, id, "group", group)
	api.uci_save(uci, appname, true)

	local tmp_file = "/tmp/passwall2_sub_" .. id
	local fetch_ok, fetch_err = sub_curl_fetch(url_str, tmp_file)
	local added, failed, build_err = 0, 0, nil
	if fetch_ok then
		added, failed, build_err = sub_build_nodes(id, group, tmp_file)
		uci:set(appname, id, "last_update", tostring(os.time()))
		api.uci_save(uci, appname, true, true)
	end
	fs.remove(tmp_file)

	if not fetch_ok then
		http_write_json({ status = "error", message = fetch_err or "Failed to fetch subscription.", id = id, group = group })
	elseif build_err then
		http_write_json({ status = "error", message = build_err, id = id, group = group })
	else
		http_write_json({ status = "ok", id = id, group = group, added = added, failed = failed })
	end
end

function subscribe_update()
	local id = http.formvalue("id")
	if not api.is_safe_id(id) or uci:get(appname, id) ~= "subscribe_list" then
		http_write_json({ status = "error", message = "Invalid subscription." })
		return
	end
	local url_str = uci:get(appname, id, "url") or ""
	local group = uci:get(appname, id, "group") or sub_derive_group(url_str)
	if not sub_is_valid_url(url_str) then
		http_write_json({ status = "error", message = "Invalid subscription URL." })
		return
	end

	local tmp_file = "/tmp/passwall2_sub_" .. id
	local fetch_ok, fetch_err = sub_curl_fetch(url_str, tmp_file)
	local added, failed, build_err = 0, 0, nil
	if fetch_ok then
		added, failed, build_err = sub_build_nodes(id, group, tmp_file)
		uci:set(appname, id, "last_update", tostring(os.time()))
		api.uci_save(uci, appname, true, true)
	end
	fs.remove(tmp_file)

	if not fetch_ok then
		http_write_json({ status = "error", message = fetch_err or "Failed to fetch subscription." })
	elseif build_err then
		http_write_json({ status = "error", message = build_err })
	else
		http_write_json({ status = "ok", added = added, failed = failed })
	end
end

function subscribe_delete()
	local id = http.formvalue("id")
	if api.is_safe_id(id) and uci:get(appname, id) == "subscribe_list" then
		uci:foreach(appname, "nodes", function(n)
			if n.subscribe_id == id then
				uci:delete(appname, n[".name"])
			end
		end)
		uci:delete(appname, id)
		api.uci_save(uci, appname, true, true)
	end
	http_write_json({ status = "ok" })
end

function subscribe_reassign_group()
	local id = http.formvalue("id")
	local new_group = sub_sanitize_group(http.formvalue("group") or "")
	if not api.is_safe_id(id) or uci:get(appname, id) ~= "subscribe_list" then
		http_write_json({ status = "error", message = "Invalid subscription." })
		return
	end
	if new_group == "" then
		http_write_json({ status = "error", message = "Group name cannot be empty." })
		return
	end
	uci:set(appname, id, "group", new_group)
	uci:foreach(appname, "nodes", function(n)
		if n.subscribe_id == id then
			uci:set(appname, n[".name"], "group", new_group)
		end
	end)
	api.uci_save(uci, appname, true, true)
	http_write_json({ status = "ok", group = new_group })
end

function save_node_list_opt()
	local option = http.formvalue("option") or ""
	local value = http.formvalue("value") or ""
	if option ~= "" then
		api.sh_uci_set(appname, "@global_other[0]", option, value, true)
	end
	http_write_json({ status = "ok" })
end

local backup_files = {
	"/etc/config/passwall2",
	"/etc/config/passwall2_server",
	"/usr/share/passwall2/domains_excluded"
}

function create_backup()
	local date = os.date("%y%m%d%H%M")
	local tar_file = "/tmp/passwall2-" .. date .. "-backup.tar.gz"
	fs.remove(tar_file)
	local cmd = "tar -czf " .. tar_file .. " " .. table.concat(backup_files, " ")
	api.sys.call(cmd)
	http.header("Content-Disposition", "attachment; filename=passwall2-" .. date .. "-backup.tar.gz")
	http.header("X-Backup-Filename", "passwall2-" .. date .. "-backup.tar.gz")
	http.prepare_content("application/octet-stream")
	http.write(fs.readfile(tar_file))
	fs.remove(tar_file)
end

function restore_backup()
	local result = { status = "error", message = "unknown error" }
	local ok, err = pcall(function()
		local filename = http.formvalue("filename")
		local chunk = http.formvalue("chunk")
		local chunk_index = tonumber(http.formvalue("chunk_index") or "-1")
		local total_chunks = tonumber(http.formvalue("total_chunks") or "-1")
		if not filename then
			result = { status = "error", message = "Missing filename" }
			return
		end
		filename = filename:match("[^/\\]+$") or ""
		if filename == "" or filename:find("%.%.") then
			result = { status = "error", message = "Invalid filename" }
			return
		end
		if not chunk then
			result = { status = "error", message = "Missing chunk data" }
			return
		end
		local file_path = "/tmp/" .. filename
		local decoded = nixio.bin.b64decode(chunk)
		if not decoded then
			result = { status = "error", message = "Base64 decode failed" }
			return
		end
		local fp = io.open(file_path, "a+")
		if not fp then
			result = { status = "error", message = "Failed to open file: " .. file_path }
			return
		end
		fp:write(decoded)
		fp:close()
		if chunk_index + 1 == total_chunks then
			api.sys.call("echo '' > /tmp/log/passwall2.log")
			api.log(0, string.format(" * PassWall2 %s", i18n.translate("Configuration file uploaded successfully…")))
			local temp_dir = '/tmp/passwall2_bak'
			api.sys.call("mkdir -p " .. temp_dir)
			if api.sys.call("tar -xzf " .. util.shellquote(file_path) .. " -C " .. util.shellquote(temp_dir)) == 0 then
				for _, backup_file in ipairs(backup_files) do
					local temp_file = temp_dir .. backup_file
					if fs.access(temp_file) then
						api.sys.call("cp -f " .. util.shellquote(temp_file) .. " " .. util.shellquote(backup_file))
					end
				end
				api.log(0, string.format(" * PassWall2 %s", i18n.translate("Configuration restored successfully…")))
				api.log(0, string.format(" * PassWall2 %s", i18n.translate("Service restarting…")))
				luci.sys.call('/etc/init.d/passwall2 restart > /dev/null 2>&1 &')
				luci.sys.call('/etc/init.d/passwall2_server restart > /dev/null 2>&1 &')
				result = { status = "success", message = "Upload completed", path = file_path }
			else
				api.log(0, string.format(" * PassWall2 %s", i18n.translate("Configuration file decompression failed, please try again!")))
				result = { status = "error", message = "Decompression failed" }
			end
			api.sys.call("rm -rf " .. util.shellquote(temp_dir))
			fs.remove(file_path)
		else
			result = { status = "success", message = "Chunk received" }
		end
	end)
	if not ok then
		result = { status = "error", message = tostring(err) }
	end
	http_write_json(result)
end



function flush_set()
	local redirect = http.formvalue("redirect") or "0"
	local reload = http.formvalue("reload") or "0"
	if reload == "1" then
		uci:set(appname, '@global[0]', "flush_set", "1")
		api.uci_save(uci, appname, true, true)
	else
		api.sh_uci_set(appname, "@global[0]", "flush_set", "1", true)
	end
	if redirect == "1" then
		http.redirect(api.url("log"))
	end
end