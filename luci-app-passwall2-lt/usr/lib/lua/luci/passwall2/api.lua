module("luci.passwall2.api", package.seeall)
appname = "passwall2"
local com = require "luci.passwall2.com"
bin = require "nixio".bin
fs = require "nixio.fs"
sys = require "luci.sys"
uci = require"luci.model.uci".cursor()
util = require "luci.util"
datatypes = require "luci.cbi.datatypes"
jsonc = require "luci.jsonc"
i18n = require "luci.i18n"

command_timeout = 300

LOG_FILE = "/tmp/log/passwall2.log"
CACHE_PATH = "/tmp/etc/passwall2_tmp"
TMP_PATH = "/tmp/etc/" .. appname
TMP_IFACE_PATH = TMP_PATH .. "/iface"

NEW_PORT = nil

local lang = uci:get("luci", "main", "lang") or "auto"
if lang == "auto" then
	local auto_lang = uci:get(appname, "@global[0]", "auto_lang")
	if auto_lang then lang = auto_lang end
end
if lang == "auto" then
	lang = i18n.default
end
i18n.setlanguage(lang)

function echolog(...)
	local result = table.concat({...}, " ")
	local f, err = io.open(LOG_FILE, "a")
	if f and err == nil then
		f:write(result .. "\n")
		f:close()
	end
end

function echolog_date(...)
	local result = os.date("%Y-%m-%d %H:%M:%S: ") .. table.concat({...}, " ")
	echolog(result)
end

function log(level, ...)
	local indent = ""
	if level >= 1 then
		for i = 1, level, 1 do
			indent = indent .. "  "
		end
		echolog_date(indent .. "- " .. table.concat({...}, " "))
	else
		echolog_date(table.concat({...}, " "))
	end
end

function is_old_uci()
	return sys.call("grep -E 'require[ \t]*\"uci\"' /usr/lib/lua/luci/model/uci.lua >/dev/null 2>&1") == 0
end

function uci_save(cursor, config, commit, apply)
	if is_old_uci() then
		cursor:save(config)
		if commit then
			cursor:commit(config)
			if apply then
				sys.call("/etc/init.d/" .. util.shellquote(config) .. " reload > /dev/null 2>&1 &")
			end
		end
	else
		commit = true
		if commit then
			if apply then
				cursor:commit(config)
			else
				sh_uci_commit(config)
			end
		end
	end
end

function sh_uci_get(config, section, option)
	local _, val = exec_call("uci -q get " .. util.shellquote(string.format("%s.%s.%s", config, section, option)))
	return val
end

function sh_uci_set(config, section, option, val, commit)
	exec_call("uci -q set " .. util.shellquote(string.format("%s.%s.%s=%s", config, section, option, val)))
	if commit then sh_uci_commit(config) end
end

function sh_uci_del(config, section, option, commit)
	exec_call("uci -q delete " .. util.shellquote(string.format("%s.%s.%s", config, section, option)))
	if commit then sh_uci_commit(config) end
end

function sh_uci_add_list(config, section, option, val, commit)
	local key = util.shellquote(string.format("%s.%s.%s", config, section, option))
	local kv = util.shellquote(string.format("%s.%s.%s=%s", config, section, option, val))
	exec_call("uci -q del_list " .. kv)
	exec_call("uci -q add_list " .. kv)
	if commit then sh_uci_commit(config) end
end

function sh_uci_commit(config)
	exec_call("uci -q commit " .. util.shellquote(config))
end

function set_cache_var(key, val)
	sys.call(". /usr/share/passwall2/utils.sh ; set_cache_var " .. util.shellquote(key) .. " " .. util.shellquote(val))
end

function get_cache_var(key)
	local val = sys.exec(". /usr/share/passwall2/utils.sh ; echo -n $(get_cache_var " .. util.shellquote(key) .. ")")
	if val == "" then val = nil end
	return val
end

function get_new_port()
	local cmd_format = ". /usr/share/passwall2/utils.sh ; echo -n $(get_new_port %s tcp,udp)"
	local set_port = 0
	if NEW_PORT and tonumber(NEW_PORT) then
		set_port = tonumber(NEW_PORT) + 1
	end
	NEW_PORT = tonumber(sys.exec(string.format(cmd_format, set_port == 0 and "auto" or set_port)))
	return NEW_PORT
end

function exec_call(cmd)
	local process = io.popen(cmd .. '; echo -e "\n$?"')
	local lines = {}
	local result = ""
	local return_code
	for line in process:lines() do
		lines[#lines + 1] = line
	end
	process:close()
	if #lines > 0 then
		return_code = lines[#lines]
		for i = 1, #lines - 1 do
			result = result .. lines[i] .. ((i == #lines - 1) and "" or "\n")
		end
	end
	return tonumber(return_code), trim(result)
end

function base64Decode(text)
	if not text then return '' end
	local encoded = text:gsub("%z", ""):gsub("%c", ""):gsub("_", "/"):gsub("-", "+")
	local mod4 = #encoded % 4
	encoded = encoded .. string.sub('====', mod4 + 1)
	local result = nixio.bin.b64decode(encoded)
	if result then
		return result:gsub("%z", "")
	else
		return text
	end
end

function base64Encode(text)
	local result = nixio.bin.b64encode(text)
	return result
end


function url(...)
	local url = string.format("admin/services/%s", appname)
	local args = { ... }
	for i, v in pairs(args) do
		if v ~= "" then
			url = url .. "/" .. v
		end
	end
	return require "luci.dispatcher".build_url(url)
end

function is_safe_id(val)
	return type(val) == "string" and val ~= "" and val:match("^[%w_%-%.]+$") ~= nil and not val:find("%.%.")
end

function trim(s)
	if type(s) ~= "string" then return "" end
	local i, j = 1, #s
	while i <= j and s:byte(i) <= 32 do i = i + 1 end
	while j >= i and s:byte(j) <= 32 do j = j - 1 end
	if i > j then return "" end
	return s:sub(i, j)
end

function split(full, sep)
	if full then
		full = full:gsub("%z", "")
		local off, result = 1, {}
		while true do
			local nStart, nEnd = full:find(sep, off)
			if not nEnd then
				local res = string.sub(full, off, string.len(full))
				if #res > 0 then
					table.insert(result, res)
				end
				break
			else
				table.insert(result, string.sub(full, off, nStart - 1))
				off = nEnd + 1
			end
		end
		return result
	end
	return {}
end

function is_exist(table, value)
	for index, k in ipairs(table) do
		if k == value then
			return true
		end
	end
	return false
end

function repeat_exist(table, value)
	local count = 0
	for index, k in ipairs(table) do
		if k:find("-") and k == value then
			count = count + 1
		end
	end
	if count > 1 then
		return true
	end
	return false
end

function remove(...)
	for index, value in ipairs({...}) do
		if value and #value > 0 and value ~= "/" then
			sys.call("rm -rf " .. util.shellquote(value))
		end
	end
end

function is_install(package)
	if package and #package > 0 then
		local file_path = "/usr/lib/opkg/info"
		local file_ext = ".control"
		if fs.stat(file_path, "type") ~= "dir" then
			file_path = "/lib/apk/packages"
			file_ext = ".list"
		end
		local st = fs.stat(file_path .. "/" .. package .. file_ext)
		return st ~= nil and (st.size or 0) > 0
	end
	return false
end

function get_args(arg)
	local var = {}
	for i, arg_k in pairs(arg) do
		if i > 0 then
			local v = arg[i + 1]
			if v then
				if repeat_exist(arg, v) == false then
					var[arg_k] = v
				end
			end
		end
	end
	return var
end

function get_function_args(arg)
	local var = nil
	if arg and #arg > 1 then
		local param = {}
		for i = 2, #arg do
			param[#param + 1] = arg[i]
		end
		var = get_args(param)
	end
	return var
end

function strToTable(str)
	if str == nil or type(str) ~= "string" then
		return {}
	end

	local chunk = loadstring("return " .. str)
	if not chunk then
		return {}
	end
	setfenv(chunk, {})
	local ok, result = pcall(chunk)
	if ok and type(result) == "table" then
		return result
	end
	return {}
end

function is_normal_node(e)
	if e and e.type and e.protocol and (e.protocol == "_balancing" or e.protocol == "_shunt" or e.protocol == "_iface" or e.protocol == "_urltest") then
		return false
	end
	return true
end

function is_special_node(e)
	return is_normal_node(e) == false
end

function is_ip(val)
	local str = val:match("%[(.-)%]") or val
	return datatypes.ipaddr(str) or false
end

function is_ipv6(val)
	local str = val:match("%[(.-)%]") or val
	return datatypes.ip6addr(str) or false
end

function is_ipv6addrport(val)
	local address, port = val:match("%[(.-)%]:([0-9]+)$")
	if address and datatypes.ip6addr(address) and datatypes.port(port) then
		return true
	end
	return false
end

function get_ipv6_only(val)
	local result = ""
	local inner = val:match("%[(.-)%]") or val
	if datatypes.ip6addr(inner) then
		result = inner
	end
	return result
end

function get_ipv6_full(val)
	local result = ""
	if is_ipv6(val) then
		result = val
		if not val:match("%[.-%]") then
			result = "[" .. result .. "]"
		end
	end
	return result
end

function get_ip_type(val)
	if is_ipv6(val) then
		return "6"
	elseif datatypes.ip4addr(val) then
		return "4"
	end
	return ""
end

function is_mac(val)
	return datatypes.macaddr(val)
end

function ip_or_mac(val)
	if val then
		if get_ip_type(val) == "4" then
			return "ip"
		end
		if is_mac(val) then
			return "mac"
		end
	end
	return ""
end

function iprange(val)
	if val then
		local ipStart, ipEnd = val:match("^([^/]+)-([^/]+)$")
		if (ipStart and datatypes.ip4addr(ipStart)) and (ipEnd and datatypes.ip4addr(ipEnd)) then
			return true
		end
	end
	return false
end

function get_domain_from_url(url)
	local domain = string.match(url, "//([^/]+)")
	if domain then
		return domain
	end
	return url
end

function get_node_name(node_id)
	local e
	if type(node_id) == "table" then
		e = node_id
	else
		e = uci:get_all(appname, node_id)
	end
	if e then
		if e.type and e.remarks then
			if e.protocol and (e.protocol == "_balancing" or e.protocol == "_shunt" or e.protocol == "_iface") then
				local type = e.type
				if type == "sing-box" then type = "Sing-Box" end
				local remark = "%s：[%s] " % {type .. " " .. i18n.translatef(e.protocol), e.remarks}
				return remark
			end
		end
	end
	return ""
end

local PROTOCOL_LABELS = {
	vmess = "VMess",
	vless = "VLESS",
	shadowsocks = "SS",
	shadowsocksr = "SSR",
	wireguard = "WG",
	hysteria = "HY",
	hysteria2 = "HY2",
	anytls = "AnyTLS",
	ssh = "SSH"
}

local function protocol_label(protocol)
	return PROTOCOL_LABELS[protocol] or protocol:gsub("^%l", string.upper)
end

local valid_nodes_cache = nil

function get_valid_nodes()
	if valid_nodes_cache then
		return valid_nodes_cache
	end
	local show_node_info = uci_get_type("global_other", "show_node_info") or "0"
	local nodes = {}
	local default_nodes = {}
	local other_nodes = {}
	uci:foreach(appname, "nodes", function(e)
		e.id = e[".name"]
		if e.type and e.remarks then
			if e.protocol and (e.protocol == "_balancing" or e.protocol == "_shunt" or e.protocol == "_iface" or e.protocol == "_urltest") then
				local type = e.type
				if type == "sing-box" then type = "Sing-Box" end
				e["remark"] = "%s：[%s] " % {type .. " " .. i18n.translatef(e.protocol), e.remarks}
				e["node_type"] = "special"
				if not e.group or e.group == "" then
					default_nodes[#default_nodes + 1] = e
				else
					other_nodes[#other_nodes + 1] = e
				end
			end
			local port = e.port or e.hysteria_hop or e.hysteria2_hop
			if port and e.address then
				local address = e.address
				if is_ip(address) or datatypes.hostname(address) then
					local type = e.type
					if (type == "sing-box" or type == "Xray") and e.protocol then
						local protocol = protocol_label(e.protocol)
						if type == "sing-box" then type = "Sing-Box" end
						type = type .. " " .. protocol
					end
					if is_ipv6(address) then address = get_ipv6_full(address) end
					e["remark"] = "%s：[%s]" % {type, e.remarks}
					if show_node_info == "1" then
						port = port:gsub(":", "-")
						e["remark"] = "%s：[%s] %s:%s" % {type, e.remarks, address, port}
					end
					e.node_type = "normal"
					if not e.group or e.group == "" then
						default_nodes[#default_nodes + 1] = e
					else
						other_nodes[#other_nodes + 1] = e
					end
				end
			end
		end
	end)
	for i = 1, #default_nodes do nodes[#nodes + 1] = default_nodes[i] end
	for i = 1, #other_nodes do nodes[#nodes + 1] = other_nodes[i] end
	valid_nodes_cache = nodes
	return nodes
end

function get_node_remarks(n)
	local remarks = ""
	if n then
		if n.protocol and (n.protocol == "_balancing" or n.protocol == "_shunt" or n.protocol == "_iface" or n.protocol == "_urltest") then
			remarks = "%s：[%s] " % {n.type .. " " .. i18n.translatef(n.protocol), n.remarks}
		else
			local type2 = n.type
			if (n.type == "sing-box" or n.type == "Xray") and n.protocol then
				local protocol = protocol_label(n.protocol)
				if type2 == "sing-box" then type2 = "Sing-Box" end
				type2 = type2 .. " " .. protocol
			end
			remarks = "%s：[%s]" % {type2, n.remarks}
		end
	end
	return remarks
end

function get_full_node_remarks(n)
	local remarks = get_node_remarks(n)
	if #remarks > 0 then
		local port = n.port or n.hysteria_hop or n.hysteria2_hop
		if n.address and port then
			port = port:gsub(":", "-")
			remarks = remarks .. " " .. n.address .. ":" .. port
		end
	end
	return remarks
end

function gen_uuid(format)
	local uuid = sys.exec("echo -n $(cat /proc/sys/kernel/random/uuid)")
	if format == nil then
		uuid = string.gsub(uuid, "-", "")
	end
	return uuid
end

function gen_short_uuid()
	return sys.exec("echo -n $(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 8)")
end

function uci_get_type(type, config, default)
	local value = uci:get_first(appname, type, config, default) or sys.exec("echo -n $(uci -q get " .. util.shellquote(string.format("%s.@%s[0].%s", appname, type, config)) .. ")")
	if (value == nil or value == "") and (default and default ~= "") then
		value = default
	end
	return value
end

function uci_get_type_id(id, config, default)
	local value = uci:get(appname, id, config, default) or sys.exec("echo -n $(uci -q get " .. util.shellquote(string.format("%s.%s.%s", appname, id, config)) .. ")")
	if (value == nil or value == "") and (default and default ~= "") then
		value = default
	end
	return value
end

function chmod_755(file)
	if file and file ~= "" then
		if not fs.access(file, "rwx", "rx", "rx") then
			fs.chmod(file, 755)
		end
	end
end

function get_customed_path(e)
	return uci_get_type("global_app", e .. "_file")
end

function finded_com(e)
	local bin = get_app_path(e)
	if not bin then return end
	local s = luci.sys.exec("echo -n $(type -t -p " .. util.shellquote(bin) .. " | head -n1)")
	if s == "" then
		s = nil
	end
	return s
end

function finded(e)
	local q = util.shellquote(e)
	return luci.sys.exec("echo -n $(type -t -p " .. util.shellquote("/bin/" .. e) .. " -p " .. util.shellquote("/usr/bin/" .. e) .. " " .. q .. " | head -n1)")
end

function is_finded(e)
	return finded(e) ~= "" and true or false
end

function clone(org)
	local function copy(org, res)
		for k,v in pairs(org) do
			if type(v) ~= "table" then
				res[k] = v;
			else
				res[k] = {};
				copy(v, res[k])
			end
		end
	end

	local res = {}
	copy(org, res)
	return res
end

local bin_version_mem_cache = {}

local function get_bin_version_cache(file, cmd)
	if not file then return "" end
	local mem_key = file .. "\1" .. (cmd or "")
	if bin_version_mem_cache[mem_key] then
		return bin_version_mem_cache[mem_key]
	end
	sys.call("mkdir -p /tmp/etc/passwall2_tmp")
	if fs.access(file) then
		chmod_755(file)
		local q_file = util.shellquote(file)
		local md5 = sys.exec("echo -n $(md5sum " .. q_file .. " | awk '{print $1}')")
		local cache_file = "/tmp/etc/passwall2_tmp/" .. md5
		if md5 ~= "" and fs.access(cache_file) then
			local version = sys.exec("echo -n $(cat " .. util.shellquote(cache_file) .. ")")
			bin_version_mem_cache[mem_key] = version
			return version
		else
			local version = sys.exec("echo -n $(" .. q_file .. " " .. cmd .. ")")
			if version and version ~= "" then
				if md5 ~= "" then
					sys.call("echo " .. util.shellquote(version) .. " > " .. util.shellquote(cache_file))
				end
				bin_version_mem_cache[mem_key] = version
				return version
			end
		end
	end
	return ""
end

function get_app_path(app_name)
	if com[app_name] then
		local def_path = com[app_name].default_path
		local path = uci_get_type("global_app", app_name:gsub("%-","_") .. "_file")
		path = path and (#path>0 and path or def_path) or def_path
		return path
	end
end

function get_app_version(app_name, file)
	if file == nil then file = get_app_path(app_name) end
	return get_bin_version_cache(file, com[app_name].cmd_version)
end

function is_file(path)
	if path and #path > 1 then
		if fs.stat(path, "type") == "reg" then
			return true
		end
	end
	return nil
end

function is_dir(path)
	if path and #path > 1 then
		if fs.stat(path, "type") == "dir" then
			return true
		end
	end
	return nil
end

function get_final_dir(path)
	if is_dir(path) then
		return path
	else
		return get_final_dir(fs.dirname(path))
	end
end

function get_free_space(dir)
	if dir == nil then dir = "/" end
	local q = util.shellquote(dir)
	if sys.call("df -k " .. q .. " >/dev/null 2>&1") == 0 then
		return tonumber(sys.exec("echo -n $(df -k " .. q .. " | awk 'NR>1' | awk '{print $4}')"))
	end
	return 0
end

function get_file_space(file)
	if file == nil then return 0 end
	if fs.access(file) then
		return tonumber(sys.exec("echo -n $(du -k " .. util.shellquote(file) .. " | awk '{print $1}')"))
	end
	return 0
end

function _unpack(t, i)
	i = i or 1
	if t[i] ~= nil then return t[i], _unpack(t, i + 1) end
end

function exec(cmd, args, writer, timeout)
	local os = require "os"
	local nixio = require "nixio"

	local fdi, fdo = nixio.pipe()
	local pid = nixio.fork()

	if pid > 0 then
		fdo:close()

		if writer or timeout then
			local starttime = os.time()
			while true do
				if timeout and os.difftime(os.time(), starttime) >= timeout then
					nixio.kill(pid, nixio.const.SIGTERM)
					return 1
				end

				if writer then
					local buffer = fdi:read(2048)
					if buffer and #buffer > 0 then
						writer(buffer)
					end
				end

				local wpid, stat, code = nixio.waitpid(pid, "nohang")

				if wpid and stat == "exited" then return code end

				if not writer and timeout then nixio.nanosleep(1) end
			end
		else
			local wpid, stat, code = nixio.waitpid(pid)
			return wpid and stat == "exited" and code
		end
	elseif pid == 0 then
		nixio.dup(fdo, nixio.stdout)
		fdi:close()
		fdo:close()
		nixio.exece(cmd, args, nil)
		nixio.stdout:close()
		os.exit(1)
	end
end

function parseURL(url)
	if not url or url == "" then
		return nil
	end
	local pattern = "^(%w+)://"
	local protocol = url:match(pattern)

	if not protocol then

		return nil
	end

	local auth_host_port = url:sub(#protocol + 4)
	local auth_pattern = "^([^@]+)@"
	local auth = auth_host_port:match(auth_pattern)
	local username, password

	if auth then
		username, password = auth:match("^([^:]+):([^:]+)$")
		auth_host_port = auth_host_port:sub(#auth + 2)
	end

	local host, port = auth_host_port:match("^([^:]+):(%d+)$")

	if not host or not port then

		return nil
	end

	return {
		protocol = protocol,
		username = username,
		password = password,
		host = host,
		port = tonumber(port)
	}
end

function compare_versions(ver1, comp, ver2)
	local table = table

	if not ver1 then ver1 = "" end
	if not ver2 then ver2 = "" end

	local av1 = util.split(ver1, "[%.%-]", nil, true)
	local av2 = util.split(ver2, "[%.%-]", nil, true)

	local max = table.getn(av1)
	local n2 = table.getn(av2)
	if (max < n2) then max = n2 end

	for i = 1, max, 1 do
		local s1 = tonumber(av1[i] or 0) or 0
		local s2 = tonumber(av2[i] or 0) or 0

		if comp == "~=" and (s1 ~= s2) then return true end
		if (comp == "<" or comp == "<=") and (s1 < s2) then return true end
		if (comp == ">" or comp == ">=") and (s1 > s2) then return true end
		if (s1 ~= s2) then return false end
	end

	return not (comp == "<" or comp == ">")
end

function cacheFileCompareToLogic(file, str)
	local result = nil
	if file and str then
		local file_str = ""
		if fs.access(file) then
			file_str = sys.exec("cat " .. file)
		end

		if file_str ~= str then
			sys.call("rm -f " .. file)
			result = false
		else
			result = true
		end

		local f_out = io.open(file, "w")
		if f_out then
			f_out:write(str)
			f_out:close()
		end
	end
	return result
end

function is_js_luci()
	return sys.call('[ -f "/www/luci-static/resources/uci.js" ]') == 0
end

function set_apply_on_parse(map)
	if not map then
		return
	end
	local lang = uci:get("luci", "main", "lang") or "auto"
	if lang == "auto" then
		local http = require "luci.http"
		local aclang = http.getenv("HTTP_ACCEPT_LANGUAGE") or ""
		for lpat in aclang:gmatch("[%w-]+") do
			lpat = lpat and lpat:gsub("-", "_")
			if uci:get("luci", "languages", lpat) then
				lang = lpat
				break
			end
			lpat = lpat and lpat:lower()
			if uci:get("luci", "languages", lpat) then
				lang = lpat
				break
			end
		end
		if lang ~= "auto" then
			sh_uci_set(appname, "@global[0]", "auto_lang", lang, true)
		end
	end
	if is_js_luci() == true then
		local hide_popup_box = nil
		if hide_popup_box == true then
			map.apply_on_parse = false
			map.on_after_apply = function(self)
				if self.redirect then
					os.execute("sleep 1")
					luci.http.redirect(self.redirect)
				end
			end
		else
			apply_redirect(map)
			local old = map.on_after_save
			map.on_after_save = function(self)
				if old then old(self) end
				map:set("@global[0]", "timestamp", os.time())
			end
			local cbi = require "luci.cbi"
			map:append(cbi.Template(appname .. "/cbi/optimize_cbi_ui"))
		end
	end
end

function luci_types(id, m, s, type_name, option_prefix)
	local rewrite_option_table = {}
	for key, value in pairs(s.fields) do
		if key:find(option_prefix) == 1 then
			if not s.fields[key].not_rewrite then
				if s.fields[key].rewrite_option then
					if not rewrite_option_table[s.fields[key].rewrite_option] then
						rewrite_option_table[s.fields[key].rewrite_option] = 1
					else
						rewrite_option_table[s.fields[key].rewrite_option] = rewrite_option_table[s.fields[key].rewrite_option] + 1
					end
				end

				s.fields[key].cfgvalue = function(self, section)

					if self.custom_cfgvalue then
						return self:custom_cfgvalue(section)
					else
						if self.rewrite_option then
							return m:get(section, self.rewrite_option)
						else
							if self.option:find(option_prefix) == 1 then
								return m:get(section, self.option:sub(1 + #option_prefix))
							end
						end
					end
				end
				s.fields[key].write = function(self, section, value)
					if s.fields["type"]:formvalue(id) == type_name then

						if self.custom_write then
							self:custom_write(section, value)
						else
							if self.rewrite_option then
								m:set(section, self.rewrite_option, value)
							else
								if self.option:find(option_prefix) == 1 then
									m:set(section, self.option:sub(1 + #option_prefix), value)
								end
							end
						end
					end
				end
				s.fields[key].remove = function(self, section)
					if s.fields["type"]:formvalue(id) == type_name then

						if self.custom_remove then
							self:custom_remove(section)
						else
							if self.rewrite_option and rewrite_option_table[self.rewrite_option] == 1 then
								m:del(section, self.rewrite_option)
							else
								if self.option:find(option_prefix) == 1 then
									m:del(section, self.option:sub(1 + #option_prefix))
								end
							end
						end
					end
				end
			end

			local deps = s.fields[key].deps
			if #deps > 0 then
				for index, value in ipairs(deps) do
					deps[index]["type"] = type_name
				end
			else
				s.fields[key]:depends({ type = type_name })
			end
		end
	end
end
function format_go_time(input)
	input = input and trim(input)
	local N = 0
	if input and input:match("^%d+$") then
		N = tonumber(input)
	elseif input and input ~= "" then
		for value, unit in input:gmatch("(%d+)%s*([hms])") do
			value = tonumber(value)
			if unit == "h" then
				N = N + value * 3600
			elseif unit == "m" then
				N = N + value * 60
			elseif unit == "s" then
				N = N + value
			end
		end
	end
	if N <= 0 then
		return "0s"
	end
	local result = ""
	local h = math.floor(N / 3600)
	local m = math.floor(N % 3600 / 60)
	local s = N % 60
	if h > 0 then result = result .. h .. "h" end
	if m > 0 then result = result .. m .. "m" end
	if s > 0 or result == "" then result = result .. s .. "s" end
	return result
end

function apply_redirect(m)
	local tmp_uci_file = "/etc/config/" .. appname .. "_redirect"
	if m.redirect and m.redirect ~= "" then
		if fs.access(tmp_uci_file) then
			local redirect
			for line in io.lines(tmp_uci_file) do
				redirect = line:match("option%s+url%s+['\"]([^'\"]+)['\"]")
				if redirect and redirect ~= "" then break end
			end
			if redirect and redirect ~= "" then
				sys.call("/bin/rm -f " .. tmp_uci_file)
				luci.http.redirect(redirect)
			end
		else
			fs.writefile(tmp_uci_file, "config redirect\n")
		end
		m.on_after_save = function(self)
			local redirect = self.redirect
			if redirect and redirect ~= "" then
				uci:set(appname .. "_redirect", "@redirect[0]", "url", redirect)
			end
		end
	else
		sys.call("/bin/rm -f " .. tmp_uci_file)
	end
end
