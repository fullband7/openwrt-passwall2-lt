module("luci.passwall2.util_link", package.seeall)

local api = require "luci.passwall2.api"
local jsonc = luci.jsonc

local function url_decode(str)
	if not str then return "" end
	str = str:gsub("+", " ")
	str = str:gsub("%%(%x%x)", function(h) return string.char(tonumber(h, 16)) end)
	return str
end

local function parse_query(str)
	local t = {}
	if not str or str == "" then return t end
	for pair in str:gmatch("[^&]+") do
		local k, v = pair:match("^([^=]+)=?(.*)$")
		if k and k ~= "" then
			t[url_decode(k)] = url_decode(v or "")
		end
	end
	return t
end

local function split_userinfo_hostport(str)
	local userinfo, hostpart = str:match("^(.-)@(.+)$")
	if not userinfo then return nil, nil, nil end
	local host, port = hostpart:match("^%[(.-)%]:(%d+)$")
	if not host then
		host, port = hostpart:match("^(.-):(%d+)$")
	end
	if not host then return nil, nil, nil end
	return userinfo, host, port
end

local function sanitize_remark(s)
	s = s or ""
	s = s:gsub("[<>\"'&]", "")
	s = s:gsub("[\r\n\t]", " ")
	if #s > 100 then s = s:sub(1, 100) end
	return s
end

local transport_map = {
	tcp = "raw", raw = "raw",
	kcp = "mkcp", mkcp = "mkcp",
	ws = "ws", grpc = "grpc",
	httpupgrade = "httpupgrade",
	xhttp = "xhttp", splithttp = "xhttp",
}

local function map_transport(net)
	return transport_map[net or "tcp"] or "raw"
end

local function parse_vmess(link)
	local rest = link:match("^vmess://(.*)$")
	if not rest then return nil, nil, "malformed link" end

	local b64_part, frag = rest:match("^(.-)#(.*)$")
	b64_part = b64_part or rest

	local decoded = api.base64Decode(b64_part)
	local data = jsonc.parse(decoded)
	if not data or not data.add or not data.port then
		return nil, nil, "invalid vmess payload"
	end

	local fields = {
		xray_protocol = "vmess",
		xray_address = data.add,
		xray_port = tostring(data.port),
		xray_uuid = data.id,
		xray_security = (data.scy and data.scy ~= "") and data.scy or "auto",
	}

	local net = data.net or "tcp"
	fields.xray_transport = map_transport(net)

	local host = data.host or ""
	local path = data.path or ""
	if net == "ws" then
		fields.xray_ws_host = host
		fields.xray_ws_path = path
	elseif net == "grpc" then
		fields.xray_grpc_serviceName = (path ~= "" and path) or host
	elseif net == "httpupgrade" then
		fields.xray_httpupgrade_host = host
		fields.xray_httpupgrade_path = path
	elseif net == "xhttp" or net == "splithttp" then
		fields.xray_xhttp_host = host
		fields.xray_xhttp_path = path
	end

	local tls = data.tls or ""
	if tls == "tls" or tls == "reality" then
		fields.xray_tls = "1"
		fields.xray_tls_serverName = (data.sni and data.sni ~= "") and data.sni or host
		if data.fp and data.fp ~= "" then
			fields.xray_utls = "1"
			fields.xray_fingerprint = data.fp
		end
	else
		fields.xray_tls = "0"
	end

	local remark = (data.ps and data.ps ~= "" and data.ps)
		or (frag and url_decode(frag))
		or (data.add .. ":" .. tostring(data.port))
	return "Xray", fields, sanitize_remark(remark)
end

local function parse_vless_or_trojan(link, scheme)
	local rest = link:match("^%w+://(.*)$")
	if not rest then return nil, nil, "malformed link" end

	local main, frag = rest:match("^(.-)#(.*)$")
	main = main or rest

	local userpart, query = main:match("^(.-)%?(.*)$")
	userpart = (userpart or main):gsub("/$", "")
	query = query or ""

	local userinfo, host, port = split_userinfo_hostport(userpart)
	if not userinfo or not host or not port then
		return nil, nil, "malformed address"
	end

	local q = parse_query(query)
	local fields = {
		xray_address = host,
		xray_port = port,
	}

	if scheme == "vless" then
		fields.xray_protocol = "vless"
		fields.xray_uuid = userinfo
		fields.xray_encryption = (q.encryption and q.encryption ~= "") and q.encryption or "none"
		if q.flow and q.flow ~= "" then
			fields.xray_flow = q.flow
		end
	else
		fields.xray_protocol = "trojan"
		fields.xray_password = userinfo
	end

	local net = q.type or "tcp"
	fields.xray_transport = map_transport(net)
	if net == "ws" then
		fields.xray_ws_host = (q.host and q.host ~= "") and q.host or host
		fields.xray_ws_path = (q.path and q.path ~= "") and q.path or "/"
	elseif net == "grpc" then
		fields.xray_grpc_serviceName = q.serviceName or ""
		if q.mode and q.mode ~= "" then
			fields.xray_grpc_mode = q.mode
		end
	elseif net == "httpupgrade" then
		fields.xray_httpupgrade_host = (q.host and q.host ~= "") and q.host or host
		fields.xray_httpupgrade_path = (q.path and q.path ~= "") and q.path or "/"
	elseif net == "xhttp" or net == "splithttp" then
		fields.xray_xhttp_host = (q.host and q.host ~= "") and q.host or host
		fields.xray_xhttp_path = (q.path and q.path ~= "") and q.path or "/"
		if q.mode and q.mode ~= "" then
			fields.xray_xhttp_mode = q.mode
		end
	end

	local security = q.security or ""
	if security == "tls" or security == "reality" then
		fields.xray_tls = "1"
		fields.xray_tls_serverName = (q.sni and q.sni ~= "") and q.sni or host
		if q.alpn and q.alpn ~= "" then
			fields.xray_alpn = q.alpn
		end
		if q.fp and q.fp ~= "" then
			fields.xray_utls = "1"
			fields.xray_fingerprint = q.fp
		end
		if security == "reality" then
			fields.xray_reality = "1"
			fields.xray_reality_publicKey = q.pbk or ""
			fields.xray_reality_shortId = q.sid or ""
			if q.spx and q.spx ~= "" then
				fields.xray_reality_spiderX = q.spx
			end
		else
			fields.xray_reality = "0"
		end
	else
		fields.xray_tls = "0"
	end

	local remark = (frag and url_decode(frag)) or (host .. ":" .. port)
	return "Xray", fields, sanitize_remark(remark)
end

local function parse_ss(link)
	local rest = link:match("^ss://(.*)$")
	if not rest then return nil, nil, "malformed link" end

	local main, frag = rest:match("^(.-)#(.*)$")
	main = main or rest

	local before_query = main:match("^(.-)%?.*$")
	if before_query then
		main = before_query
	end
	main = main:gsub("/$", "")

	local method, password, host, port

	if main:find("@") then
		local userinfo, hostpart = main:match("^(.-)@(.+)$")
		local h, p = hostpart:match("^(.-):(%d+)$")
		if not h then return nil, nil, "malformed address" end
		local decoded = userinfo:find(":") and userinfo or api.base64Decode(userinfo)
		method, password = decoded:match("^(.-):(.*)$")
		host, port = h, p
	else
		local decoded = api.base64Decode(main)
		method, password, host, port = decoded:match("^(.-):(.-)@(.-):(%d+)$")
	end

	if not method or not host or not port then
		return nil, nil, "malformed ss link"
	end

	local fields = {
		ss_address = host,
		ss_port = port,
		ss_method = method,
		ss_password = password,
	}

	local remark = (frag and url_decode(frag)) or (host .. ":" .. port)
	return "SS", fields, sanitize_remark(remark)
end

local function parse_ssr(link)
	local rest = link:match("^ssr://(.*)$")
	if not rest then return nil, nil, "malformed link" end

	local decoded = api.base64Decode(rest)
	local main, query = decoded:match("^(.-)/%?(.*)$")
	main = main or decoded
	query = query or ""

	local host, port, protocol, method, obfs, password_b64 =
		main:match("^(.-):(%d+):(.-):(.-):(.-):(.*)$")
	if not host then return nil, nil, "malformed ssr link" end

	local password = api.base64Decode(password_b64)
	local q = parse_query(query)

	local fields = {
		ssr_address = host,
		ssr_port = port,
		ssr_protocol = protocol,
		ssr_method = method,
		ssr_obfs = obfs,
		ssr_password = password,
	}
	if q.obfsparam and q.obfsparam ~= "" then
		fields.ssr_obfs_param = api.base64Decode(q.obfsparam)
	end
	if q.protoparam and q.protoparam ~= "" then
		fields.ssr_protocol_param = api.base64Decode(q.protoparam)
	end

	local remark = host .. ":" .. port
	if q.remarks and q.remarks ~= "" then
		remark = api.base64Decode(q.remarks)
	end

	return "SSR", fields, sanitize_remark(remark)
end

local function parse_hysteria2(link)
	local rest = link:match("^%w+://(.*)$")
	if not rest then return nil, nil, "malformed link" end

	local main, frag = rest:match("^(.-)#(.*)$")
	main = main or rest

	local userpart, query = main:match("^(.-)%?(.*)$")
	userpart = (userpart or main):gsub("/$", "")
	query = query or ""

	local password, hostpart = userpart:match("^(.-)@(.+)$")
	if not password then return nil, nil, "malformed address" end
	local host, port = hostpart:match("^(.-):(%d+)$")
	if not host then return nil, nil, "malformed address" end

	local q = parse_query(query)
	local fields = {
		hysteria2_address = host,
		hysteria2_port = port,
		hysteria2_auth_password = password,
	}
	if q.sni and q.sni ~= "" then
		fields.hysteria2_tls_serverName = q.sni
	end
	if q.insecure == "1" then
		fields.hysteria2_tls_allowInsecure = "1"
	end
	if q.obfs and q.obfs ~= "" and q.obfs ~= "none" then
		fields.hysteria2_obfs_type = q.obfs
		if q["obfs-password"] and q["obfs-password"] ~= "" then
			fields.hysteria2_obfs = q["obfs-password"]
		end
	end
	if q.mport and q.mport ~= "" then
		fields.hysteria2_hop = q.mport
	end

	local remark = (frag and url_decode(frag)) or (host .. ":" .. port)
	return "Hysteria2", fields, sanitize_remark(remark)
end

local function parse_tuic(link)
	local rest = link:match("^tuic://(.*)$")
	if not rest then return nil, nil, "malformed link" end

	local main, frag = rest:match("^(.-)#(.*)$")
	main = main or rest

	local userpart, query = main:match("^(.-)%?(.*)$")
	userpart = (userpart or main):gsub("/$", "")
	query = query or ""

	local userinfo, hostpart = userpart:match("^(.-)@(.+)$")
	if not userinfo then return nil, nil, "malformed address" end
	local host, port = hostpart:match("^(.-):(%d+)$")
	if not host then return nil, nil, "malformed address" end

	local uuid, password = userinfo:match("^(.-):(.*)$")
	if not uuid then uuid, password = userinfo, "" end

	local q = parse_query(query)
	local fields = {
		tuic_address = host,
		tuic_port = port,
		tuic_uuid = uuid,
		tuic_password = password,
	}
	if q.congestion_control and q.congestion_control ~= "" then
		fields.tuic_congestion_control = q.congestion_control
	end
	if q.udp_relay_mode and q.udp_relay_mode ~= "" then
		fields.tuic_udp_relay_mode = q.udp_relay_mode
	end

	local remark = (frag and url_decode(frag)) or (host .. ":" .. port)
	return "TUIC", fields, sanitize_remark(remark)
end

-- Parses one share link and returns type_name, fields (UCI option table), remarks
-- or nil, nil, error_message on failure.
function parse_link(line)
	line = api.trim(line)
	if line == "" then return nil, nil, nil end

	if line:match("^vmess://") then
		return parse_vmess(line)
	elseif line:match("^vless://") then
		return parse_vless_or_trojan(line, "vless")
	elseif line:match("^trojan://") then
		return parse_vless_or_trojan(line, "trojan")
	elseif line:match("^ss://") then
		return parse_ss(line)
	elseif line:match("^ssr://") then
		return parse_ssr(line)
	elseif line:match("^hysteria2://") or line:match("^hy2://") then
		return parse_hysteria2(line)
	elseif line:match("^tuic://") then
		return parse_tuic(line)
	else
		return nil, nil, "unsupported link scheme"
	end
end
