local _M = {}

_M.hysteria = {
	cmd_version = "version | awk '/^Version:/ {print $2}'",
	default_path = "/usr/bin/hysteria"
}

_M["sing-box"] = {
	cmd_version = "version | awk '{print $3}' | sed -n 1P",
	default_path = "/usr/bin/sing-box"
}

_M.xray = {
	cmd_version = "version | awk '{print $2}' | sed -n 1P",
	default_path = "/usr/bin/xray"
}

return _M
