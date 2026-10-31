local _M = {}

_M.xray = {
	cmd_version = "version | awk '{print $2}' | sed -n 1P",
	default_path = "/usr/bin/xray"
}

return _M
