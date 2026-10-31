#!/bin/sh

. /usr/share/passwall2/utils.sh

url_test_node() {
	local result=0
	local node_id=$1
	local _type=$(echo $(config_n_get "${node_id}" type) | tr 'A-Z' 'a-z')
	[ -n "${_type}" ] && {
		local _tmp_port=$(get_new_port 48900 tcp,udp)
		/usr/share/${CONFIG}/app.sh run_socks flag="url_test_${node_id}" node="${node_id}" bind=127.0.0.1 socks_port=${_tmp_port} config_file="url_test_${node_id}.json"
		local curlx="socks5h://127.0.0.1:${_tmp_port}"
		sleep 1s
		local url=$(config_t_get global_other url_test_url https://www.google.com/generate_204)
		case "${url}" in
			http://*|https://*) ;;
			*) url="https://www.google.com/generate_204" ;;
		esac
		result=$(curl --connect-timeout 3 --proto '=http,https' -o /dev/null -I -skL -w "%{http_code}:%{time_starttransfer}" -x "$curlx" -- "${url}")
		pgrep -af "url_test_${node_id}" | awk '! /test\.sh/{print $1}' | xargs kill -9 >/dev/null 2>&1
		rm -rf /tmp/etc/${CONFIG}/*url_test_${node_id}*.json
	}
	echo $result
}

arg1=$1
shift
case $arg1 in
url_test_node)
	url_test_node "$@"
	;;
esac
