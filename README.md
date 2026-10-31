# PassWall2 LT

This is a modified version of Passwall2 with changes including lightweight and faster code execution.
The main goal of this version is to make it suitable and performant for routers with Limited Flash Storage. the modifications include a noticeable reduction in the unnecessary dependencies as well as optimizations in the Lua codes.

## 1. Modifications

The overall codebase is roughly **20% smaller** than the official version, mainly because entire unused subsystems were removed rather than trimmed.

- **Removed the Server Side** Completely from Back-End and Front-End
- **Removed the Node Subscribe feature** (`subscribe.lua`, ~2,100 lines). This was the auto-updating subscription URL system that periodically downloaded node lists from remote servers over `curl`. It has been removed entirely, along with its settings pages.
- **Removed GeoIP/GeoSite `.dat` file management** (rule downloading, conversion, and related settings pages, ~550 lines). The app no longer downloads or converts geo-data files. Manual routing rules (the Shunt Rule table) are fully preserved and unaffected. Only the old automatic geo-database pipeline is gone.
- **Removed the built-in "check for updates" / self-update mechanism** (~350 lines of dead code in the core API module). This code checked GitHub for new binary releases and downloaded them; it was already unreachable from the UI and has now been fully deleted.
- **Reduced curl dependency.** With subscriptions and geo-data downloads removed, the project no longer needs the `curl` package for its core functionality (a few optional, user-triggered features such as node connectivity testing still use it).
- **Core API module (`api.lua`) is about 30% smaller** (1,431 → ~996 lines) after removing the above dead code paths.
- Redesigned the Node Tables
- Added a Built-in Modal Overlay
  
## 2. Performance (fewer repeated operations, lower memory use)

- **Removed repeated, redundant computation.** The full node list was being recalculated from scratch multiple times during a single page load (once for every protocol type). It is now computed once and reused, cutting redundant work on setups with many nodes.
- **Replaced shell subprocess calls with direct system calls** for common checks (file/directory existence, installed-package checks). Previously each check spawned a new shell process; now it's a single in-process call, which is both faster and lighter on system resources, especially noticeable on lower-power routers.
- **Removed two extra subprocess spawns per custom DNS entry** during config generation, replaced with a single in-memory text operation.
- **Replaced long chains of repeated comparisons** (used for labeling proxy protocols) with a single lookup table, which is faster and avoids duplicated logic in two different places.
- **Added lightweight caching** for repeated binary-version lookups, avoiding unnecessary repeated shell calls within the same request.

## 3. Security

- **Fixed command injection vulnerabilities in dozens of locations** across the firewall, subscription, and configuration-generation scripts. The most serious case allowed a value coming from a remote/untrusted source (a node's "remarks" field) to break out of its intended context and execute arbitrary shell commands with root privileges when the firewall rules were generated. All such values are now properly escaped at their source, closing the entire class of issue in one place rather than patching each call site individually.
- **Fixed a path traversal vulnerability** in the log-viewing endpoints, which previously could be tricked into reading files outside their intended directory.
- **Fixed a stored XSS vulnerability** where log content was rendered directly in the admin browser without escaping; it is now properly sanitized before display.
- **Removed unrestricted dynamic code execution.** A helper function used to convert stored text into a Lua value by executing it directly; it is now run in a restricted, sandboxed environment that cannot access the filesystem, network, or shell. This eliminates a potential remote-code-execution path.
- **Replaced several risky filesystem checks that shelled out to the OS** (e.g. `[ -f file ]` via a subprocess) with direct, injection-proof system calls, a security improvement that came as a side effect of the performance work above.
  
---

*Everything listed above was verified to keep the core proxy/routing logic (Xray and sing-box configuration generation, firewall redirect rules) unchanged in behavior. These are hardening and cleanup changes, not a redesign of how traffic is routed.*

---

## ⬇️ Installation 

OpenWrt 24.10

```bash
wget -O /tmp/luci-app-passwall2-26-r8-lt.ipk https://github.com/fullband7/openwrt-passwall2-lt/releases/download/v26.10-r8-lt/luci-app-passwall2-lt.ipk
opkg install /tmp/luci-app-passwall2-lt.ipk
rm /tmp/luci-app-passwall2-lt.ipk
service rpcd restart
```

OpenWrt 25.12

```bash
wget -O /tmpluci-app-passwall2-26-r8-lt.apk https://github.com/fullband7/openwrt-passwall2-lt/releases/download/v26.10-r8-lt/luci-app-passwall2-lt.apk
apk add --allow-untrusted /tmp/luci-app-passwall2-lt.apk
rm /tmp/luci-app-passwall2-lt.apk
service rpcd restart
```
