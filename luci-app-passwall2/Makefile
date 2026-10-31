include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-passwall2
PKG_VERSION:=26.10
PKG_RELEASE:=7

PKG_MAINTAINER:=PassWall 2
PKG_LICENSE:=GPL-3.0-only

LUCI_TITLE:=LuCI support for PassWall 2
LUCI_DESCRIPTION:=PassWall 2 is a proxy and traffic routing manager for the LuCI web interface.
LUCI_DEPENDS:=+libc +coreutils +coreutils-nohup +curl +ip-full +libuci-lua +lua +luci-compat +luci-lib-jsonc +resolveip +tcping

CONFIG_LUCI_CSSTIDY:=

define Package/$(PKG_NAME)/conffiles
/etc/config/passwall2
/usr/share/passwall2/domains_excluded
endef

define Package/$(PKG_NAME)/postinst
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] || [ -n "$${APK_INSTROOT}" ] && exit 0

chmod 0755 /etc/init.d/passwall2 2>/dev/null
chmod 0755 /etc/hotplug.d/iface/98-passwall2 2>/dev/null
chmod 0755 /etc/uci-defaults/luci-passwall2 2>/dev/null
chmod 0755 /usr/share/passwall2/*.sh 2>/dev/null

[ -f /etc/uci-defaults/luci-passwall2 ] && ( . /etc/uci-defaults/luci-passwall2 ) && rm -f /etc/uci-defaults/luci-passwall2

rm -f /tmp/luci-indexcache /tmp/luci-indexcache.*
rm -rf /tmp/luci-modulecache/

[ -x /etc/init.d/rpcd ] && /etc/init.d/rpcd restart 2>/dev/null

exit 0
endef

define Package/$(PKG_NAME)/postrm
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] || [ -n "$${APK_INSTROOT}" ] && exit 0

uci -q delete ucitrack.@passwall2[-1]
uci -q commit ucitrack

uci -q delete firewall.passwall2
uci -q commit firewall

rm -rf /tmp/etc/passwall2 /tmp/etc/passwall2_tmp
rm -f /tmp/log/passwall2.log
rm -f /tmp/luci-indexcache /tmp/luci-indexcache.*
rm -rf /tmp/luci-modulecache/

[ -x /etc/init.d/rpcd ] && /etc/init.d/rpcd restart 2>/dev/null

exit 0
endef

include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage - OpenWrt buildroot signature
