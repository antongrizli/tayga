include $(TOPDIR)/rules.mk

PKG_NAME:=tayga-managed-openwrt
PKG_VERSION:=@VERSION@
PKG_RELEASE:=7
PKG_LICENSE:=GPL-2.0-or-later
PKG_LICENSE_FILES:=LICENSE
PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk

# APK SDKs require a version constraint on every runtime-only dependency.
# Keep the established opkg syntax for the IPK branch.
tayga_runtime_dep = $(1)$(if $(CONFIG_USE_APK), (>=0))
tayga_exact_dep = $(1) $(if $(CONFIG_USE_APK),(=$(PKG_VERSION)-r$(PKG_RELEASE)),(= $(PKG_VERSION)-r$(PKG_RELEASE)))

define Package/tayga-managed-openwrt
  SECTION:=net
  CATEGORY:=Network
  TITLE:=TAYGA managed tools (binary only)
  DEPENDS:=@IPV6 +libpthread
  # Runtime-only: the SDK already contains kernel artifacts; do not rebuild
  # its entire package/kernel/linux directory to compile this userspace tool.
  EXTRA_DEPENDS:=$(call tayga_runtime_dep,kmod-tun)
  CONFLICTS:=tayga tayga-managed
endef

define Package/tayga-managed-openwrt/description
  SDK-built TAYGA and PREF64 discovery tools. Does not activate profiles,
  modify UCI/network/DNS/firewall, or install an init service.
endef

define Package/tayga-managed-openwrt-procd
  SECTION:=net
  CATEGORY:=Network
  TITLE:=TAYGA optional procd service for externally prepared networking
  PROVIDES:=tayga-openwrt-core-upgrade-api-1
  DEPENDS:=+tayga-managed-openwrt
  EXTRA_DEPENDS:=$(call tayga_exact_dep,tayga-managed-openwrt), $(call tayga_runtime_dep,procd), $(call tayga_runtime_dep,uci), $(call tayga_runtime_dep,flock), $(call tayga_runtime_dep,netifd), $(call tayga_runtime_dep,jshn)
endef

define Package/tayga-managed-openwrt-procd/description
  Disabled by default in UCI. Supervises one TAYGA process using an existing
  TUN and administrator-prepared routes/firewall. Persistent config snapshots
  and file recovery; does not configure WAN, fw4, or DNS.
endef

define Package/tayga-managed-openwrt-procd/conffiles
/etc/config/tayga_managed
endef

define Package/tayga-managed-openwrt-network
  SECTION:=net
  CATEGORY:=Network
  TITLE:=TAYGA owned CLAT/NAT64/SIIT netifd, fw4 and DNS integration
  DEPENDS:=+tayga-managed-openwrt-procd
  EXTRA_DEPENDS:=$(call tayga_exact_dep,tayga-managed-openwrt-procd), $(call tayga_runtime_dep,firewall4), $(call tayga_runtime_dep,nftables), $(call tayga_runtime_dep,coreutils-timeout)
endef

define Package/tayga-managed-openwrt-network/description
  Optional managed CLAT/NAT64/SIIT TUN, addresses, routes, fw4 includes,
  runtime dnsmasq/DNS64 integration and readiness rollback.
  Does not rewrite network/firewall/dhcp UCI settings.
endef

define Package/tayga-managed-openwrt-network/prerm
#!/bin/sh
[ -n "$$IPKG_INSTROOT" ] && exit 0
if [ -d /var/run/tayga-managed/network ]; then
	/etc/init.d/tayga-managed stop || exit 1
fi
exit 0
endef

define Package/tayga-managed-openwrt-upgrade
  SECTION:=net
  CATEGORY:=Network
  TITLE:=TAYGA independent package upgrade and boot recovery coordinator
  DEPENDS:=+tayga-managed-openwrt-network
  EXTRA_DEPENDS:=tayga-managed-openwrt-procd $(if $(CONFIG_USE_APK),(>=$(PKG_VERSION)-r$(PKG_RELEASE)),(>= $(PKG_VERSION)-r$(PKG_RELEASE)))
endef

define Package/tayga-managed-openwrt-upgrade/description
  Stable coordinator for replacing the base/procd/network package set.
  Retains previous archives and accepted state; boot recovery runs before TAYGA.
endef

define Package/tayga-managed-openwrt-upgrade/prerm
#!/bin/sh
[ -n "$$IPKG_INSTROOT" ] && exit 0
if [ -e /etc/tayga-managed/package-upgrade ] || [ -L /etc/tayga-managed/package-upgrade ]; then exit 1; fi
flock -n /var/lock/tayga-package-upgrade.lock true || exit 1
exit 0
endef

define Package/tayga-managed-openwrt/conffiles
/etc/tayga/tayga.conf.example
endef

define Build/Prepare
	$(call Build/Prepare/Default)
	$(CP) ./source/. $(PKG_BUILD_DIR)/
endef

define Build/Configure
endef

define Build/Compile
	+$(MAKE) $(PKG_JOBS) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" AR="$(TARGET_AR)" \
		CFLAGS="$(TARGET_CFLAGS) $(TARGET_CPPFLAGS)" \
		LDFLAGS="$(TARGET_LDFLAGS)" VERSION="$(PKG_VERSION)" \
		BRANCH=openwrt-sdk COMMIT=unknown tayga pref64-discover
endef

define Package/tayga-managed-openwrt/install
	$(INSTALL_DIR) $(1)/usr/sbin $(1)/etc/tayga $(1)/usr/libexec/tayga
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/build/tayga $(1)/usr/sbin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/build/pref64-discover $(1)/usr/sbin/
	$(INSTALL_CONF) $(PKG_BUILD_DIR)/packaging/tayga.conf.example $(1)/etc/tayga/
	$(INSTALL_DATA) ./package-owner $(1)/usr/libexec/tayga/
	$(INSTALL_DIR) $(1)/usr/share/doc/tayga-managed-openwrt
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/LICENSE $(1)/usr/share/doc/tayga-managed-openwrt/
endef

define Package/tayga-managed-openwrt-procd/install
	$(INSTALL_DIR) $(1)/etc/init.d $(1)/etc/config $(1)/usr/libexec/tayga $(1)/etc/hotplug.d/iface
	$(INSTALL_BIN) ./source/packaging/openwrt/tayga-managed.init $(1)/etc/init.d/tayga-managed
	$(INSTALL_CONF) ./source/packaging/openwrt/tayga_managed.config $(1)/etc/config/tayga_managed
	$(INSTALL_BIN) ./source/packaging/openwrt/openwrt-state.sh $(1)/usr/libexec/tayga/openwrt-state
	echo 1 > $(1)/usr/libexec/tayga/core-upgrade-api
	$(INSTALL_BIN) ./source/packaging/openwrt/openwrt-uplink.sh $(1)/usr/libexec/tayga/openwrt-uplink
	$(INSTALL_DATA) ./source/packaging/openwrt/tayga-managed.hotplug $(1)/etc/hotplug.d/iface/95-tayga-managed
endef

define Package/tayga-managed-openwrt-network/install
	$(INSTALL_DIR) $(1)/lib/netifd/proto $(1)/usr/libexec/tayga
	$(INSTALL_BIN) ./source/packaging/openwrt/tayga-managed.proto $(1)/lib/netifd/proto/tayga-managed.sh
	$(INSTALL_BIN) ./source/packaging/openwrt/openwrt-network.sh $(1)/usr/libexec/tayga/openwrt-network
	$(INSTALL_BIN) ./source/packaging/installer/configure.sh $(1)/usr/libexec/tayga/configure.sh
	$(foreach chain,forward output srcnat,$(INSTALL_DIR) $(1)/usr/share/nftables.d/chain-pre/$(chain); $(INSTALL_DATA) ./source/packaging/openwrt/fw4-$(chain).nft $(1)/usr/share/nftables.d/chain-pre/$(chain)/95-tayga-managed.nft;)
endef

define Package/tayga-managed-openwrt-upgrade/install
	$(INSTALL_DIR) $(1)/usr/libexec/tayga $(1)/etc/init.d
	$(INSTALL_BIN) ./source/packaging/openwrt/openwrt-upgrade.sh $(1)/usr/libexec/tayga/openwrt-upgrade
	$(INSTALL_BIN) ./source/packaging/openwrt/tayga-package-recovery.init $(1)/etc/init.d/tayga-package-recovery
	echo 1 > $(1)/usr/libexec/tayga/package-upgrade-api
endef

$(eval $(call BuildPackage,tayga-managed-openwrt))
$(eval $(call BuildPackage,tayga-managed-openwrt-procd))
$(eval $(call BuildPackage,tayga-managed-openwrt-network))
$(eval $(call BuildPackage,tayga-managed-openwrt-upgrade))
