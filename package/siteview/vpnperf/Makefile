
include $(TOPDIR)/rules.mk

PKG_NAME    := vpnperf
PKG_RELEASE := 1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/vpnperf
  SECTION  := net
  CATEGORY := Network
  TITLE    := vpn network remote perf utils 
  DEPENDS  := iperf +libstdcpp 
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)/src
	mkdir -p $(PKG_BUILD_DIR)/lib
	$(CP) ./src/* $(PKG_BUILD_DIR)/src
	$(CP) ./lib/* $(PKG_BUILD_DIR)/lib
	$(CP) ./top_makefile $(PKG_BUILD_DIR)/Makefile
endef

define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/include
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/lib/vpnperf_client.h $(1)/usr/include/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/lib/libvpnperf_client.so $(1)/usr/lib/
endef

define Package/vpnperf/install
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/vpnperf $(1)/usr/sbin/
	$(INSTALL_BIN) ./init/vpnperf.init $(1)/etc/init.d/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/lib/libvpnperf_client.so $(1)/usr/lib/
endef

$(eval $(call BuildPackage,vpnperf))
