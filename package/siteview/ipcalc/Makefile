
include $(TOPDIR)/rules.mk

PKG_NAME:=ipcalc
PKG_RELEASE:=0.2.4

include $(INCLUDE_DIR)/package.mk

define Package/ipcalc
	SECTION  := utils
 	CATEGORY := Utilities
	TITLE    := an IPV4/IPV6 ipcalc tool
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)
endef

MAKE_VARS += \
	USE_GEOIP=no \
	USE_MAXMIND=no

define Package/ipcalc/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/ipcalc $(1)/usr/sbin/
endef

$(eval $(call BuildPackage,ipcalc))
