
include $(TOPDIR)/rules.mk

PKG_NAME:=networkmap
PKG_VERSION:=1.0

PKG_BUILD_DIR:= $(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

define Package/networkmap
	SECTION  := net
 	CATEGORY := Network
	TITLE    := networkmap for attached devices
	DEPENDS  := 
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)
endef

define Package/networkmap/install
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/networkmap.init $(1)/etc/init.d/networkmap
	$(INSTALL_DIR) $(1)/etc/hotplug.d/iface
	$(INSTALL_BIN) ./files/networkmap.hotplug $(1)/etc/hotplug.d/iface/99-networmap
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/networkmap $(1)/usr/sbin/
endef

$(eval $(call BuildPackage,networkmap))
