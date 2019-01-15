
include $(TOPDIR)/rules.mk

PKG_NAME:=shared
PKG_VERSION:=1.0

PKG_BUILD_DIR:= $(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

define Package/shared
    SECTION:=libs
    CATEGORY:=Libraries
    TITLE:=Library implementing the common function in embeded linux
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/include/
	$(CP) $(PKG_BUILD_DIR)/*.h $(1)/usr/include/
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/libshared.so $(1)/usr/lib/libshared.so
endef

define Package/shared/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/libshared.so $(1)/usr/lib
endef

$(eval $(call BuildPackage,shared))
