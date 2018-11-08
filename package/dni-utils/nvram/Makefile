# 
# Copyright (C) 2008 Delta Networks Inc.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=nvram
PKG_RELEASE:=1

PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/nvram
  SECTION:=utils
  CATEGORY:=Base system
  TITLE:=nvram for app config
endef

define Build/Prepare
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Package/nvram/install
    $(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/nvram.init $(1)/etc/init.d/nvram
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/nvram $(1)/usr/sbin/
endef

$(eval $(call BuildPackage,nvram))
