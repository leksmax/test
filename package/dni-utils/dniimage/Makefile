
include $(TOPDIR)/rules.mk

PKG_NAME:=dniimage
PKG_RELEASE:=1

PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/dniimage
  SECTION:=utils
  CATEGORY:=Base system
  TITLE:=dni upgrade image check tools
  DEPENDS:=artmtd
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Package/dniimage/install
	$(INSTALL_DIR) $(1)/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/dniimage $(1)/sbin/
endef

$(eval $(call BuildPackage,dniimage))
