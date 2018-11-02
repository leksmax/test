
include $(TOPDIR)/rules.mk

PKG_NAME:=webcgi
PKG_VERSION:=1.0

PKG_BUILD_DIR:= $(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

define Package/webcgi
	SECTION  := net
 	CATEGORY := Network
	TITLE    := web management cgi for httpd server 
	DEPENDS  := +libuci 
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)
endef

define Build/Compile
endef

define Package/webcgi/install
	$(INSTALL_DIR) $(1)/www
	$(CP) ./files/upload.html $(1)/www/
	$(INSTALL_DIR) $(1)/www/cgi-bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/web-cgi $(1)/www/cgi-bin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/upgrade.cgi $(1)/www/cgi-bin/
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/network.cli $(1)/usr/sbin/
endef

$(eval $(call BuildPackage,webcgi))
