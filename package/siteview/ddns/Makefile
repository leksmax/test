#
# Copyright (C) 2006-2016 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=ddns
PKG_VERSION:=1
PKG_RELEASE:=1

PKG_LICENSE:=GPL-2.0
PKG_LICENSE_FILES:=COPYING

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION).$(PKG_RELEASE)

include $(INCLUDE_DIR)/package.mk

define Package/ddns/Default
	SECTION:=net
	CATEGORY:=Base system
	SUBMENU:=DDNS
endef


define Build/Prepare
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(call Build/Compile/noip)
	$(call Build/Compile/ez-ipupdate)
endef

define Package/ddns
	$(call Package/ddns/Default)
	TITLE:=ddns applications
endef

define Package/ddns/install
	$(INSTALL_DIR) $(1)/etc/init.d/
	$(INSTALL_BIN) ./files/ddns.script $(1)/etc/init.d/ddns
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_BIN) ./files/ddns.conf $(1)/etc/config/ddns
	$(INSTALL_DIR) $(1)/etc/hotplug.d/iface
	$(INSTALL_BIN) ./files/ddns.hotplug $(1)/etc/hotplug.d/iface/33-ddns
endef

define Package/noip
	$(call Package/ddns/Default)
	DEPENDS:=ddns
	TITLE+=noip ddns
endef
	
define Build/Compile/noip
	$(MAKE) -C $(PKG_BUILD_DIR)/noip2 \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="$(TARGET_CFLAGS)" \
		CPPFLAGS="$(TARGET_CPPFLAGS)" \
		LDFLAGS="$(TARGET_LDFLAGS)"
endef

define Package/noip/install
	$(INSTALL_DIR) $(1)/usr/sbin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/noip2/noip2 $(1)/usr/sbin/	
endef

define Package/ez-ipupdate
	$(call Package/ddns/Default)
	DEPENDS:=ddns
	TITLE+=ez-ipupdate ddns
endef

define Build/Compile/ez-ipupdate
	$(call Build/Configure/Default,,,ez-ipupdate) 
	$(MAKE) -C $(PKG_BUILD_DIR)/ez-ipupdate \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="$(TARGET_CFLAGS)" \
		CPPFLAGS="$(TARGET_CPPFLAGS)" \
		LDFLAGS="$(TARGET_LDFLAGS)"
endef

define Package/ez-ipupdate/install
	$(INSTALL_DIR) $(1)/usr/sbin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/ez-ipupdate/ez-ipupdate $(1)/usr/sbin/	
endef

$(eval $(call BuildPackage,ddns))
$(eval $(call BuildPackage,noip))
$(eval $(call BuildPackage,ez-ipupdate))
