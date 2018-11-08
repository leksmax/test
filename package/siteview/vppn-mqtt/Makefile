# 
# Copyright (C) 2006 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# $Id: Makefile 4855 2006-09-24 20:49:31Z nico $

include $(TOPDIR)/rules.mk
GIT_HOME:=$(TOPDIR)/git_home

PKG_NAME:=vppn-mqtt
PKG_VERSION:=0.1
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/vppn-mqtt
  SECTION:=net
  CATEGORY:=Network
  DEPENDS:=+evmongoose +libpthread +libev +libopenssl +libcurl +zlib +libstdcpp
  TITLE:=Vppn Package
  URL:=http://vppn.net/source
endef

define Package/vppn-mqtt/description
 This package contains Vppn ctrl Client.
endef

#define Package/vppn-mqtt/config
#	menu "Configuration"
#		source "$(SOURCE)/Config.in"
#	endmenu
#endef

TARGET_CFLAGS += -I$(STAGING_DIR)/usr/include -L$(STAGING_DIR)/usr/lib -DBOARD_NAME=7800 -DHAVE_BUSYBOX=1

define Build/Prepare
	$(CP) $(GIT_HOME)/mqtt-ctrl-m/* $(PKG_BUILD_DIR)/
endef

define Package/vppn-mqtt/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_DIR) $(1)/etc/init.d/
	$(INSTALL_DIR) $(1)/etc/site
	$(INSTALL_DIR) $(1)/etc/tinc/
	$(INSTALL_DIR) $(1)/www/cgi-bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/mqtt-client/mqtt-client $(1)/usr/sbin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/vpnlogd/vpnlogd $(1)/usr/sbin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/swap-routed/swap-routed $(1)/usr/sbin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/vpn-debug/vpn-debug $(1)/usr/sbin/vpn-debug
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/vppnctrl/vppnctrl $(1)/usr/sbin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/vppnctrl/vpn_genkey.sh $(1)/usr/bin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/agent/mqtt-agent $(1)/usr/bin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/agent/monitor-agent $(1)/usr/bin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/agent/vpncloud_agent $(1)/usr/bin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/agent/tinc_dump $(1)/usr/bin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/cgi/vpnctrl.cgi $(1)/www/cgi-bin/
	$(INSTALL_BIN) init/mqtt-client.init $(1)/etc/init.d/mqtt-client.init
	$(INSTALL_BIN) init/vppnctrl.init $(1)/etc/init.d/vppnctrl.init
	$(INSTALL_BIN) site/init_domain.conf $(1)/etc/site/init_domain.conf
	$(INSTALL_BIN) site/insight_ca.crt $(1)/etc/site/insight_ca.crt
	$(INSTALL_BIN) vppn_custom.conf $(1)/etc/vppn_custom.conf
endef

$(eval $(call BuildPackage,vppn-mqtt))
