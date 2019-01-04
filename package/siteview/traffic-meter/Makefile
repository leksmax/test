
include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=traffic_meter
PKG_VERSION:=1.0
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define KernelPackage/ipt-maccount
    SUBMENU := Netfilter Extensions
    TITLE   := maccount match netfilter module
    DEPENDS := +kmod-ipt-core
    FILES   := $(PKG_BUILD_DIR)/module/ipt_account.ko
	AUTOLOAD := $(call AutoLoad,41,ipt_account)
endef

define Package/iptables-mod-maccount
    SECTION  := net
    CATEGORY := Network
    SUBMENU  := Firewall
    TITLE    := maccount match iptables extension
    DEPENDS  := iptables +kmod-ipt-maccount
endef

define Package/traffic-meter
	SETCTION := net
	CATEGORY := Network
	TITLE	 := traffic meter of all
	DEPENDS  := +iptables-mod-maccount +shared
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile/maccount-kmod
	$(MAKE) -C $(LINUX_DIR) \
		CROSS_COMPILE="$(KERNEL_CROSS)" \
		ARCH="$(LINUX_KARCH)" \
		SUBDIRS="$(PKG_BUILD_DIR)/module" \
		KERNELDIR=$(LINUX_DIR) \
		CC="$(TARGET_CC)" \
		EXTRA_CFLAGS="-I$(PKG_BUILD_DIR)/header" \
		modules
endef

define Build/Compile/maccount-lib
    $(MAKE) -C $(PKG_BUILD_DIR)/extension \
        $(TARGET_CONFIGURE_OPTS) \
        CFLAGS="$(TARGET_CFLAGS)" \
        LDFLAGS="$(TARGET_LDFLAGS)" \
		IFLAGS="$(TARGET_CPPFLAGS) -I$(PKG_BUILD_DIR)/header" 
endef	

define Build/Compile/traffic-meter
    ( CFLAGS="$(TARGET_CFLAGS)" \
	  LDFLAGS="$(TARGET_LDFLAGS)" \
	  IFLAGS="$(TARGET_CPPFLAGS) -I$(PKG_BUILD_DIR)/header" \
      $(TARGET_CONFIGURE_OPTS) \
      $(MAKE) -C $(PKG_BUILD_DIR)/app )
endef	

define Build/Compile
	$(Build/Compile/maccount-kmod)
	$(Build/Compile/maccount-lib)
	$(Build/Compile/traffic-meter)
endef

define Package/iptables-mod-maccount/install
	$(INSTALL_DIR) $(1)/usr/lib/iptables
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/extension/*.so $(1)/usr/lib/iptables/
endef

define Package/traffic-meter/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/app/traffic_meter  $(1)/usr/sbin/
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_DATA) ./files/traffic_meter.config $(1)/etc/config/traffic
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/traffic_meter.init $(1)/etc/init.d/traffic_init
	$(INSTALL_DIR) $(1)/lib/traffic
	$(INSTALL_BIN) ./files/traffic_meter.script $(1)/lib/traffic/
endef

$(eval $(call KernelPackage,ipt-maccount))
$(eval $(call BuildPackage,iptables-mod-maccount))
$(eval $(call BuildPackage,traffic-meter))
