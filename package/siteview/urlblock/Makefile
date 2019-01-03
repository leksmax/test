
include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=weburl
PKG_VERSION:=1.0
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define KernelPackage/ipt-weburl
    SUBMENU := Netfilter Extensions
    TITLE   := weburl netfilter module
    DEPENDS := +kmod-ipt-core
    FILES   := $(PKG_BUILD_DIR)/module/ipt_weburl.ko
endef

define Package/iptables-mod-weburl
    SECTION  := net
    CATEGORY := Network
    SUBMENU  := Firewall
    TITLE    := weburl iptables extension
    DEPENDS  := iptables +kmod-ipt-weburl
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile/weburl-kmod
	$(MAKE) -C $(LINUX_DIR) \
		CROSS_COMPILE="$(KERNEL_CROSS)" \
		ARCH="$(LINUX_KARCH)" \
		SUBDIRS="$(PKG_BUILD_DIR)/module" \
		KERNELDIR=$(LINUX_DIR) \
		CC="$(TARGET_CC)" \
		EXTRA_CFLAGS="-I$(PKG_BUILD_DIR)/header" \
		modules
endef

define Build/Compile/weburl-lib
    $(MAKE) -C $(PKG_BUILD_DIR)/extension \
        $(TARGET_CONFIGURE_OPTS) \
        CFLAGS="$(TARGET_CFLAGS)" \
        LDFLAGS="$(TARGET_LDFLAGS)" \
		IFLAGS="$(TARGET_CPPFLAGS) -I$(PKG_BUILD_DIR)/header" 
endef	

define Build/Compile
	$(Build/Compile/weburl-kmod)
	$(Build/Compile/weburl-lib)
endef

define Package/iptables-mod-weburl/install
	$(INSTALL_DIR) $(1)/usr/lib/iptables
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/extension/*.so $(1)/usr/lib/iptables/
endef

$(eval $(call KernelPackage,ipt-weburl))
$(eval $(call BuildPackage,iptables-mod-weburl))
