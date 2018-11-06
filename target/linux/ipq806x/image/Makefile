# Copyright (c) 2013 The Linux Foundation. All rights reserved.
#
include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/image.mk

# 2015/03/19
# Torby and Tony confirmed that Netgear have sent new requirement out to resize
# whole kernel and rootfs to 32MB.
# Leave 4MB to kernel and others will be reserved to rootfs and bad block.
#
# * page size = 2KB, block size = 128KB.
# * kernel + rootfs = 32MB = 256 blocks
# * bad blocks = 2MB = 16 blocks
# Partitions have to align to block size.
MAX_KERNEL_SIZE=$(shell echo $$((17 * 128 * 1024))) # kernel blocks * 128 * 1024
MAX_IMAGE_SIZE=$(shell echo $$(((256 - 16) * 128 * 1024))) # (kernel blocks + rootfs blocks - reserved block for bad block) * 128 * 1024

UBIFS_OPTS = -m 2048 -e 124KiB -c 4096 -U -F
UBINIZE_OPTS = -m 2048 -p 128KiB

E2SIZE=$(shell echo $$(($(CONFIG_TARGET_ROOTFS_PARTSIZE)*1024)))

define Device/NETGEAR_R7800
	HW_VERSION := R7800
	FW_VERSION := V1.0.2.46
	LG_VERSION := V1.0.0.321
	CLOUD_VERSION := 20161026
	DEVICE_DTS := qcom-ipq8065-r7800
	NETGEAR_BOARD_ID := R7800
	NETGEAR_HW_ID := 29764958+0+128+512+4x4+4x4+cascade
	FW_REGION := ""
endef

define Device/NETGEAR_BR500
	HW_VERSION := BR500
	FW_VERSION := V1.0.2.46
	LG_VERSION := V1.0.0.321
	CLOUD_VERSION := 20161026
	DEVICE_DTS := qcom-ipq8065-br500
	NETGEAR_BOARD_ID := BR500
	NETGEAR_HW_ID := 29764958+0+128+1024+0+0
	FW_REGION := ""
endef

define Image/Prepare
	echo "$(HW_VERSION)" > $(TARGET_DIR)/hardware_version
	echo "$(FW_VERSION)" > $(TARGET_DIR)/firmware_version
	echo "$(FW_REGION)" > $(TARGET_DIR)/firmware_region
	echo "$(LG_VERSION)" > $(TARGET_DIR)/default_language_version
	echo "$(CLOUD_VERSION)" > $(TARGET_DIR)/cloud_version
	echo "$(NETGEAR_BOARD_ID)" > $(TARGET_DIR)/module_name
	echo "$(NETGEAR_HW_ID)" > $(TARGET_DIR)/hw_id
	date > $(TARGET_DIR)/firmware_time
endef

define MkImageLzma
	mkimage -A arm -O linux -C lzma -T kernel -a 0x40908000 \
		-e 0x40908000 -n 'Linux-$(LINUX_VERSION)' \
		-d $(1) $(2)
endef

define Image/Build/DniImage
	dd if=$(KDIR)/uImage of=$(KDIR)/vmlinux-$(2).uImage
	$(STAGING_DIR_HOST)/bin/R7800 \
		$(KDIR)/vmlinux-$(2).uImage \
		$(KDIR)/vmlinux-$(2).uImage.normal
	dd if=$(KDIR)/root.$(1) of=$(KDIR)/root.$(1).final bs=2k conv=sync
	$(call MkImageLzma,$(KDIR)/root.$(1).final,$(KDIR)/squashfs-$(2).uImage)
	$(STAGING_DIR_HOST)/bin/R7800 \
		$(KDIR)/squashfs-$(2).uImage \
		$(KDIR)/squashfs-$(2).uImage.tmp
	cat $(KDIR)/vmlinux-$(2).uImage.normal > $(KDIR)/vmlinux-$(2).uImage.tmp
	$(TOPDIR)/tools/checksize $(KDIR)/vmlinux-$(2).uImage.tmp $(shell expr $(MAX_KERNEL_SIZE) - 64)
	dd if=$(KDIR)/vmlinux-$(2).uImage.tmp bs=$(shell expr $(MAX_KERNEL_SIZE) - 64) conv=sync of=$(KDIR)/vmlinux-$(2).uImage.final
	dd if=$(KDIR)/squashfs-$(2).uImage.tmp bs=64 count=1 >> $(KDIR)/vmlinux-$(2).uImage.final
	( \
		dd if=$(KDIR)/vmlinux-$(2).uImage.final bs=$(MAX_KERNEL_SIZE) conv=sync; \
		dd if=$(KDIR)/root.$(1).final bs=64k; \
	) > $(BIN_DIR)/$(IMG_PREFIX)-sysupgrade.bin
	$(TOPDIR)/tools/checksize $(BIN_DIR)/$(IMG_PREFIX)-sysupgrade.bin $(MAX_IMAGE_SIZE)
	$(STAGING_DIR_HOST)/bin/mkdniimg \
		-B $(NETGEAR_BOARD_ID) -v $(FW_VERSION) -r $(FW_REGION) -H $(NETGEAR_HW_ID) \
		-i $(BIN_DIR)/$(IMG_PREFIX)-sysupgrade.bin \
		-o $(BIN_DIR)/$(NETGEAR_BOARD_ID)-$(FW_VERSION)$(FW_REGION).img
endef

define Image/BuildKernel	
	$(CP) $(LINUX_DIR)/vmlinux $(BIN_DIR)/$(IMG_PREFIX)-vmlinux.elf
	$(CP) $(LINUX_DIR)/arch/arm/boot/Image $(BIN_DIR)/$(IMG_PREFIX)-vmlinux.bin
	cp $(KDIR)/zImage $(KDIR)/uImage.tmp
	cat $(LINUX_DIR)/arch/arm/boot/dts/$(DEVICE_DTS).dtb >> $(KDIR)/uImage.tmp
	mkimage -A arm -O linux -C none -T kernel -a 0x42208000 \
		-e 0x42208000 -n 'Linux-$(LINUX_VERSION)' \
		-d $(KDIR)/uImage.tmp $(KDIR)/uImage
	dd if=$(KDIR)/uImage of=$(BIN_DIR)/$(IMG_PREFIX)-$(KERNEL)-uImage bs=2k conv=sync
endef

define Image/Build/squashfs
	@echo "+++++++ Image/Build/squashfs +++++++"
endef

define Image/Build
	$(call Image/Build/$(1),$(1))
	dd if=$(KDIR)/root.$(1) of=$(BIN_DIR)/$(IMG_PREFIX)-$(1)-root.img bs=2k conv=sync
	$(call Image/Build/DniImage,$(1),$(NETGEAR_BOARD_ID))
endef

$(eval $(call Device/$(PROFILE)))
$(eval $(call BuildImage))
