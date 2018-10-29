TINC_KEY_TYPE=rsa
SUBDIRS=common mqtt-client cgi agent vppnctrl vpnlogd swap-routed vpn-debug

ifeq ($(TINC_KEY_TYPE), rsa)
ROOT_CFLAGS=-DTINC_RSA_KEY
else ifeq ($(TINC_KEY_TYPE), ed25519)
ROOT_CFLAGS=-DTINC_ED_KEY
endif

define build_target
	for subdir in $(SUBDIRS); \
	do \
		make ROOT_CFLAGS="$(ROOT_CFLAGS)" -C $$subdir $1; \
	done
endef

all:
	$(call build_target, $@)

clean:
	$(call build_target, $@)

.PHONY:all clean
