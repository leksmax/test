#!/bin/sh

CONFFILES=/tmp/sysupgrade.conffiles
CONF_TAR=/tmp/sysupgrade.tgz

add_uci_conffiles() {
	local file="$1"
	( find $(sed -ne '/^[[:space:]]*$/d; /^#/d; p' \
			/etc/sysupgrade.conf /lib/upgrade/keep.d/* 2>/dev/null) \
			-type f -o -type l 2>/dev/null;
	  opkg list-changed-conffiles ) | sort -u > "$file"
	return 0
}

do_save_conffiles() {
	local conf_tar="${1:-$CONF_TAR}"
	echo "Saving config files..."
	tar czf "$conf_tar" -T "$CONFFILES" 2>/dev/null
	rm -f "$CONFFILES"
}

create_backup() {
	add_uci_conffiles "$CONFFILES"
	do_save_conffiles "$1"
	exit $?
}

restore_config() {
	local conf_tar="${1:-$CONF_RESTORE}"

	[ "$VERBOSE" -gt 1 ] && TAR_V="v" || TAR_V=""
	tar -C / -xzf "$conf_tar"
	exit $?
}

case $1 in
	"create")
		create_backup $2
	;;
	"restore")
		restore_config $2
	;;
	*)
		echo "unknow args"
	;;
esac

exit 0
