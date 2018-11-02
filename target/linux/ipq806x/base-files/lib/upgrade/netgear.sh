#!/bin/sh

RAM_ROOT=/tmp/root

[ -x /usr/bin/ldd ] || ldd() { LD_TRACE_LOADED_OBJECTS=1 $*; }
libs() { ldd $* 2>/dev/null | sed -r 's/(.* => )?(.*) .*/\2/'; }

install_file() { # <file> [ <file> ... ]
    for file in "$@"; do
        dest="$RAM_ROOT/$file"
        [ -f $file -a ! -f $dest ] && {
            dir="$(dirname $dest)"
            mkdir -p "$dir"
            cp $file $dest
        }
    done
}

install_bin() { # <file> [ <symlink> ... ]
    src=$1
    files=$1
    [ -x "$src" ] && files="$src $(libs $src)"
    install_file $files
    shift
    for link in "$@"; do {
        dest="$RAM_ROOT/$link"
        dir="$(dirname $dest)"
        mkdir -p "$dir"
        [ -f "$dest" ] || ln -s $src $dest
    }; done
}

supivot() { # <new_root> <old_root>
    /bin/mount | grep "on $1 type" 2>&- 1>&- || /bin/mount -o bind $1 $1
    mkdir -p $1$2 $1/proc $1/sys $1/dev $1/tmp $1/overlay && \
    /bin/mount -o noatime,move /proc $1/proc && \
    pivot_root $1 $1$2 || {
        /bin/umount -l $1 $1
        return 1
    }

    /bin/mount -o noatime,move $2/sys /sys
    /bin/mount -o noatime,move $2/dev /dev
    /bin/mount -o noatime,move $2/tmp /tmp
    /bin/mount -o noatime,move $2/overlay /overlay 2>&-
    return 0
}

run_ramfs() { # <command> [...]
    install_bin /bin/busybox /bin/ash /bin/sh /bin/mount /bin/umount    \
        /sbin/pivot_root /usr/bin/wget /sbin/reboot /bin/sync /bin/dd   \
        /bin/grep /bin/cp /bin/mv /bin/tar /usr/bin/md5sum "/usr/bin/[" \
        /bin/dd /bin/vi /bin/ls /bin/cat /usr/bin/awk /usr/bin/hexdump  \
        /bin/sleep /bin/zcat /usr/bin/bzcat /usr/bin/printf /usr/bin/wc \
        /bin/cut /usr/bin/printf /bin/sync /bin/mkdir /bin/rmdir    \
        /bin/rm /usr/bin/basename /bin/kill /bin/chmod

	install_bin /sbin/artmtd
	install_bin /usr/sbin/nandwrite
    install_bin /sbin/mtd
    install_bin /sbin/mount_root
    install_bin /sbin/snapshot
    install_bin /sbin/snapshot_tool
    install_bin /usr/sbin/ubiupdatevol
    install_bin /usr/sbin/ubiattach
    install_bin /usr/sbin/ubiblock
    install_bin /usr/sbin/ubiformat
    install_bin /usr/sbin/ubidetach
    install_bin /usr/sbin/ubirsvol
    install_bin /usr/sbin/ubirmvol
    install_bin /usr/sbin/ubimkvol
    for file in $RAMFS_COPY_BIN; do
        install_bin ${file//:/ }
    done
    install_file /etc/resolv.conf /lib/*.sh /lib/functions/*.sh /lib/upgrade/*.sh $RAMFS_COPY_DATA

    [ -L "/lib64" ] && ln -s /lib $RAM_ROOT/lib64

    supivot $RAM_ROOT /mnt || {
        echo "Failed to switch over to ramfs. Please reboot."
        exit 1
    }

    /bin/mount -o remount,ro /mnt
    /bin/umount -l /mnt

    grep /overlay /proc/mounts > /dev/null && {
        /bin/mount -o noatime,remount,ro /overlay
        /bin/umount -l /overlay
    }

    # spawn a new shell from ramdisk to reduce the probability of cache issues
    exec /bin/busybox ash -c "$*"
}

install_bin() { # <file> [ <symlink> ... ]
    src=$1
    files=$1
    [ -x "$src" ] && files="$src $(libs $src)"
    install_file $files
    shift
    for link in "$@"; do {
        dest="$RAM_ROOT/$link"
        dir="$(dirname $dest)"
        mkdir -p "$dir"
        [ -f "$dest" ] || ln -s $src $dest
    }; done
}

ask_bool() {
    local default="$1"; shift;
    local answer="$default"

    [ "$INTERACTIVE" -eq 1 ] && {
        case "$default" in
            0) echo -n "$* (y/N): ";;
            *) echo -n "$* (Y/n): ";;
        esac
        read answer
        case "$answer" in
            y*) answer=1;;
            n*) answer=0;;
            *) answer="$default";;
        esac
    }   
    [ "$answer" -gt 0 ] 
}

find_mtd_index() {
	local PART="$(grep "\"$1\"" /proc/mtd | awk -F: '{print $1}')"
	local INDEX="${PART##mtd}"
	
	echo ${INDEX}
}

dni_upgrade() {
	#echo "Performing system upgrade..."
	
	nandwrite --input-skip=128 -p -m -q /dev/mtd8 $IMAGE_FILE
	
	#echo "Upgrade completed"
	[ -n $DELAY ] && sleep "$DELAY"
	ask_bool 1 "Reboot" && {
		#echo "Rebooting system..."
		reboot -f
		sleep 5
		echo b 2>/dev/null >/proc/sysrq-trigger
	}
}