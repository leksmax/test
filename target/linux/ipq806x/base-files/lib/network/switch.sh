#!/bin/sh
# Copyright (C) 2009 OpenWrt.org

gen_random_mac() {
    echo "00:03:7f:$(hexdump -n 4 /dev/urandom | awk 'NR==1 {print $2$3}' \
			| sed 's/../&:/g' | cut -c 1-8)"
}

et_landefmac() {
    local tmp

    tmp=`artmtd -r mac_lan | awk -F ": " '{print $2}'`
    [ -n "$tmp" ] && echo "$tmp" || gen_random_mac
}

et_wandefmac() {
    local tmp

    tmp=`artmtd -r mac_wan | awk -F ": " '{print $2}'`
    [ -n "$tmp" ] && echo "$tmp" || gen_random_mac
}

load_default_mac() {
    local lan_mac
    local wan_mac

    lan_mac=$(et_landefmac)
    wan_mac=$(et_wandefmac)

    ifconfig eth1 hw ether $lan_mac
    ifconfig eth0 hw ether $wan_mac
}

setup_switch() {

    load_default_mac

    # vlan
    /sbin/sysinit switch
    
    sleep 1

    # interface
    /sbin/sysinit interface
}
