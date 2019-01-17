
#ifndef __UBUS_H_
#define __UBUS_H_

struct ubus_lan_status {
    int status;
    int uptime;
    char ifname[20];
    char ipaddr[16];
    char netmask[16];
};

struct ubus_wan_status {
    int status;
    int uptime;
    char ifname[20];
    char proto[10];
    int metric;
    char ipaddr[16];
    char netmask[16];
    char gateway[16];
    char dns1[16];
    char dns2[16];
};

int ubus_get_lan_status(const char * name, struct ubus_lan_status * lan);
int ubus_get_wan_status(const char * name, struct ubus_lan_status * wan);

#endif
