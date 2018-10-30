
#ifndef __NETWORK_H_
#define __NETWORK_H_

#define LAN1_NAME "LAN1"
#define LAN1_VLANID 1

/*
 * UCI name
 */
#define LAN1_IPADDR "network.lan.ipaddr"
#define LAN1_NETMASK "network.lan.netmask"
#define LAN1_MACADDR "network.lan.macaddr"
#define LAN1_DHCP_IGNORE "dhcp.lan.ignore"
#define LAN1_DHCP_START "dhcp.lan.start"
#define LAN1_DHCP_LIMIT "dhcp.lan.limit"

typedef enum {
    RIP_NONE = 0,
    RIP_1,
    RIP_1B,
    RIP_2M
} rip_ver_t;

typedef enum {
    RIP_DIR_BOTH = 0,
    RIP_DIR_IN,
    RIP_DIR_OUT
} rip_dir_t;

typedef struct lan_cfg {
    char name[33];
    char ipaddr[16];
    char netmask[16];
    int dhcpd_enable;
    char dhcpd_start[16];
    char dhcpd_end[16];
    int ripd_enable;
    int rip_direction;
    int rip_version;
    char macaddr[18];
    int vlanid;
    char desc[65];
} lan_cfg_t;

typedef struct dhcpd_res {
    int lan_idx;
    char mac[18];
    char ip[16];
    char name[64];
} dhcpd_res_t;

int network_main(char *cmd, char *data);

#endif
