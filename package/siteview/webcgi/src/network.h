
#ifndef __NETWORK_H_
#define __NETWORK_H_

#include "utils.h"
#include "servlet.h"

#define ADDR4_LEN 16
#define ADDR6_LEN 46
#define ETHER_LEN 18

#define LAN_IPADDR         ("ipaddr")
#define LAN_NETMASK        ("netmask")
#define LAN_MACADDR        ("macaddr")
#define LAN_VLAN           ("vlan")

#define LAN1_DHCP_IGNORE    ("dhcp.lan.ignore")
#define LAN1_DHCP_START     ("dhcp.lan.start")
#define LAN1_DHCP_LIMIT     ("dhcp.lan.limit")
#define LAN1_DHCP_LEASETIME ("dhcp.lan.leasetime")

#define WAN_PROTO          ("proto")
#define WAN_IPADDR         ("ipaddr")
#define WAN_NETMASK        ("netmask")
#define WAN_GATEWAY        ("gateway")
#define WAN_PPPOE_USER     ("username")
#define WAN_PPPOE_PWD      ("password")
#define WAN_PPPOE_SERVICE  ("service")
#define WAN_DNS            ("dns")
#define WAN_MACADDR        ("macaddr")

#define DUALWAN_ENABLED     ("dualwan.global.enabled")
#define DUALWAN_PRIMARY     ("dualwan.global.primary")
#define DUALWAN_SECONDARY   ("dualwan.global.secondary")
#define DUALWAN_MODE        ("dualwan.global.mode")
#define DUALWAN_WEIGHT1     ("dualwan.global.weight1")
#define DUALWAN_WEIGHT2     ("dualwan.global.weight2")

enum {
    WAN4_PROTO_NONE   = 0,
    WAN4_PROTO_STATIC = 1,
    WAN4_PROTO_DHCP   = 2,
    WAN4_PROTO_PPPOE  = 3,
    WAN4_PROTO_PPTP   = 4,
    WAN4_PROTO_L2TP   = 5,
    _WAN4_PROTO_MAX
};

enum {
    LAN1_UNIT = 1,
    LAN2_UNIT = 2,
    LAN3_UNIT = 3,
    LAN4_UNIT = 4,
    _LAN_UNIT_MAX
};

enum {
    WAN1_UNIT = 1,
    WAN2_UNIT = 2,
    _WAN_UNIT_MAX
};

enum {
    _WAN6_TYPE_MAX
};

typedef struct {
    char lan[10];
    char ipaddr[ADDR4_LEN];
    char netmask[ADDR4_LEN];
    int dhcpd_enable;
    char dhcpd_start[ADDR4_LEN];
    char dhcpd_end[ADDR4_LEN];
    char macaddr[ETHER_LEN];
    char vlan;
} lan_cfg_t;

typedef struct {
    char wan[10];
    char proto[10];
    char ipaddr[ADDR4_LEN];
    char netmask[ADDR4_LEN];
    char gateway[ADDR4_LEN];
    char pppoe_user[65];
    char pppoe_pwd[65];
    char service[65];
    char dns_mode[10];
    char dns1[ADDR4_LEN];
    char dns2[ADDR4_LEN];
    char macaddr[ETHER_LEN];
    int vlan;
} wan_cfg_t;

typedef struct {
    int enabled;
    char lan[10];
    char ip6type[10];
    char ip6prefix[46];
    int ip6assign;
    int leasetime;
} lan6_cfg_t;

typedef struct {    
    int enabled;
    char wan[10];
    char ip6type[10];
    char ip6addr[46];
    int ip6assign;
    char ip6gw[46];
    char ip6mode[10];
    int ip6delegate;
    char ip6dnsmode[10];
    char ip6dns1[46];
    char ip6dns2[46];
} wan6_cfg_t;

typedef struct {
    int enabled;
    char primary[10];
    char secondary[10];
    int mode;
    int weight1;
    int weight2;
} dualwan_cfg_t;

typedef struct {
    char interface[10];
    int interval;
    int times;
    char target[10];
    char ipaddr[16];
} dualwan_failover_cfg_t;

struct network_state {

    int lan_num;
    struct list_head lans;

    int wan_num;
    struct list_head wans;
    
    int vpn_num;
    struct list_head vpns;
};

int get_interface_lan(cgi_request_t * req, cgi_response_t * resp);
int get_interface_wan(cgi_request_t * req, cgi_response_t * resp);

int get_lan_config(cgi_request_t * req, cgi_response_t * resp);
int set_lan_config(cgi_request_t * req, cgi_response_t * resp);
int get_lan_status(cgi_request_t * req, cgi_response_t * resp);

int lan_interface_config(cgi_request_t * req, cgi_response_t * resp);

int get_wan_config(cgi_request_t * req, cgi_response_t * resp);
int set_wan_config(cgi_request_t * req, cgi_response_t * resp);
int get_wan_status(cgi_request_t * req, cgi_response_t * resp);

int get_lan6_config(cgi_request_t * req, cgi_response_t * resp);
int set_lan6_config(cgi_request_t * req, cgi_response_t * resp);
int get_lan6_status(cgi_request_t * req, cgi_response_t * resp);

int get_wan6_config(cgi_request_t * req, cgi_response_t * resp);
int set_wan6_config(cgi_request_t * req, cgi_response_t * resp);
int get_wan6_status(cgi_request_t * req, cgi_response_t * resp);

int get_dualwan_config(cgi_request_t * req, cgi_response_t * resp);
int set_dualwan_config(cgi_request_t * req, cgi_response_t * resp);
int dualwan_check_config(cgi_request_t * req, cgi_response_t * resp);
int get_dualwan_status(cgi_request_t * req, cgi_response_t * resp);

#endif
