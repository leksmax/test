
#ifndef __NETWORK_H_
#define __NETWORK_H_

#define ADDR4_LEN 16
#define ADDR6_LEN 46
#define ETHER_LEN 18

#define LAN1_IPADDR         ("network.lan.ipaddr")
#define LAN1_NETMASK        ("network.lan.netmask")
#define LAN1_MACADDR        ("network.lan.macaddr")

#define LAN1_DHCP_IGNORE    ("dhcp.lan.ignore")
#define LAN1_DHCP_START     ("dhcp.lan.start")
#define LAN1_DHCP_LIMIT     ("dhcp.lan.limit")
#define LAN1_DHCP_LEASETIME ("dhcp.lan.leasetime")

#define WAN1_PROTO          ("network.wan.proto")
#define WAN1_IPADDR         ("network.wan.ipaddr")
#define WAN1_NETMASK        ("network.wan.netmask")
#define WAN1_GATEWAY        ("network.wan.gateway")
#define WAN1_PPPOE_USER     ("network.wan.username")
#define WAN1_PPPOE_PWD      ("network.wan.password")
#define WAN1_PPPOE_SERVICE  ("network.wan.service")
#define WAN1_DNS            ("network.wan.dns")
#define WAN1_MACADDR        ("network.wan.macaddr")

typedef struct {
    char lan[10];
    char ipaddr[ADDR4_LEN];
    char netmask[ADDR4_LEN];
    int dhcpd_enable;
    char dhcpd_start[ADDR4_LEN];
    char dhcpd_end[ADDR4_LEN];
    char macaddr[ETHER_LEN];
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
} wan_cfg_t;

int get_interface_lan(cgi_request_t * req, cgi_response_t * resp);
int get_lan_config(cgi_request_t * req, cgi_response_t * resp);
int set_lan_config(cgi_request_t * req, cgi_response_t * resp);

int get_interface_wan(cgi_request_t * req, cgi_response_t * resp);
int get_wan_config(cgi_request_t * req, cgi_response_t * resp);
int set_wan_config(cgi_request_t * req, cgi_response_t * resp);

#endif
