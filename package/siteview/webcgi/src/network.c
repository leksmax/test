
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "ubus.h"
#include "webcgi.h"
#include "network.h"

/*
    lan:
        br-lan
        br-lan1
        br-lan2
        br-lan3

    wan:
        ethwan1
        ethwan2
 */

const char *lan_names[_LAN_UNIT_MAX] = {
    "(error)",
    "LAN1",
    "LAN2",
    "LAN3",
    "LAN4",
};

const char *lan_sec_names[_LAN_UNIT_MAX] = {
    "(error)",
    "lan",
    "lan2",
    "lan3",
    "lan4",
};

const char *wan_names[_WAN_UNIT_MAX] = {
    "(error)",
    "WAN1",
    "WAN2",
};

const char *wan_sec_names[_WAN_UNIT_MAX] = {
    "(error)",
    "wan",
    "wan2",
};

const char *wan4_modes[_WAN4_PROTO_MAX] = {
    "none",
    "static",
    "dhcp",
    "pppoe",
    "pptp",
    "l2tp",
};

const char *wan6_modes[_WAN6_TYPE_MAX] = {
    "none",
};

char *config_get_wan(int unit, const char *name)
{
    char wanx_param[128] = {0};
    snprintf(wanx_param, sizeof(wanx_param), "network.%s.%s", wan_sec_names[unit], name);
    return config_get(wanx_param);
}

int config_get_wan_int(int unit, const char *name)
{
    char wanx_param[128] = {0};
    snprintf(wanx_param, sizeof(wanx_param), "network.%s.%s", wan_sec_names[unit], name);
    return config_get_int(wanx_param);
}

int config_set_wan(int unit, const char *name, char *value)
{
    char wanx_param[128] = {0};
    snprintf(wanx_param, sizeof(wanx_param), "network.%s.%s", wan_sec_names[unit], name);
    return config_set(wanx_param, value);
}

int config_set_wan_int(int unit, const char *name, int value)
{
    char wanx_param[128] = {0};
    snprintf(wanx_param, sizeof(wanx_param), "network.%s.%s", wan_sec_names[unit], name);
    return config_set_int(wanx_param, value);    
}

char *config_get_lan(int unit, const char *name)
{
    char lanx_param[128] = {0};
    snprintf(lanx_param, sizeof(lanx_param), "network.%s.%s", lan_sec_names[unit], name);
    return config_get(lanx_param);
}

int config_get_lan_int(int unit, const char *name)
{
    char lanx_param[128] = {0};
    snprintf(lanx_param, sizeof(lanx_param), "network.%s.%s", lan_sec_names[unit], name);
    return config_get_int(lanx_param);
}

int config_set_lan(int unit, const char *name, char *value)
{
    char lanx_param[128] = {0};
    snprintf(lanx_param, sizeof(lanx_param), "network.%s.%s", lan_sec_names[unit], name);
    return config_set(lanx_param, value);
}

int config_set_lan_int(int unit, const char *name, int value)
{
    char lanx_param[128] = {0};
    snprintf(lanx_param, sizeof(lanx_param), "network.%s.%s", lan_sec_names[unit], name);
    return config_set_int(lanx_param, value);    
}

char *config_get_wan6(int unit, const char *name)
{
    char wanx_param[128] = {0};
    snprintf(wanx_param, sizeof(wanx_param), "net6conf.wan%d.%s", unit, name);
    return config_get(wanx_param);
}

int config_get_wan6_int(int unit, const char *name)
{
    char wanx_param[128] = {0};
    snprintf(wanx_param, sizeof(wanx_param), "net6conf.wan%d.%s", unit, name);    
    return config_get_int(wanx_param);
}

int config_set_wan6(int unit, const char *name, char *value)
{
    char wanx_param[128] = {0};
    snprintf(wanx_param, sizeof(wanx_param), "net6conf.wan%d.%s", unit, name);
    return config_set(wanx_param, value);
}

int config_set_wan6_int(int unit, const char *name, int value)
{
    char wanx_param[128] = {0};
    snprintf(wanx_param, sizeof(wanx_param), "net6conf.wan%d.%s", unit, name);
    return config_set_int(wanx_param, value);    
}

char *config_get_dualwan(int unit, const char *name)
{
    char param[128] = {0};
    snprintf(param, sizeof(param), "dualwan.wan%d.%s", unit, name);
    return config_get(param);
}

int config_get_dualwan_int(int unit, const char *name)
{
    char param[128] = {0};
    snprintf(param, sizeof(param), "dualwan.wan%d.%s", unit, name);
    return config_get_int(param);
}

int config_set_dualwan(int unit, const char *name, char *value)
{
    char param[128] = {0};
    snprintf(param, sizeof(param), "dualwan.wan%d.%s", unit, name);
    return config_set(param, value);
}

int config_set_dualwan_int(int unit, const char *name, int value)
{
    char param[128] = {0};
    snprintf(param, sizeof(param), "dualwan.wan%d.%s", unit, name);
    return config_set_int(param, value);    
}

int get_lan_unit(char *name)
{
    int unit;

    for (unit = 1; unit < _LAN_UNIT_MAX; unit ++)
    {
        if (!strcmp(name, lan_names[unit]))
        {
            return unit;
        }
    }
    
    return LAN1_UNIT;    
}

int get_wan_unit(char *name)
{
    int unit;

    for (unit = 1; unit < _WAN_UNIT_MAX; unit ++)
    {
        if (!strcmp(name, wan_names[unit]))
        {
            return unit;
        }
    }
    
    return WAN1_UNIT;
}

int get_main_ifname(int unit)
{
    return config_get_wan(unit, "ifname");
}

int get_wan_proto(int unit)
{
    int i;
    char *proto;
    
    proto = config_get_wan(unit, "proto");
    
    for (i = 0; i < _WAN4_PROTO_MAX; i ++)
    {
        if (!strcmp(wan4_modes[i], proto))
        {
            return i;
        }
    }

    return WAN4_PROTO_NONE;
}

char *get_wan_ifname(int unit)
{
    int proto;
    char *wan_ifname;

    proto = get_wan_proto(unit);
    if (proto == WAN4_PROTO_NONE ||
        proto == WAN4_PROTO_STATIC ||
        proto == WAN4_PROTO_DHCP)
    {
        return get_main_ifname(unit);
    }
    else if (proto == WAN4_PROTO_PPPOE)
    {
        
    }
}

void _uci_add_intf_wan(int unit)
{
    char wanx_sec[128];

    if (unit == WAN1_UNIT)
    {
        snprintf(wanx_sec, sizeof(wanx_sec), "network.wan");
    }
    else
    {
        snprintf(wanx_sec, sizeof(wanx_sec), "network.wan%d", unit);
    }
    
    config_set(wanx_sec, "interface");
}

void _uci_del_intf_wan(int unit)
{
    char wanx_sec[128];

    if (unit == LAN1_UNIT)
    {
        snprintf(wanx_sec, sizeof(wanx_sec), "network.wan");
    }
    else
    {
        snprintf(wanx_sec, sizeof(wanx_sec), "network.wan%d", unit);
    }

    config_unset(wanx_sec);
}

void _uci_add_intf_lan(int unit)
{
    char lanx_sec[128];

    if (unit == LAN1_UNIT)
    {
        snprintf(lanx_sec, sizeof(lanx_sec), "network.lan");
    }
    else
    {
        snprintf(lanx_sec, sizeof(lanx_sec), "network.lan%d", unit);
    }
    
    config_set(lanx_sec, "interface");
}

void _uci_del_intf_lan(int unit)
{
    char lanx_sec[128];

    if (unit == LAN1_UNIT)
    {
        snprintf(lanx_sec, sizeof(lanx_sec), "network.lan");
    }
    else
    {
        snprintf(lanx_sec, sizeof(lanx_sec), "network.lan%d", unit);
    }

    config_unset(lanx_sec);
}

#define ADP_NTWK

int libgw_get_lan_cfg(char *lan, lan_cfg_t *cfg)
{
    int unit = 1;
    int ignore = 0;
    int start, limit;
    uint32_t ip, mask;
    uint32_t ip1, ip2;
    struct in_addr addr;
    
    unit = get_lan_unit(lan);
    if (unit < 0)
    {
        return -1;
    }

    strncpy(cfg->lan, lan, sizeof(cfg->lan) - 1);
    strncpy(cfg->ipaddr, config_get_lan(unit, LAN_IPADDR), sizeof(cfg->ipaddr) - 1);
    strncpy(cfg->netmask, config_get_lan(unit, LAN_NETMASK), sizeof(cfg->netmask) - 1);

    cfg->vlan = config_get_lan_int(unit, LAN_VLAN);

    ignore = config_get_int(LAN1_DHCP_IGNORE);
    cfg->dhcpd_enable = ((ignore == 0) ? 1 : 0);

    start = config_get_int(LAN1_DHCP_START);
    limit = config_get_int(LAN1_DHCP_LIMIT);

    ip = inet_addr(cfg->ipaddr);
    mask = inet_addr(cfg->netmask);

    ip1 = (ip & mask) + htonl(start);
    ip2 = ip1 + htonl(limit - 1);

    memcpy(&addr, &ip1, 4);
    strncpy(cfg->dhcpd_start, inet_ntoa(addr), sizeof(cfg->dhcpd_start) - 1);

    memcpy(&addr, &ip2, 4);
    strncpy(cfg->dhcpd_end, inet_ntoa(addr), sizeof(cfg->dhcpd_end) - 1);

    return 0;
}

int libgw_set_lan_cfg(char *lan, lan_cfg_t *cfg)
{
    int unit;
    int start, limit;
    uint32_t ip, mask;
    uint32_t ip1, ip2;

    unit = get_lan_unit(lan);

    config_set_lan(unit, LAN_IPADDR, cfg->ipaddr);
    config_set_lan(unit, LAN_NETMASK, cfg->netmask);

    ip = inet_addr(cfg->ipaddr);
    mask = inet_addr(cfg->netmask);

    if(cfg->dhcpd_enable == 1)
    {
        config_set_int(LAN1_DHCP_IGNORE, 0);

        ip1 = inet_addr(cfg->dhcpd_start);
        ip2 = inet_addr(cfg->dhcpd_end);

        start = ntohl(ip1 - (ip & mask));
        limit = ntohl(ip2 - ip1) + 1;

        config_set_int(LAN1_DHCP_START, start);
        config_set_int(LAN1_DHCP_LIMIT, limit);
    }
    else
    {
        config_set_int(LAN1_DHCP_IGNORE, 1);
    }

    config_commit("network");
    config_commit("dhcp");

    return 0;
}

int libgw_get_wan_cfg(char *wan, wan_cfg_t *cfg)
{
    char dns[64] = {0};
    int unit = WAN1_UNIT;
    
    unit = get_wan_unit(wan);

    strncpy(cfg->wan, wan, sizeof(cfg->wan) - 1);
    
    strncpy(cfg->proto, config_get_wan(unit, WAN_PROTO), sizeof(cfg->proto) - 1);
    strncpy(cfg->ipaddr, config_get_wan(unit, WAN_IPADDR), sizeof(cfg->ipaddr) - 1);
    strncpy(cfg->netmask, config_get_wan(unit, WAN_NETMASK), sizeof(cfg->netmask) - 1);
    strncpy(cfg->gateway, config_get_wan(unit, WAN_GATEWAY), sizeof(cfg->gateway) - 1);
    
    strncpy(cfg->pppoe_user, config_get_wan(unit, WAN_PPPOE_USER), sizeof(cfg->pppoe_user) - 1);
    strncpy(cfg->pppoe_pwd, config_get_wan(unit, WAN_PPPOE_PWD), sizeof(cfg->pppoe_pwd) - 1);
    strncpy(cfg->service, config_get_wan(unit, WAN_PPPOE_SERVICE), sizeof(cfg->service) - 1);
    
    strncpy(dns, config_get_wan(unit, WAN_DNS), sizeof(dns) - 1);

    cfg->vlan = config_get_wan_int(unit, WAN_VLAN);

    if (dns[0] != '\0')
    {
        strncpy(cfg->dns_mode, "manual", sizeof(cfg->dns_mode) - 1);
        sscanf(dns, "%s %s", cfg->dns1, cfg->dns2);
    }
    else 
    {
        strncpy(cfg->dns_mode, "auto", sizeof(cfg->dns_mode) - 1);
    }
    
    return 0;
}

int libgw_set_wan_cfg(char *wan, wan_cfg_t *cfg)
{
    int cnt = 0;
    char dns[64] = {0};
    int unit = WAN1_UNIT;

    unit = get_wan_unit(wan);

    config_set_wan(unit, WAN_PROTO, cfg->proto);
  
    if (strcmp(cfg->proto, "dhcp") == 0)
    {
        /* 暂时没有参数 */
    }
    else if (strcmp(cfg->proto, "static") == 0)
    {
        config_set_wan(unit, WAN_IPADDR, cfg->ipaddr);   
        config_set_wan(unit, WAN_NETMASK, cfg->netmask);
        config_set_wan(unit, WAN_GATEWAY, cfg->gateway);
    }
    else if (strcmp(cfg->proto, "pppoe") == 0)
    {
        config_set_wan(unit, WAN_PPPOE_USER, cfg->pppoe_user);   
        config_set_wan(unit, WAN_PPPOE_PWD, cfg->pppoe_pwd);
        config_set_wan(unit, WAN_PPPOE_SERVICE, cfg->service);
    }
    else if (strcmp(cfg->proto, "pptp") == 0)
    {
        /* TODO */
    }
    else if (strcmp(cfg->proto, "l2tp") == 0)
    {
        /* TODO */
    }

    if (strcmp(cfg->dns_mode, "manual") == 0)
    {
        if (cfg->dns1[0] != '\0')
        {
            cnt = snprintf(dns, sizeof(dns), "%s", cfg->dns1);
        }
        
        if (cfg->dns2[0] != '\0')
        {
            snprintf(dns + cnt, sizeof(dns) - cnt, " %s", cfg->dns2);
        }
        
        config_set_wan(unit, WAN_DNS, dns);
    }
    else 
    {
        config_set_wan(unit, WAN_DNS, "");
    }

    config_commit("network");

    return 0;
}

int libgw_get_lan6_cfg(char *lan, lan6_cfg_t *cfg)
{
    int unit;
    
    unit = get_lan_unit(lan);

#if 0
    cfg->enabled = config_get_lan6_int(unit, "enabled");    

    strncpy(cfg->lan, config_get_lan6(unit, "lan"), sizeof(cfg->lan) - 1);
    strncpy(cfg->ip6type, config_get_lan6(unit, "ip6type"), sizeof(cfg->ip6type) - 1);
    strncpy(cfg->ip6prefix, config_get_lan6(unit, "ip6prefix"), sizeof(cfg->ip6prefix) - 1);
    
    cfg->ip6assign = config_get_lan6_int(unit, "ip6assign");
    cfg->leasetime = config_get_lan6_int(unit, "leasetime");
#endif

    return 0;
}

int libgw_get_wan6_cfg(char *wan, wan6_cfg_t *cfg)
{
    int unit;
    
    unit = get_wan_unit(wan);
    
    cfg->enabled = config_get_wan6_int(unit, "enabled");    

    strncpy(cfg->wan, config_get_wan6(unit, "lan"), sizeof(cfg->wan) - 1);
    strncpy(cfg->ip6type, config_get_wan6(unit, "ip6type"), sizeof(cfg->ip6type) - 1);
    strncpy(cfg->ip6addr, config_get_wan6(unit, "ip6prefix"), sizeof(cfg->ip6addr) - 1);
    cfg->ip6assign = config_get_wan6_int(unit, "ip6assign");
    strncpy(cfg->ip6gw, config_get_wan6(unit, "ip6gw"), sizeof(cfg->ip6gw) - 1);
    strncpy(cfg->ip6dns1, config_get_wan6(unit, "ip6dns1"), sizeof(cfg->ip6dns1) - 1);
    strncpy(cfg->ip6dns2, config_get_wan6(unit, "ip6dns2"), sizeof(cfg->ip6dns2) - 1);
    strncpy(cfg->ip6mode, config_get_wan6(unit, "ip6mode"), sizeof(cfg->ip6mode) - 1);
    cfg->ip6delegate = config_get_wan6_int(unit, "ip6delegate");
    strncpy(cfg->ip6dnsmode, config_get_wan6(unit, "ip6dnsmode"), sizeof(cfg->ip6dnsmode) - 1);
    
    return 0;
}

int libgw_get_dualwan_cfg(dualwan_cfg_t *cfg)
{    
    cfg->enabled = config_get_int(DUALWAN_ENABLED);
    strncpy(cfg->primary, config_get(DUALWAN_PRIMARY), sizeof(cfg->primary) - 1);
    strncpy(cfg->secondary, config_get(DUALWAN_SECONDARY), sizeof(cfg->secondary) - 1);
    cfg->mode = config_get_int(DUALWAN_MODE);
    cfg->weight1 = config_get_int(DUALWAN_WEIGHT1);
    cfg->weight2 = config_get_int(DUALWAN_WEIGHT2);
    
    return 0;
}

void _uci_enabled_wan2(int enabled)
{    
    if (enabled)
    {
        config_unset("network.wan2.disabled");
    }
    else
    {
        config_set("network.wan2.disabled", "1");
    }

    config_commit("network");
}

int libgw_set_dualwan_cfg(char *wan, dualwan_cfg_t *cfg)
{
    config_set_int(DUALWAN_ENABLED, cfg->enabled);

    if (cfg->enabled == 1)
    {
        config_set(DUALWAN_PRIMARY, cfg->primary);
        config_set(DUALWAN_SECONDARY, cfg->secondary);
        config_set_int(DUALWAN_MODE, cfg->mode);

        if (cfg->mode == 2)
        {
            config_set_int(DUALWAN_WEIGHT1, cfg->weight1);
            config_set_int(DUALWAN_WEIGHT2, cfg->weight2);
        }
    }

    _uci_enabled_wan2(cfg->enabled);
    
    config_commit("dualwan");

    return 0;   
}

#define WEB_NTWK

int parse_lan_config(cJSON *params, lan_cfg_t *cfg)
{
    int ret = 0;
    int intVal = 0;
    char *strVal = NULL;

    strVal = cjson_get_string(params, "lan");
    if (!strVal)
    {
        return -1;
    }
    
    strncpy(cfg->lan, strVal, sizeof(cfg->lan) - 1);

    strVal = cjson_get_string(params, "ipaddr");
    if (!strVal)
    {
        return -1;
    }
    
    strncpy(cfg->ipaddr, strVal, sizeof(cfg->ipaddr) - 1);

    strVal = cjson_get_string(params, "netmask");
    if (!strVal)
    {
        return -1;
    }
    
    strncpy(cfg->netmask, strVal, sizeof(cfg->netmask) - 1);

    ret = cjson_get_int(params, "dhcpd_enable", &intVal);
    if (ret < 0)
    {
        return -1;  
    }
    
    cfg->dhcpd_enable = intVal;

    strVal = cjson_get_string(params, "dhcpd_start");
    if (!strVal && cfg->dhcpd_enable == 1)
    {
        return -1;
    }
    
    strncpy(cfg->dhcpd_start, strVal, sizeof(cfg->dhcpd_start) - 1);

    strVal = cjson_get_string(params, "dhcpd_end");
    if (!strVal && cfg->dhcpd_enable == 1)
    {
        return -1;
    }
    
    strncpy(cfg->dhcpd_end, strVal, sizeof(cfg->dhcpd_end) - 1);

    return 0;
}

int parse_wan_config(cJSON *params, wan_cfg_t *cfg)
{
    char *strVal = NULL;

    strVal = cjson_get_string(params, "proto");
    if (!strVal)
    {
        return -1;
    }

    strncpy(cfg->proto, strVal, sizeof(cfg->proto) - 1);

    if (strcmp(cfg->proto, "static") == 0)
    {
        strVal = cjson_get_string(params, "ipaddr");
        if (!strVal)
        {
            return -1;
        }
        
        strncpy(cfg->ipaddr, strVal, sizeof(cfg->ipaddr) - 1);

        strVal = cjson_get_string(params, "netmask");
        if (!strVal)
        {
            return -1;
        }

        strncpy(cfg->netmask, strVal, sizeof(cfg->netmask) - 1);

        strVal = cjson_get_string(params, "gateway");
        if (!strVal)
        {
            return -1;
        }
        
        strncpy(cfg->gateway, strVal, sizeof(cfg->gateway) - 1);        
    }
    else if (strcmp(cfg->proto, "pppoe") == 0)
    {
        strVal = cjson_get_string(params, "username");
        if (!strVal)
        {
            return -1;
        }
        
        strncpy(cfg->pppoe_user, strVal, sizeof(cfg->pppoe_user) - 1);

        strVal = cjson_get_string(params, "password");
        if (!strVal)
        {
            return -1;
        }
        
        strncpy(cfg->pppoe_pwd, strVal, sizeof(cfg->pppoe_pwd) - 1);

        strVal = cjson_get_string(params, "service");
        if (strVal)
        {
            strncpy(cfg->service, strVal, sizeof(cfg->service) - 1);
        }
    }
    
    strVal = cjson_get_string(params, "dns_mode");
    if (!strVal)
    {
        return -1;
    }
    
    strncpy(cfg->dns_mode, strVal, sizeof(cfg->dns_mode) - 1);

    if (strcmp(cfg->dns_mode, "manual") == 0)
    {
        strVal = cjson_get_string(params, "dns1");
        if (!strVal)
        {
            return -1;
        }
        
        strncpy(cfg->dns1, strVal, sizeof(cfg->dns1) - 1);

        strVal = cjson_get_string(params, "dns2");
        if (strVal)
        {
            strncpy(cfg->dns2, strVal, sizeof(cfg->dns2) - 1);    
        }
    }

    return 0;
}

int parse_dualwan_config(cJSON *params, dualwan_cfg_t *cfg)
{
    int ret = 0;
    char *strVal = NULL;
    int intVal = 0;

    ret = cjson_get_int(params, "enabled", &intVal);
    if (ret < 0)
    {
        return -1;
    }

    cfg->enabled = intVal;

    if (intVal == 0)
    {
        return 0;
    }

    strVal = cjson_get_string(params, "primary");
    if (!strVal)
    {
        return -1;
    }
    
    strncpy(cfg->primary, strVal, sizeof(cfg->primary) - 1);

    strVal = cjson_get_string(params, "secondary");
    if (!strVal)
    {
        return -1;
    }

    strncpy(cfg->secondary, strVal, sizeof(cfg->secondary) - 1);
    
    ret = cjson_get_int(params, "mode", &cfg->mode);
    if (ret < 0)
    {
        return -1;
    }    

    if (cfg->mode == 2)
    {
        ret = cjson_get_int(params, "weight1", &cfg->weight1);
        if (ret < 0)
        {
            return -1;
        }

        ret = cjson_get_int(params, "weight2", &cfg->weight2);
        if (ret < 0)
        {
            return -1;
        }
    }
    return 0;
}

int parse_dualwan_failover_config(cJSON *params, dualwan_failover_cfg_t *cfg)
{
    int ret = 0;
    char *strVal = NULL;
    int intVal = 0;

    strVal = cjson_get_string(params, "interface");
    if (!strVal)
    {
        return -1;
    }
    
    strncpy(cfg->interface, strVal, sizeof(cfg->interface) - 1);

    ret = cjson_get_int(params, "interval", &intVal);
    if (ret < 0)
    {
        return -1;
    }

    cfg->interval = intVal;

    ret = cjson_get_int(params, "times", &intVal);
    if (ret < 0)
    {
        return -1;
    }

    cfg->times = intVal;

    strVal = cjson_get_string(params, "target");
    if (!strVal)
    {
        return -1;
    }

    strncpy(cfg->target, strVal, sizeof(cfg->target) - 1);

    strVal = cjson_get_string(params, "ipaddr");
    if (!strVal)
    {
        return -1;
    }

    strncpy(cfg->ipaddr, strVal, sizeof(cfg->ipaddr) - 1);
    
    return 0;
}


#define API_NTWK

int get_lan_config(cgi_request_t *req, cgi_response_t *resp)
{
    int ret = 0;
    int method = 0;
    cJSON *params = NULL;
    char *strVal = NULL;
    lan_cfg_t cfg;
    
    ret = param_init(req->post_data, &method, &params);
    if (ret < 0)
    {
        cgi_errno = CGI_ERR_PARAM;
        goto out;
    }

    strVal = cjson_get_string(params, "lan");
    if (!strVal)
    {    
        cgi_errno = CGI_ERR_CFG_PARAM;
        goto out;
    }

    memset(&cfg, 0x0, sizeof(lan_cfg_t));

    ret = libgw_get_lan_cfg("LAN1", &cfg);
    if (ret < 0)
    {    
        cgi_errno = CGI_ERR_CFG_FILE;
        goto out;
    }

    webs_json_header(req->out);
    webs_write(req->out, "{\"code\":%d,\"data\":{", cgi_errno);
    webs_write(req->out, "\"interface\":[{\"lan\":\"%s\",\"ipaddr\":\"%s\",\"netmask\":\"%s\","
			"\"dhcpd_enable\":%d,\"dhcpd_start\":\"%s\",\"dhcpd_end\":\"%s\"}]",
		    cfg.lan, cfg.ipaddr, cfg.netmask, cfg.dhcpd_enable, cfg.dhcpd_start, 
		    cfg.dhcpd_end);
    webs_write(req->out, "}}");
    
out:
    param_free();

    if (cgi_errno != CGI_ERR_OK)
    {
        webs_json_header(req->out);
        webs_write(req->out, "{\"code\":%d,\"data\":{}}", cgi_errno);
    }
    
    return ret;
}

int get_lan_status(cgi_request_t *req, cgi_response_t *resp)
{
    int ret = 0;
    int method = 0;
    cJSON *params = NULL;
    char *strVal = NULL;
    int unit;
    char macaddr[18];
    struct ubus_lan_status lan;
    int getall = 0;
    int cnt = 0;
    unsigned char mac[6];
    
    ret = param_init(req->post_data, &method, &params);
    if (ret < 0)
    {
        cgi_errno = CGI_ERR_PARAM; 
        goto out;
    }

    strVal = cjson_get_string(params, "lan");
    if (!strVal || strVal[0] == '\0')
    {    
        getall = 1;
    }

    if (getall)
    {
        webs_json_header(req->out);
        webs_write(req->out, "{\"code\":%d,\"data\":{", cgi_errno);
        webs_write(req->out, "\"interface\":[");

        for (unit = LAN1_UNIT; unit < _LAN_UNIT_MAX; unit ++)
        {
            memset(&lan, 0x0, sizeof(struct ubus_lan_status));
            ret = ubus_get_lan_status(lan_sec_names[unit], &lan);
            if (ret < 0)
            {
                continue;    
            }

            if (get_interface_hwaddr(lan.ifname, mac) == 0) 
            { 
                sprintf(macaddr, "%02X:%02X:%02X:%02X:%02X:%02X", 
                    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
            } 

            webs_write(req->out, "%s{\"lan\":\"%s\",\"macaddr\":\"%s\",\"ipaddr\":\"%s\",\"netmask\":\"%s\","
                "\"uptime\":%d}", (cnt > 0) ? "," : "", lan_names[unit], macaddr, lan.ipaddr, lan.netmask, lan.uptime);

            cnt ++;
        }
        webs_write(req->out, "]}}");
    }
    else
    {
        unit = get_lan_unit(strVal);
        memset(&lan, 0x0, sizeof(struct ubus_lan_status));
        ret = ubus_get_lan_status(lan_sec_names[unit], &lan);
        if (ret < 0)
        {
            cgi_errno = CGI_ERR_INTERNAL;
            goto out;
        }

        if (get_interface_hwaddr(lan.ifname, mac) == 0) 
        { 
            sprintf(macaddr, "%02X:%02X:%02X:%02X:%02X:%02X", 
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        }
        
        webs_json_header(req->out);
        webs_write(req->out, "{\"code\":%d,\"data\":{", cgi_errno);
        webs_write(req->out, "\"interface\":[");

        webs_write(req->out, "%s{\"lan\":\"%s\",\"macaddr\":\"%s\",\"ipaddr\":\"%s\",\"netmask\":\"%s\","
            "\"uptime\":%d}", (cnt > 0) ? "," : "", lan_names[unit], macaddr, lan.ipaddr, lan.netmask, lan.uptime);
        
        webs_write(req->out, "]}}");
    }
    
out:
    param_free();

    if (cgi_errno != CGI_ERR_OK)
    {
        webs_json_header(req->out);
        webs_write(req->out, "{\"code\":%d,\"data\":{}}", cgi_errno);
    }
    
    return ret;
}

int lan_interface_config(cgi_request_t *req, cgi_response_t *resp)
{
    int ret = 0;
    int method = 0;
    cJSON *params = NULL;

    ret = param_init(req->post_data, &method, &params);
    if (ret < 0)
    {   
        cgi_errno = CGI_ERR_PARAM;
        goto out;
    }
     
out:
    param_free();

    webs_json_header(req->out);
    webs_write(req->out, "{\"code\":%d,\"data\":{}}", cgi_errno);
        
    return 0;
}

int set_lan_config(cgi_request_t *req, cgi_response_t *resp)
{
    int ret = 0;
    int method = 0;
    char *lan = NULL;
    cJSON *params = NULL;
    lan_cfg_t cfg;
    
    ret = param_init(req->post_data, &method, &params);
    if (ret < 0)
    {
        cgi_errno = CGI_ERR_PARAM; 
        goto out;
    }

    lan = cjson_get_string(params, "lan");
    if (!lan)
    {
        cgi_errno = CGI_ERR_CFG_PARAM;
        goto out;
    }

    memset(&cfg, 0x0, sizeof(lan_cfg_t));
    
    ret = parse_lan_config(params, &cfg);
    if (ret < 0)
    {
        cgi_errno = CGI_ERR_CFG_PARAM;
        goto out;
    }

    libgw_set_lan_cfg("LAN1", &cfg);
 
    fork_exec(1, "/etc/init.d/network restart;/etc/init.d/dnsmasq restart");
   
out:
    param_free();

    webs_json_header(req->out);
    webs_write(req->out, "{\"code\":%d,\"data\":{}}", cgi_errno);

    return 0;
}

int get_wan_config(cgi_request_t *req, cgi_response_t *resp)
{
    int ret = 0;
    int method = 0;
    int getall = 0;
    cJSON *params = NULL;
    char *wan_name = NULL;
    wan_cfg_t cfg;
    
    ret = param_init(req->post_data, &method, &params);
    if (ret < 0)
    {
        cgi_errno = CGI_ERR_PARAM; 
        goto out;
    }

    wan_name = cjson_get_string(params, "wan");
    if (!wan_name || wan_name[0] == '\0')
    {    
        getall = 1;
    }

    memset(&cfg, 0x0, sizeof(wan_cfg_t));
    
    webs_json_header(req->out);
    webs_write(req->out, "{\"code\":%d,\"data\":{", cgi_errno);

    webs_write(req->out, "\"interface\":["); 

    if (getall == 0)
    {
        libgw_get_wan_cfg(wan_name, &cfg);

        webs_write(req->out, "{\"wan\":\"%s\",\"proto\":\"%s\",\"ipaddr\":\"%s\",\"macaddr\":\"%s\","
                "\"netmask\":\"%s\",\"gateway\":\"%s\",\"username\":\"%s\",\"password\":\"%s\","
                "\"service\":\"%s\",\"dns_mode\":\"%s\",\"dns1\":\"%s\",\"dns2\":\"%s\",\"vlan\":%d}",
                cfg.wan, cfg.proto, cfg.ipaddr, cfg.macaddr, cfg.netmask, cfg.gateway, cfg.pppoe_user, 
                cfg.pppoe_pwd, cfg.service, cfg.dns_mode, cfg.dns1, cfg.dns2, cfg.vlan);
    }
    else
    {
        libgw_get_wan_cfg("WAN1", &cfg);

        webs_write(req->out, "{\"wan\":\"%s\",\"proto\":\"%s\",\"ipaddr\":\"%s\",\"macaddr\":\"%s\","
                "\"netmask\":\"%s\",\"gateway\":\"%s\",\"username\":\"%s\",\"password\":\"%s\","
                "\"service\":\"%s\",\"dns_mode\":\"%s\",\"dns1\":\"%s\",\"dns2\":\"%s\",\"vlan\":%d}",
                cfg.wan, cfg.proto, cfg.ipaddr, cfg.macaddr, cfg.netmask, cfg.gateway, cfg.pppoe_user, 
                cfg.pppoe_pwd, cfg.service, cfg.dns_mode, cfg.dns1, cfg.dns2, cfg.vlan);

        libgw_get_wan_cfg("WAN2", &cfg);
        
        webs_write(req->out, ",{\"wan\":\"%s\",\"proto\":\"%s\",\"ipaddr\":\"%s\",\"macaddr\":\"%s\","
                "\"netmask\":\"%s\",\"gateway\":\"%s\",\"username\":\"%s\",\"password\":\"%s\","
                "\"service\":\"%s\",\"dns_mode\":\"%s\",\"dns1\":\"%s\",\"dns2\":\"%s\",\"vlan\":%d}",
                cfg.wan, cfg.proto, cfg.ipaddr, cfg.macaddr, cfg.netmask, cfg.gateway, cfg.pppoe_user, 
                cfg.pppoe_pwd, cfg.service, cfg.dns_mode, cfg.dns1, cfg.dns2, cfg.vlan);

    }
    
    webs_write(req->out, "]}}");
out:
    
    param_free();

    if (cgi_errno != CGI_ERR_OK)
    {
        webs_json_header(req->out);
        webs_write(req->out, "{\"code\":%d,\"data\":{}}", cgi_errno);
    }
    
    return ret;
}

int get_wan_status(cgi_request_t *req, cgi_response_t *resp)
{
    int ret = 0;
    int method = 0;
    cJSON *params = NULL;
    char *strVal = NULL;
    int unit;
    char macaddr[18];
    struct ubus_wan_status wan;
    int getall = 0;
    int cnt = 0;
    unsigned char mac[6];
    
    ret = param_init(req->post_data, &method, &params);
    if (ret < 0)
    {
        cgi_errno = CGI_ERR_PARAM; 
        goto out;
    }

    strVal = cjson_get_string(params, "wan");
    if (!strVal || strVal[0] == '\0')
    {    
        getall = 1;
    }

    if (getall)
    {
        webs_json_header(req->out);
        webs_write(req->out, "{\"code\":%d,\"data\":{", cgi_errno);
        webs_write(req->out, "\"interface\":[");

        for (unit = WAN1_UNIT; unit < _WAN_UNIT_MAX; unit ++)
        {
            memset(&wan, 0x0, sizeof(struct ubus_wan_status));
            ret = ubus_get_wan_status(wan_sec_names[unit], &wan);
            if (ret < 0)
            {
                continue;    
            }

            if (get_interface_hwaddr(wan.ifname, mac) == 0) 
            { 
                sprintf(macaddr, "%02X:%02X:%02X:%02X:%02X:%02X", 
                    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
            } 

            webs_write(req->out, "%s{\"wan\":\"%s\",\"macaddr\":\"%s\",\"proto\":\"%s\",\"ipaddr\":\"%s\","
                "\"netmask\":\"%s\",\"gateway\":\"%s\",\"dns1\":\"%s\",\"dns2\":\"%s\","
                "\"uptime\":%d}", (cnt > 0) ? "," : "", wan_names[unit], macaddr, wan.proto, wan.ipaddr, 
                wan.netmask, wan.gateway, wan.dns1, wan.dns2, wan.uptime);

            cnt ++;
        }
        webs_write(req->out, "]}}");
    }
    else
    {
        unit = get_wan_unit(strVal);
        memset(&wan, 0x0, sizeof(struct ubus_wan_status));
        ret = ubus_get_wan_status(wan_sec_names[unit], &wan);
        if (ret < 0)
        {
            cgi_errno = CGI_ERR_INTERNAL;
            goto out;
        }

        if (get_interface_hwaddr(wan.ifname, mac) == 0) 
        { 
            sprintf(macaddr, "%02X:%02X:%02X:%02X:%02X:%02X", 
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        }
        
        webs_json_header(req->out);
        webs_write(req->out, "{\"code\":%d,\"data\":{", cgi_errno);
        webs_write(req->out, "\"interface\":[");

        webs_write(req->out, "%s{\"wan\":\"%s\",\"macaddr\":\"%s\",\"proto\":\"%s\",\"ipaddr\":\"%s\","
            "\"netmask\":\"%s\",\"gateway\":\"%s\",\"dns1\":\"%s\",\"dns2\":\"%s\","
            "\"uptime\":%d}", (cnt > 0) ? "," : "", wan_names[unit], macaddr, wan.proto, wan.ipaddr, 
            wan.netmask, wan.gateway, wan.dns1, wan.dns2, wan.uptime);        
        webs_write(req->out, "]}}");
    }
    
out:
    param_free();

    if (cgi_errno != CGI_ERR_OK)
    {
        webs_json_header(req->out);
        webs_write(req->out, "{\"code\":%d,\"data\":{}}", cgi_errno);
    }
    
    return ret;
}

int set_wan_config(cgi_request_t *req, cgi_response_t *resp)
{
    int ret = 0;
    int method = 0;
    char *wan = NULL;
    cJSON *params = NULL;
    wan_cfg_t cfg;
    
    ret = param_init(req->post_data, &method, &params);
    if (ret < 0)
    {
        cgi_errno = CGI_ERR_PARAM; 
        goto out;
    }

    wan = cjson_get_string(params, "wan");
    if (!wan)
    {
        cgi_errno = CGI_ERR_CFG_PARAM;
        goto out;
    }

    memset(&cfg, 0x0, sizeof(wan_cfg_t));
    
    ret = parse_wan_config(params, &cfg);
    if (ret < 0)
    {
        cgi_errno = CGI_ERR_CFG_PARAM;
        goto out;
    }

    libgw_set_wan_cfg(wan, &cfg);

    fork_exec(1, "/etc/init.d/network restart");

out:
    param_free();

    webs_json_header(req->out);
    webs_write(req->out, "{\"code\":%d,\"data\":{}}", cgi_errno);

    return 0;
}

int get_lan6_status(cgi_request_t *req, cgi_response_t *resp)
{
    return 0;
}

int get_lan6_config(cgi_request_t *req, cgi_response_t *resp)
{
    int ret = 0;
    int method = 0;
    cJSON *params = NULL;
    char *strVal = NULL;
    lan6_cfg_t cfg;
    
    ret = param_init(req->post_data, &method, &params);
    if (ret < 0)
    {
        cgi_errno = CGI_ERR_PARAM; 
        goto out;
    }

    strVal = cjson_get_string(params, "lan");
    if (!strVal)
    {    
        cgi_errno = CGI_ERR_CFG_PARAM;
        goto out;
    }

    /* 获取所有Interface LAN IPv6协议接口配置 */
    if (strVal == '\0')
    {
 
    }
    else
    {
        memset(&cfg, 0x0, sizeof(lan6_cfg_t));

        ret = libgw_get_lan6_cfg(strVal, &cfg);
        if (ret < 0)
        {    
            cgi_errno = CGI_ERR_CFG_PARAM;
            goto out;
        }
    }
    
    webs_json_header(req->out);
    webs_write(req->out, "{\"code\":%d,\"data\":{", cgi_errno);
    webs_write(req->out, "\"interface\":[{\"lan\":\"%s\",\"ip6type\":\"%s\",\"ip6prefix\":\"%s\","
            "\"ip6assign\":%d,\"leasetime\":%d}]", cfg.lan, cfg.ip6type, cfg.ip6prefix, 
            cfg.ip6assign, cfg.leasetime);
    webs_write(req->out, "}}");
out:
    
    param_free();

    if (cgi_errno != CGI_ERR_OK)
    {
        webs_json_header(req->out);
        webs_write(req->out, "{\"code\":%d,\"data\":{}}", cgi_errno);
    }
    
    return ret;
}

int set_lan6_config(cgi_request_t *req, cgi_response_t *resp)
{
    return 0;
}

int get_wan6_status(cgi_request_t *req, cgi_response_t *resp)
{
    return 0;
}

int get_wan6_config(cgi_request_t *req, cgi_response_t *resp)
{
    int ret = 0;
    int method = 0;
    cJSON *params = NULL;
    char *strVal = NULL;
    wan6_cfg_t cfg;
    
    ret = param_init(req->post_data, &method, &params);
    if (ret < 0)
    {
        cgi_errno = CGI_ERR_PARAM; 
        goto out;
    }

    strVal = cjson_get_string(params, "wan");
    if (!strVal)
    {    
        cgi_errno = CGI_ERR_CFG_PARAM;
        goto out;
    }

    /* 获取所有Interface WAN IPv6协议接口配置 */
    if (strVal == '\0')
    {
            
    }
    else
    {
        memset(&cfg, 0x0, sizeof(wan6_cfg_t));

        ret = libgw_get_wan6_cfg(strVal, &cfg);
        if (ret < 0)
        {    
            cgi_errno = CGI_ERR_CFG_PARAM;
            goto out;
        }
    }
    
    webs_json_header(req->out);
    webs_write(req->out, "{\"code\":%d,\"data\":{", cgi_errno);
    webs_write(req->out, "\"interface\":[{\"wan\":\"%s\",\"ip6type\":\"%s\",\"ip6prefix\":\"%s\","
            "\"ip6assign\":%d,\"leasetime\":%d}]", cfg.wan, cfg.ip6type, cfg.ip6addr, 
            cfg.ip6assign, cfg.ip6gw);
    webs_write(req->out, "}}");
out:
    
    param_free();

    if (cgi_errno != CGI_ERR_OK)
    {
        webs_json_header(req->out);
        webs_write(req->out, "{\"code\":%d,\"data\":{}}", cgi_errno);
    }
    
    return ret;
}

int set_wan6_config(cgi_request_t *req, cgi_response_t *resp)
{
    return 0;
}

/* 多WAN状态 */
int get_dualwan_status(cgi_request_t *req, cgi_response_t *resp)
{
    int ret = 0;
    int dualwan = 0;

    dualwan = config_get(DUALWAN_ENABLED);
    if (!dualwan)
    {
        cgi_errno = CGI_DUALWAN_DISABLED;
        goto out;
    }

    webs_json_header(req->out);
    webs_write(req->out, "{\"code\":%d,\"data\":{", cgi_errno);
    webs_write(req->out, "\"dualwan\":[");
    webs_write(req->out, "{\"interface\":\"WAN1\",\"state\":\"down\"}");
    webs_write(req->out, ",{\"interface\":\"WAN2\",\"state\":\"down\"}");
    webs_write(req->out, "}}");    

out:
    if (cgi_errno != CGI_ERR_OK)
    {
        webs_json_header(req->out);
        webs_write(req->out, "{\"code\":%d,\"data\":{}}", cgi_errno);
    }    

    return 0;
}

int get_dualwan_config(cgi_request_t *req, cgi_response_t *resp)
{
    int ret = 0;
    dualwan_cfg_t cfg;

    memset(&cfg, 0x0, sizeof(dualwan_cfg_t));

    ret = libgw_get_dualwan_cfg(&cfg);
    if (ret < 0)
    {
        cgi_errno = CGI_ERR_CFG_FILE;
        goto out;
    }
    
    webs_json_header(req->out);
    webs_write(req->out, "{\"code\":%d,\"data\":{", cgi_errno);
    webs_write(req->out, "\"enabled\":%d,\"primary\":\"%s\",\"secondary\":\"%s\","
            "\"mode\":%d,\"weight1\":%d,\"weight2\":%d", cfg.enabled, cfg.primary,
            cfg.secondary, cfg.mode, cfg.weight1, cfg.weight2);
    webs_write(req->out, "}}");
    
out:

    if (cgi_errno != CGI_ERR_OK)
    {
        webs_json_header(req->out);
        webs_write(req->out, "{\"code\":%d,\"data\":{}}", cgi_errno);
    }
    
    return 0;
}

int set_dualwan_config(cgi_request_t *req, cgi_response_t *resp)
{
    int ret = 0;
    int method = 0;
    char *wan = NULL;
    cJSON *params = NULL;
    dualwan_cfg_t cfg;

    ret = param_init(req->post_data, &method, &params);
    if (ret < 0)
    {
        cgi_errno = CGI_ERR_PARAM; 
        goto out;
    }

    memset(&cfg, 0x0, sizeof(dualwan_cfg_t));

    ret = parse_dualwan_config(params, &cfg);
    if (ret < 0)
    {
        cgi_errno = CGI_ERR_CFG_PARAM;
        goto out;
    }

    libgw_set_dualwan_cfg(wan, &cfg);

    fork_exec(1, "/etc/init.d/dualwan restart");

out:
    param_free();

    webs_json_header(req->out);
    webs_write(req->out, "{\"code\":%d,\"data\":{}}", cgi_errno);
    
    return 0;
}

int libgw_get_dualwan_failover_cfg(char *wan, dualwan_failover_cfg_t *cfg)
{
    int unit = 0;

    unit = get_wan_unit(wan);
    
    cfg->interval = config_get_dualwan_int(unit, "interval");
    cfg->times = config_get_dualwan_int(unit, "times");
    strncpy(cfg->target, config_get_dualwan(unit, "target"), sizeof(cfg->target));
    strncpy(cfg->ipaddr, config_get_dualwan(unit, "ipaddr"), sizeof(cfg->ipaddr));

    return 0;
}

int libgw_set_dualwan_failover_cfg(char *wan, dualwan_failover_cfg_t *cfg)
{
    int unit = 0;

    unit = get_wan_unit(wan);
    config_set_dualwan_int(unit, "interval", cfg->interval);
    config_set_dualwan_int(unit, "times", cfg->times);
    config_set_dualwan(unit, "target", cfg->target);
    config_set_dualwan(unit, "ipaddr", cfg->ipaddr);

    config_commit("dualwan");

    return 0;
}

int get_dualwan_check_config(cgi_request_t *req, cJSON *params)
{
    int ret = 0;
    int getall = 0;
    char *wan_name = NULL;
    int unit = 0;
    dualwan_failover_cfg_t cfg;

    wan_name = cjson_get_string(params, "wan");
    if (!wan_name || wan_name[0] == '\0')
    {
        getall = 1;
    }

    webs_json_header(req->out);
    webs_write(req->out, "{\"code\":%d,\"data\":{", cgi_errno);
    webs_write(req->out, "\"dualwan\":[");
    
    if (getall == 0)
    {
        memset(&cfg, 0x0, sizeof(dualwan_failover_cfg_t));
        libgw_get_dualwan_failover_cfg(wan_name, &cfg);        
        webs_write(req->out, "{\"interface\":\"%s\",\"interval\":%d,\"times\":%d,\"target\":\"%s\",\"ipaddr\":\"%s\"}",
            wan_name, cfg.interval, cfg.times, cfg.target, cfg.ipaddr);
    }
    else if (getall == 1)
    {
        libgw_get_dualwan_failover_cfg("WAN1", &cfg);        
        webs_write(req->out, "{\"interface\":\"%s\",\"interval\":%d,\"times\":%d,\"target\":\"%s\",\"ipaddr\":\"%s\"}",
            "WAN1", cfg.interval, cfg.times, cfg.target, cfg.ipaddr);        

        libgw_get_dualwan_failover_cfg("WAN2", &cfg);        
        webs_write(req->out, ",{\"interface\":\"%s\",\"interval\":%d,\"times\":%d,\"target\":\"%s\",\"ipaddr\":\"%s\"}",
            "WAN2", cfg.interval, cfg.times, cfg.target, cfg.ipaddr);
    }

    webs_write(req->out, "]}}");

    return CGI_ERR_OK;
}

int set_dualwan_check_config(cgi_request_t *req, cJSON *params)
{
    int ret = 0;
    dualwan_failover_cfg_t cfg;

    memset(&cfg, 0x0, sizeof(dualwan_failover_cfg_t));

    ret = parse_dualwan_failover_config(params, &cfg);
    if (ret < 0)
    {
        return CGI_ERR_CFG_PARAM;
    }

    libgw_set_dualwan_failover_cfg(cfg.interface, &cfg);

    //fork_exec(1, "/etc/init.d/dualwan restart");

    webs_json_header(req->out);
    webs_write(req->out, "{\"code\":%d,\"data\":{}}", cgi_errno);
    
    return CGI_ERR_OK;
}

int dualwan_check_config(cgi_request_t *req, cgi_response_t *resp)
{
    int ret = 0;
    int method = 0;
    cJSON *params = NULL;

    ret = param_init(req->post_data, &method, &params);
    if (ret < 0)
    {   
        cgi_errno = CGI_ERR_PARAM;
        goto out;
    }
    
    switch(method)
    {
        case CGI_GET:
            cgi_errno = get_dualwan_check_config(req, params);
            break;
        case CGI_SET:
            cgi_errno = set_dualwan_check_config(req, params);
            break;
        default:
            cgi_errno = CGI_ERR_NOT_FOUND;
            break;
    }

out:
    param_free();

    if (cgi_errno != CGI_ERR_OK)
    {
        webs_json_header(req->out);
        webs_write(req->out, "{\"code\":%d,\"data\":{}}", cgi_errno);
    }
    
    return 0;
}

/* brief info */
int get_interface_lan(cgi_request_t *req, cgi_response_t *resp)
{
    webs_json_header(req->out);
    webs_write(req->out, "{\"code\":0,\"data\":{\"num\":1,\"interface\":[{\"lan\":\"LAN1\"}]}}");
    return 0;
}

/* 获取WAN接口数 */
int get_interface_wan(cgi_request_t *req, cgi_response_t *resp)
{
    int dualwan = 0;

    /* 是否开启了双WAN口 */
    dualwan = config_get_int(DUALWAN_ENABLED);
    
    webs_json_header(req->out);
    
    webs_write(req->out, "{\"code\":0,\"data\":{");
    webs_write(req->out, "\"num\":%d,\"interface\":[", (dualwan == 1) ? 2 : 1);
    webs_write(req->out, "{\"wan\":\"WAN1\"}");
    
    if (dualwan)
    {
        webs_write(req->out, ",{\"wan\":\"WAN2\"}");
    }
    
    webs_write(req->out, "]}}");
    
    return 0;
}
