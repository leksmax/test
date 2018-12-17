
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "servlet.h"
#include "network.h"
#include "utils.h"

const char *lan_section_names[] = {
    "lan",
    "lan2",
    "lan3",
    "lan4"
};

const char *wan_section_names[] = {
    "wan",
    "wan2",
    "wan3",
    "wan4"
};

int get_lan_unit(char *name)
{
    int unit = 0;
    
    if (!name)
    {
        return -1;
    }

    if((sscanf(name, "LAN%d", &unit)) != 1)
    {
        return -1;
    }

    return unit;
}

int get_wan_unit(char *name)
{
    int unit = 0;
    
    if (!name)
    {
        return -1;
    }

    if((sscanf(name, "WAN%d", &unit)) != 1)
    {
        return -1;
    }

    return unit;
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
    strncpy(cfg->ipaddr, config_get(LAN1_IPADDR), sizeof(cfg->ipaddr) - 1);
    strncpy(cfg->netmask, config_get(LAN1_NETMASK), sizeof(cfg->netmask) - 1);

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
    int start, limit;
    uint32_t ip, mask;
    uint32_t ip1, ip2;

    config_set(LAN1_IPADDR, cfg->ipaddr);
    config_set(LAN1_NETMASK, cfg->netmask);

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
    int unit = 1;
    int ignore = 0;
    int start, limit;
    uint32_t ip, mask;
    uint32_t ip1, ip2;
    struct in_addr addr;
    char dns[64] = {0};
    
    unit = get_wan_unit(wan);
    if (unit < 0)
    {
        return -1;
    }
        
    strncpy(cfg->wan, wan, sizeof(cfg->wan) - 1);
    strncpy(cfg->proto, config_get(WAN1_PROTO), sizeof(cfg->proto) - 1);
    strncpy(cfg->ipaddr, config_get(WAN1_IPADDR), sizeof(cfg->ipaddr) - 1);
    strncpy(cfg->netmask, config_get(WAN1_NETMASK), sizeof(cfg->netmask) - 1);
    strncpy(cfg->gateway, config_get(WAN1_GATEWAY), sizeof(cfg->gateway) - 1);
    
    strncpy(cfg->pppoe_user, config_get(WAN1_PPPOE_USER), sizeof(cfg->pppoe_user) - 1);
    strncpy(cfg->pppoe_pwd, config_get(WAN1_PPPOE_PWD), sizeof(cfg->pppoe_pwd) - 1);
    strncpy(cfg->service, config_get(WAN1_PPPOE_SERVICE), sizeof(cfg->service) - 1);
    strncpy(dns, config_get(WAN1_DNS), sizeof(dns) - 1);

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

    config_set(WAN1_PROTO, cfg->proto);
  
    if (strcmp(cfg->proto, "dhcp") == 0)
    {
    }
    else if (strcmp(cfg->proto, "static") == 0)
    {
        config_set(WAN1_IPADDR, cfg->ipaddr);   
        config_set(WAN1_NETMASK, cfg->netmask);
        config_set(WAN1_GATEWAY, cfg->gateway);
    }
    else if (strcmp(cfg->proto, "pppoe") == 0)
    {
        config_set(WAN1_PPPOE_USER, cfg->pppoe_user);   
        config_set(WAN1_PPPOE_PWD, cfg->pppoe_pwd);
        config_set(WAN1_PPPOE_SERVICE, cfg->service);
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
        //log_debug("cfg->dns1 = %s\n", cfg->dns1);
        //log_debug("cfg->dns2 = %s\n", cfg->dns2);

        if (cfg->dns1[0] != '\0')
        {
            cnt = snprintf(dns, sizeof(dns), "%s", cfg->dns1);
        }
        
        if (cfg->dns2[0] != '\0')
        {
            snprintf(dns + cnt, sizeof(dns) - cnt, " %s", cfg->dns2);
        }

        //log_debug("dns = %s\n", dns);
        
        config_set(WAN1_DNS, dns);
    }
    else 
    {
        config_unset(WAN1_DNS);
    }

    config_commit("network");

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

        //log_debug("cfg->dns1 = %s\n", cfg->dns1);
        //log_debug("strVal = %s\n", strVal);

        strVal = cjson_get_string(params, "dns2");
        if (strVal)
        {
            strncpy(cfg->dns2, strVal, sizeof(cfg->dns2) - 1);    
        }
    }

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
        cgi_errno = 101;
        goto out;
    }

    strVal = cjson_get_string(params, "lan");
    if (!strVal)
    {    
        cgi_errno = 102;
        goto out;
    }

    memset(&cfg, 0x0, sizeof(lan_cfg_t));

    ret = libgw_get_lan_cfg("LAN1", &cfg);
    if (ret < 0)
    {    
        cgi_errno = 102;
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

int get_dhcp_config(cgi_request_t *req, cgi_response_t *resp)
{
    return 0;
}

int get_dhcp_list(cgi_request_t *req, cgi_response_t *resp)
{
    return 0;
}

int get_dhcp_reserv(cgi_request_t *req, cgi_response_t *resp)
{
    return 0;
}

int get_wan_config(cgi_request_t *req, cgi_response_t *resp)
{
    int ret = 0;
    int method = 0;
    cJSON *params = NULL;
    char *strVal = NULL;
    wan_cfg_t cfg;
    
    ret = param_init(req->post_data, &method, &params);
    if (ret < 0)
    {
        cgi_errno = 101;
        goto out;
    }

    strVal = cjson_get_string(params, "wan");
    if (!strVal)
    {    
        cgi_errno = 102;
        goto out;
    }

    memset(&cfg, 0x0, sizeof(wan_cfg_t));

    ret = libgw_get_wan_cfg("WAN1", &cfg);
    if (ret < 0)
    {    
        cgi_errno = 102;
        goto out;
    }
    
    webs_json_header(req->out);
    webs_write(req->out, "{\"code\":%d,\"data\":{", cgi_errno);
    webs_write(req->out, "\"interface\":[{\"wan\":\"%s\",\"proto\":\"%s\",\"ipaddr\":\"%s\","
            "\"netmask\":\"%s\",\"gateway\":\"%s\",\"username\":\"%s\",\"password\":\"%s\","
            "\"service\":\"%s\",\"dns_mode\":\"%s\",\"dns1\":\"%s\",\"dns2\":\"%s\"}]",
            cfg.wan, cfg.proto, cfg.ipaddr, cfg.netmask, cfg.gateway, cfg.pppoe_user, 
            cfg.pppoe_pwd, cfg.service, cfg.dns_mode, cfg.dns1, cfg.dns2);
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
        cgi_errno = 101; 
        goto out;
    }

    lan = cjson_get_string(params, "lan");
    if (!lan)
    {
        cgi_errno = 102;
        goto out;
    }

    memset(&cfg, 0x0, sizeof(lan_cfg_t));
    
    ret = parse_lan_config(params, &cfg);
    if (ret < 0)
    {
        cgi_errno = 102;
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

int add_dhcp_reserv(cgi_request_t *req, cgi_response_t *resp)
{
    return 0;
}

int delete_dhcp_reserv(cgi_request_t *req, cgi_response_t *resp)
{
    return 0;
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
        cgi_errno = 101; 
        goto out;
    }

    wan = cjson_get_string(params, "wan");
    if (!wan)
    {
        cgi_errno = 102;
        goto out;
    }

    memset(&cfg, 0x0, sizeof(wan_cfg_t));
    
    ret = parse_wan_config(params, &cfg);
    if (ret < 0)
    {
        cgi_errno = 102;
        goto out;
    }

    libgw_set_wan_cfg("WAN1", &cfg);

    fork_exec(1, "/etc/init.d/network restart");
    
out:
    param_free();

    webs_json_header(req->out);
    webs_write(req->out, "{\"code\":%d,\"data\":{}}", cgi_errno);

    return 0;
}

/* brief info */
int get_interface_lan(cgi_request_t *req, cgi_response_t *resp)
{
    webs_json_header(req->out);
    webs_write(req->out, "{\"code\":0,\"data\":{\"num\":1,\"interface\":[{\"lan\":\"LAN1\"}]}}");
    return 0;
}

/* brief info */
int get_interface_wan(cgi_request_t *req, cgi_response_t *resp)
{
    webs_json_header(req->out);
    webs_write(req->out, "{\"code\":0,\"data\":{\"num\":1,\"interface\":[{\"wan\":\"WAN1\"}]}}");
    return 0;
}
