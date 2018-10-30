
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "utils.h"
#include "network.h"

int g_lan_idx = 0;

void get_lan1_cfg(lan_cfg_t *lan)
{
    int ignore = 0;
    int start, limit;
    uint32_t ip, mask;
    uint32_t ip1, ip2;
    struct in_addr addr;
    
    strncpy(lan->name, LAN1_NAME, sizeof(lan->name) - 1);    
    strncpy(lan->ipaddr, config_get(LAN1_IPADDR), sizeof(lan->ipaddr) - 1);
    strncpy(lan->netmask, config_get(LAN1_NETMASK), sizeof(lan->netmask) - 1);

    ignore = config_get_int(LAN1_DHCP_IGNORE);
    lan->dhcpd_enable = ((ignore == 0) ? 1 : 0);

    start = config_get_int(LAN1_DHCP_START);
    limit = config_get_int(LAN1_DHCP_LIMIT);

    ip = inet_addr(lan->ipaddr);
    mask = inet_addr(lan->netmask);

    ip1 = (ip & mask) + htonl(start);
    ip2 = ip1 + htonl(limit - 1);

    memcpy(&addr, &ip1, 4);
    strncpy(lan->dhcpd_start, inet_ntoa(addr), sizeof(lan->dhcpd_start) - 1);

    memcpy(&addr, &ip2, 4);
    strncpy(lan->dhcpd_end, inet_ntoa(addr), sizeof(lan->dhcpd_end) - 1);

    lan->ripd_enable = 0;
    lan->rip_direction = 0;
    lan->rip_version  = 0;
    
    lan->vlanid = 1;
}

void set_lan1_cfg(lan_cfg_t *lan)
{
    int start, limit;
    uint32_t ip, mask;
    uint32_t ip1, ip2;

    config_set(LAN1_IPADDR, lan->ipaddr);
    config_set(LAN1_NETMASK, lan->netmask);

    ip = inet_addr(lan->ipaddr);
    mask = inet_addr(lan->netmask);

    if(lan->dhcpd_enable == 1)
    {
        config_set_int(LAN1_DHCP_IGNORE, 0);

        ip1 = inet_addr(lan->dhcpd_start);
        ip2 = inet_addr(lan->dhcpd_end);

        start = ntohl(ip1 - (ip & mask));
        limit = ntohl(ip2 - ip1) + 1;

        config_set_int(LAN1_DHCP_START, start);
        config_set_int(LAN1_DHCP_LIMIT, limit);
    }
    else
    {
        config_set_int(LAN1_DHCP_IGNORE, 1);
    }
}

void lan_subnet_config_get(int idx, lan_cfg_t *lan)
{
    if(idx == 0)
    {
        get_lan1_cfg(lan);
    }
}

void lan_subnet_config_set(int idx, lan_cfg_t *lan)
{
    if(idx == 0)
    {
        set_lan1_cfg(lan);
    }
}

int parse_lan_param(cJSON *item, struct lan_cfg *lan)
{
    int ret = 0;
    int intVal = 0;
    char *strVal = NULL;

    if(!item || item->type != cJSON_Object)
    {
        return -1;
    }

    strVal = cjson_get_string(item, "name");
    if(!strVal)
    {
        return -1;
    }
    strncpy(lan->name, strVal, sizeof(lan->name) - 1);

    strVal = cjson_get_string(item, "ipaddr");
    if(!strVal)
    {
        return -1;
    }
    strncpy(lan->ipaddr, strVal, sizeof(lan->ipaddr) - 1);

    strVal = cjson_get_string(item, "netmask");
    if(!strVal)
    {
        return -1;
    }  
    strncpy(lan->netmask, strVal, sizeof(lan->netmask) - 1);

    ret = cjson_get_int(item, "dhcp_enable", &intVal);
    if(ret < 0)
    {
        return -1;
    }
    lan->dhcpd_enable = intVal;

    strVal = cjson_get_string(item, "dhcp_start");
    if(!strVal)
    {
        return -1;
    }
    strncpy(lan->dhcpd_start, strVal, sizeof(lan->dhcpd_start) - 1); 

    strVal = cjson_get_string(item, "dhcp_end");
    if(!strVal)
    {
        return -1;
    }
    strncpy(lan->dhcpd_end, strVal, sizeof(lan->dhcpd_end) - 1); 

    ret = cjson_get_int(item, "ripd_enable", &intVal);
    if(ret == 0)
    {
        lan->ripd_enable = intVal;
    }
    
    ret = cjson_get_int(item, "rip_direction", &intVal);
    if(ret == 0)
    {
        lan->rip_direction = intVal;
    }

    ret = cjson_get_int(item, "rip_version", &intVal);
    if(ret == 0)
    {
        lan->rip_version = intVal;
    }

    strVal = cjson_get_string(item, "macaddr");
    if(!strVal)
    {
        return -1;
    }
    strncpy(lan->macaddr, strVal, sizeof(lan->macaddr) - 1);    

    ret = cjson_get_int(item, "vlanid", &intVal);
    if(ret < 0)
    {
        return -1;
    }
    lan->vlanid = intVal;

    strVal = cjson_get_string(item, "desc");
    if(!strVal)
    {
        return -1;
    }
    strncpy(lan->desc, strVal, sizeof(lan->desc) - 1);

    return 0;
}

/* 显示子网列表 */
int lan_subnet_list()
{
    int i = 0;
    int lan_num;
    lan_cfg_t lan;
    cJSON *rObj = NULL;
    cJSON *data = NULL;
    cJSON *subnet = NULL;

    rObj = cJSON_CreateObject();
    data = cJSON_CreateObject();
    subnet = cJSON_CreateArray();
    
    if(!rObj || !data || !subnet)
    {
        cgi_errno = CGI_ERR_OTHER;
        goto err;
    }

    lan_num = 1;
    
    for(i = 0; i < lan_num; i ++)
    {
        cJSON *item = NULL;

        item = cJSON_CreateObject();
        if(!item)
        {
            cgi_errno = CGI_ERR_OTHER;
            goto err;
        }
        
        memset(&lan, 0x0, sizeof(lan_cfg_t));
    
        lan_subnet_config_get(i, &lan);

        cJSON_AddNumberToObject(item, "id", i + 1);
        cJSON_AddStringToObject(item, "name", lan.name);
        cJSON_AddStringToObject(item, "ipaddr", lan.ipaddr);
        cJSON_AddStringToObject(item, "netmask", lan.netmask);
        cJSON_AddStringToObject(item, "macaddr", lan.macaddr);
        cJSON_AddNumberToObject(item, "dhcp_enable", lan.dhcpd_enable);
        cJSON_AddStringToObject(item, "dhcp_start", lan.dhcpd_start);
        cJSON_AddStringToObject(item, "dhcp_end", lan.dhcpd_end);
        cJSON_AddNumberToObject(item, "ripd_enable", lan.ripd_enable);
        cJSON_AddNumberToObject(item, "rip_version", lan.rip_version);        
        cJSON_AddNumberToObject(item, "rip_direction", lan.rip_direction);
        cJSON_AddNumberToObject(item, "vlanid", lan.vlanid);
        cJSON_AddStringToObject(item, "desc", lan.desc);

        cJSON_AddItemToArray(subnet, item);
    }

    cJSON_AddNumberToObject(data, "num", lan_num);
    cJSON_AddItemToObject(data, "subnet", subnet);
    cJSON_AddNumberToObject(rObj, "code", cgi_errno);
    cJSON_AddItemToObject(rObj, "data", data); 

    char *out = NULL;

    out = cJSON_PrintUnformatted(rObj);
    if(!out)
    {
        cgi_errno = CGI_ERR_OTHER;
        goto err;
    }

    webs_write(stdout, "%s", out);
    free(out);

    if(rObj)
    {
        cJSON_Delete(rObj);
    }
    
err:
    if(cgi_errno != CGI_ERR_OK)
    {
        webs_write(stdout, "{\"code\":%d,\"data\":{}}", cgi_errno);
    }

    return 0;
}

int lan_subnet_edit(char *data, int len)
{
    int ret = 0;
    cJSON *rObj = NULL;
    cJSON *item = NULL;
    struct lan_cfg lan;
    int lan_num, lan_id;
    char lan_name[20] = {0};

    lan_num = 1;

    rObj = cJSON_Parse(data);
    if(!rObj)
    {
        ret = -1;
        cgi_errno = CGI_ERR_OTHER;
        goto err;
    }
    
    cgi_debug("\n");

    item = cJSON_GetObjectItem(rObj, "subnet");
    if(!item)
    {
        ret = -1;
        cgi_errno = CGI_ERR_PARAM;
        goto err;
    }
    
    cgi_debug("\n");
    
    memset(&lan, 0x0, sizeof(struct lan_cfg));

    ret = cjson_get_int(item, "id", &lan_id);
    if(ret < 0 || lan_id != 1)
    {
        ret = -1;
        cgi_errno = CGI_ERR_PARAM;
        goto err;
    }

    cgi_debug("\n");
    
    ret = parse_lan_param(item, &lan);
    if(ret < 0)
    {
        ret = -1;
        cgi_errno = CGI_ERR_PARAM;
        goto err;
    }
    
    cgi_debug("\n");

    strncpy(lan_name, "LAN1", sizeof(lan_name) - 1);
    lan_subnet_config_set((lan_id - 1), &lan);
    
    /* 保存配置 */
    config_commit();

    cgi_debug("\n");

    g_lan_idx = lan_id;
    cgi_log_info("edit %s subnet ok", lan_name);
    
err:
    if(rObj)
    {
        cJSON_Delete(rObj);
    }
    
    fprintf(stdout, "{\"code\":%d,\"data\":{}}", cgi_errno);   

    return ret;
}

int network_main(char *cmd, char *data)
{
    int ret = 0;

    if (!cmd)
    {
        return -1;
    }

    if (strcmp(cmd, "lan_subnet_list") == 0)
    {
        return lan_subnet_list();
    }
    
    if (data != NULL)
    {
        if (strcmp(cmd, "lan_subnet_edit") == 0)
        {
            ret = lan_subnet_edit(data, strlen(data));
        }

        if (ret == 0)
        {
            fork_exec(1, "/etc/init.d/network restart;/etc/init.d/dnsmasq restart");
        }
    }

    return ret;
}
