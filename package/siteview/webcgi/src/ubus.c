
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ubus.h"
#include "utils.h"

int _parse_lan_status(char *buf, struct ubus_lan_status *lan)
{
    int ret = 0;
    int intVal = 0;
    char *strVal = NULL;    
    cJSON *root = NULL;
    cJSON *item = NULL;

    root = cJSON_Parse((const char *)buf);
    if (!root)
    {
        return -1;
    }
    
    ret = cjson_get_bool(root, "up", &intVal);
    if (ret < 0)
    {
        goto end;
    }

    lan->status = intVal;

    strVal = cjson_get_string(root, "device");
    if (!strVal)
    {
        ret = -1;
        goto end;
    }
    
    strncpy(lan->ifname, strVal, sizeof(lan->ifname) - 1);

    if (lan->status == 0)
    {
        goto end;
    }

    ret = cjson_get_int(root, "uptime", &intVal);
    if (ret < 0)
    {
        goto end;   
    }

    lan->uptime = intVal;

    /* addr4 */    
    cJSON *addr4 = NULL;
    addr4 = cJSON_GetObjectItem(root, "ipv4-address");
    if (!addr4 || addr4->type != cJSON_Array)
    {
        goto end;
    }

    intVal = cJSON_GetArraySize(addr4);
    if (intVal > 0)
    {
        item = cJSON_GetArrayItem(addr4, 0);
        if (item->type != cJSON_Object)
        {
            goto end;
        }

        strVal = cjson_get_string(item, "address");
        if (strVal)
        {
            strncpy(lan->ipaddr, strVal, sizeof(lan->ipaddr) - 1);
        }
        
        ret = cjson_get_int(item, "mask", &intVal);
        if (ret < 0)
        {
            goto end;
        }

        strncpy(lan->netmask, prefix_to_mask_str(intVal), sizeof(lan->netmask) - 1);
    }

end:
    cJSON_Delete(root);

    return ret;
}


int _parse_wan_status(char *buf, struct ubus_wan_status *wan)
{
    int ret = 0;
    int intVal = 0;
    char *strVal = NULL;    
    cJSON *root = NULL;
    cJSON *item = NULL;
    int count = 0;

    root = cJSON_Parse((const char *)buf);
    if (!root)
    {
        return -1;
    }
    
    ret = cjson_get_bool(root, "up", &intVal);
    if (ret < 0)
    {
        goto end;
    }

    wan->status = intVal;

    strVal = cjson_get_string(root, "device");
    if (!strVal)
    {
        ret = -1;
        goto end;
    }
    
    strncpy(wan->ifname, strVal, sizeof(wan->ifname) - 1);

    if (wan->status == 0)
    {
        goto end;
    }

    ret = cjson_get_int(root, "uptime", &intVal);
    if (ret < 0)
    {
        goto end;   
    }

    wan->uptime = intVal;

    strVal = cjson_get_string(root, "proto");
    if (strVal)
    {
        strncpy(wan->proto, strVal, sizeof(wan->proto) - 1);
    }

    ret = cjson_get_int(root, "metric", &intVal);
    if (ret < 0)
    {
        goto end;
    }

    wan->metric = intVal;

    /* addr4 */    
    cJSON *addr4 = NULL;
    addr4 = cJSON_GetObjectItem(root, "ipv4-address");
    if (!addr4 || addr4->type != cJSON_Array)
    {
        goto end;
    }

    intVal = cJSON_GetArraySize(addr4);
    if (intVal > 0)
    {
        item = cJSON_GetArrayItem(addr4, 0);
        if (item->type != cJSON_Object)
        {
            goto end;
        }

        strVal = cjson_get_string(item, "address");
        if (strVal)
        {
            strncpy(wan->ipaddr, strVal, sizeof(wan->ipaddr) - 1);
        }
        
        ret = cjson_get_int(item, "mask", &intVal);
        if (ret < 0)
        {
            goto end;
        }

        strncpy(wan->netmask, prefix_to_mask_str(intVal), sizeof(wan->netmask) - 1);
    }

    /* route */
    cJSON *route = NULL;    
    route = cJSON_GetObjectItem(root, "route");
    if (!route || route->type != cJSON_Array)
    {
        return -1;      
    }

    count = 0;
    item = route->child;
    while (item)
    {
        if (item->type != cJSON_Object)
        {
            continue;
        }
        
        ret = cjson_get_int(item, "mask", &intVal);
        if (ret < 0)
        {
            continue;
        }

        /* mask == 0  */
        if (intVal == 0)
        {
            strVal = cjson_get_string(item, "nexthop");
            if (strVal)
            {
                strncpy(wan->gateway, strVal, sizeof(wan->gateway) - 1);
            }
        }
        item = item->next;
    }

    /* dns */
    cJSON *dns = NULL;
    dns = cJSON_GetObjectItem(root, "dns-server");
    if (!dns || dns->type != cJSON_Array)
    {
        ret = -1;
        goto end;
    }

    count = 1;
    item = dns->child;
    while (item)
    {
        if (item->type != cJSON_String)
        {
            continue;
        }

        if (count == 1)
        {
            strncpy(wan->dns1, item->valuestring, sizeof(wan->dns1));
        }
        else if (count == 2)
        {
            strncpy(wan->dns1, item->valuestring, sizeof(wan->dns1)); 
        }

        count ++;
        item = item->next;
    }
  
end:
    cJSON_Delete(root);

    return ret;
}

int ubus_call_interface_status(const char *name, char *res, int len)
{
    FILE *fp = NULL;
    size_t rlen = 0;
    char cmd[128] = {0};   

    snprintf(cmd, sizeof(cmd), "ubus call network.interface.%s status -S -t 1", name);
    fp = popen(cmd, "r");
    if (!fp)
    {
        return -1;
    }

    rlen = fread(res, 1, len, fp);

    pclose(fp);

    if (rlen <= 1)
    {
        return -1;
    }
    
    res[rlen] = '\0';    

    return 0;
}

int ubus_get_lan_status(const char *name, struct ubus_lan_status *lan)
{
    int ret = 0;
    char buf[1024] = {0};

    ret = ubus_call_interface_status(name, buf, sizeof(buf));
    if (ret < 0)
    {
        return -1;
    }

    ret = _parse_lan_status(buf, lan);
    if (ret < 0)
    {
        return -1;
    }
    
    return ret;
}

int ubus_get_wan_status(const char *name, struct ubus_lan_status *wan)
{
    int ret = 0;
    char buf[1024] = {0};

    ret = ubus_call_interface_status(name, buf, sizeof(buf));
    if (ret < 0)
    {
        return -1;
    }

    ret = _parse_wan_status(buf, wan);
    if (ret < 0)
    {
        return -1;
    }
    
    return ret;
}