
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "webcgi.h"
#include "vlan.h"

#define SWITCH_VLAN_API

int get_vlan_entry(cgi_request_t *req, cgi_response_t *resp)
{
    int i = 0;
    int ret = 0;
    char ports[128];

#if 0
    /* 获取配置 */
    ret = libgw_get_switch_vlan();
    if (ret < 0)
    {
        cgi_errno = CGI_ERR_CFG_FILE;
        goto out;
    }
#endif

    webs_json_header(req->out);
    
    webs_write(req->out, "{\"code\":%d,\"data\":{", cgi_errno);
    //webs_write(req->out, "\"num\":%d", sw.vlan_entry);
    webs_write(req->out, ",\"entry\":[");

#if 0
    list_for_each_entry()
    for (i = 0; i < sw.vlan_entry; i ++) {
        webs_write(req->out, "%s\"id\":%d", i > 0 ? "," : "", i + 1);        
        webs_write(req->out, "\"%s\":\"%s\"", i > 0 ? "," : "", i + 1);
        pbmp_to_ports(i, ports, sizeof(ports));
    }
#endif

    webs_write(req->out, "]}}");
    return 0;
}

int vlan_entry_add(cJSON *params)
{
    return 0;
}

int vlan_entry_edit(cJSON *params)
{
    return 0;
}

int vlan_entry_del(cJSON *params)
{
    return 0;
}

void vlan_entry_commit()
{

}

int vlan_entry_config(cgi_request_t *req, cgi_response_t *resp)
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
        case CGI_ADD:
            ret = vlan_entry_add(params);
            break;
        case CGI_SET:
            ret = vlan_entry_edit(params);
            break;
        case CGI_DEL:
            ret = vlan_entry_del(params);
            break;
        default:
            cgi_errno = CGI_ERR_NOT_FOUND;
            break;
    }

    vlan_entry_commit();

    /* 重新初始化VLAN配置 */
    
out:
    param_free();
    
    webs_json_header(req->out);
    webs_write(req->out, "{\"code\":%d,\"data\":{}}", cgi_errno);       

    return 0;
}

#define SWITCH_PORT_API

int port_vlan_list(cgi_request_t *req, cgi_response_t *resp)
{
    int i = 0;
    int ret = 0;
    char ports[128];

#if 0
    /* 获取配置 */
    ret = libgw_get_switch_port();
    if (ret < 0)
    {
        cgi_errno = CGI_ERR_CFG_FILE;
        goto out;
    }

    webs_json_header(req->out);

    webs_write(req->out, "{\"code\":%d,\"data\":{", cgi_errno);
//    webs_write(req->out, "\"num\":%d", sw.vlan_entry);
    webs_write(req->out, ",\"entry\":[");

    /* 遍历   switch port vlan 配置 */

    list_for_each_entry()
    for (i = 0; i < sw.vlan_entry; i ++) {
        webs_write(req->out, "%s\"id\":%d", i > 0 ? "," : "", i + 1);        
        webs_write(req->out, "\"%s\":\"%s\"", i > 0 ? "," : "", i + 1);
        pbmp_to_ports(i, ports, sizeof(ports));
    }
#endif

    webs_write(req->out, "]}}");

out:

    return 0;
}

int port_vlan_edit(cJSON *params)
{
    return 0;
}

void port_vlan_commit()
{
}

int port_vlan_config(cgi_request_t *req, cgi_response_t *resp)
{
    int ret = 0;
    int method = 0;
    cJSON *params = NULL;
    char *strVal = NULL;
    
    ret = param_init(req->post_data, &method, &params);
    if (ret < 0)
    {
        cgi_errno = CGI_ERR_PARAM;
        goto out;
    }

    ret = port_vlan_edit(params);
    if (ret < 0)
    {
        
    }

    port_vlan_commit();

    /* 重新初始化VLAN配置 */
out:    
    param_free();

    webs_json_header(req->out);
    webs_write(req->out, "{\"code\":%d,\"data\":{}}", cgi_errno);    

    return 0;
}
