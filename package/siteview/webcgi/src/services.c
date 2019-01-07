
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "utils.h"
#include "servlet.h"
#include "services.h"

const char *ddns_services[_DDNS_MAX] = {
    "(BUG)",
    "www.no-ip.com",
    "www.DynDNS.org",
};

int libgw_get_ddns_cfg(ddns_cfg_t *cfg)
{
    return 0;
}

int libgw_set_ddns_cfg(ddns_cfg_t *cfg)
{
    return 0;
}

int libgw_get_upnp_cfg(upnp_cfg_t *cfg)
{
    return 0;
}

int libgw_set_upnp_cfg(upnp_cfg_t *cfg)
{
    return 0;
}

int parse_json_ddns_cfg(cJSON *param, ddns_cfg_t *cfg)
{
    return 0;
}

int parse_json_upnp_cfg(cJSON *param, upnp_cfg_t *cfg)
{
    return 0;
}

#define DDNS_API

int get_ddns_services(cgi_request_t *req, cgi_response_t *resp)
{
    int i = 0;
    
    webs_json_header(req->out);
    webs_write(req->out, "{\"code\":%d,\"data\":{\"services\":[", cgi_errno);
    for (i = 1; i < _DDNS_MAX; i ++)
    {
        webs_write(req->out, "%s{\"id\":%d,\"service_name\":\"%s\"}", (i > 1 ? "," : ""), 
                i, ddns_services[i]);        
    }
    webs_write(req->out, "]}}");

    return 0;
}

int get_ddns_config(cgi_request_t *req, cgi_response_t *resp)
{
    int ret = 0;
    ddns_cfg_t cfg;
   
    memset(&cfg, 0x0, sizeof(ddns_cfg_t));

    ret = libgw_get_ddns_cfg(&cfg);
    if (ret < 0)
    {    
        cgi_errno = CGI_ERR_CFG_PARAM;
        goto out;
    }

    webs_json_header(req->out);
    webs_write(req->out, "{\"code\":%d,\"data\":{", cgi_errno);
    webs_write(req->out, "{\"enabled\":%d,\"service\":\"%s\",\"updatetime\":%d,"
            "\"domainname\":\"%s\",\"username\":\"%s\",\"password\":\"%s\"}",
            cfg.enabled, cfg.service, cfg.updatetime, cfg.host, cfg.username, cfg.password);
    webs_write(req->out, "}}");
    
out:

    if (cgi_errno != CGI_ERR_OK)
    {
        webs_json_header(req->out);
        webs_write(req->out, "{\"code\":%d,\"data\":{}}", cgi_errno);
    }
    
    return ret;
}

int set_ddns_config(cgi_request_t *req, cgi_response_t *resp)
{
    int ret = 0;
    int method = 0;
    cJSON *params = NULL;
    char *strVal = NULL;
    ddns_cfg_t cfg;
    
    ret = param_init(req->post_data, &method, &params);
    if (ret < 0)
    {
        cgi_errno = CGI_ERR_PARAM;
        goto out;
    }

    memset(&cfg, 0x0, sizeof(ddns_cfg_t));
    
    ret = parse_json_ddns_cfg(params, &cfg);
    if (ret < 0)
    {
        cgi_errno = CGI_ERR_CFG_PARAM;
        goto out;
    }
    
    ret = libgw_set_ddns_cfg(&cfg);
    if (ret < 0)
    {
        cgi_errno = CGI_ERR_CFG_FILE;
        goto out;
    }

    fork_exec(1, "/etc/init.d/ddns restart");
    
out:
    param_free();

    webs_json_header(req->out);
    webs_write(req->out, "{\"code\":%d,\"data\":{}}", cgi_errno);
    
    return ret;
}

#define UPNPD_API

int get_upnpd_rules(cgi_request_t *req, cgi_response_t *resp)
{
#if 0
    int ret = -1, i = 0, arr_size = 0;
    cJSON *pRoot = NULL, *arr = NULL; 
    char cmdbuf[128] = {0};

    pRoot = cJSON_Parse(data);
    if(NULL == pRoot)
    {
        cgi_errno = CGI_ERR_PARAM;
        goto cleanup;
    }

    arr = cJSON_GetObjectItem(pRoot, "nums");
    if(NULL == arr)
    {
        cgi_errno = CGI_ERR_CFG_PARAM;
        goto cleanup;
    }

    arr_size = cJSON_GetArraySize(arr);
    for(i = 0; i < arr_size; i ++)
    { 
        cJSON *pSub = cJSON_GetArrayItem(arr, i);
        if(NULL != pSub)
        {
            snprintf(cmdbuf, sizeof(cmdbuf), "iptables -t nat -D MINIUPNPD %d", pSub->valueint - i);
            system(cmdbuf);
            snprintf(cmdbuf, sizeof(cmdbuf), "iptables -t filter -D MINIUPNPD %d", pSub->valueint - i);
            system(cmdbuf);
        }
    }
    
cleanup:
    if(0 == cgi_errno)
    {
        ret = 0;
    }
    
    webs_write(stdout, "{\"code\":%d,\"data\":{}}", cgi_errno);
    if(pRoot) cJSON_Delete(pRoot);
#endif

    return 0;
}

int del_upnpd_rules(cgi_request_t *req, cgi_response_t *resp)
{
#if 0
    int i = 0, num = 0, ret = -1;
    char *outData = NULL;
    cJSON *pRoot = NULL, *item = NULL, *arr = NULL; 
    struct upnpd_rules upnp[MAX_UPNP_RULES_NUM];

    pRoot = cJSON_CreateObject();
    arr = cJSON_CreateArray();
    if(NULL == pRoot || NULL == arr)
    {
        cgi_errno = 222;
        goto cleanup;
    }

    for(i = 0; i < MAX_UPNP_RULES_NUM; i++)
    {
        memset(&upnp[i], 0x0, sizeof(struct upnpd_rules));
    }
    
    num = read_upnpd_rules(upnp);

    for(i = 0; i < num; i++)
    {
        item = cJSON_CreateObject();
        if(NULL == item)
        {
            cgi_errno = 222;
            cgi_log_error("create object failed!\n");
            goto cleanup;
        }
        cJSON_AddNumberToObject(item, "num", upnp[i].num);
        cJSON_AddNumberToObject(item, "internalPort", upnp[i].inport);
        cJSON_AddNumberToObject(item, "externalPort", upnp[i].outport);
        cJSON_AddStringToObject(item, "protocol", upnp[i].protocol);
        //cJSON_AddStringToObject(item, "interface", upnp[i].interface);
        cJSON_AddStringToObject(item, "internalClient", upnp[i].ipaddr);

        cJSON_AddItemToArray(arr, item);
    }
    cJSON_AddNumberToObject(pRoot, "code", cgi_errno);
    cJSON_AddItemToObject(pRoot, "data", arr);

    outData = cJSON_PrintUnformatted(pRoot);
    if(NULL == outData)
    {
        cgi_errno = 101;
        cgi_log_error("unformat data failed!\n");
        goto cleanup;
    }
    
cleanup:

    if(0 == cgi_errno)
    {
        ret = 0;
        webs_write(stdout, "%s", outData);
    }
    else
    {
        webs_write(stdout, "{\"code\":%d,\"data\":{}}", cgi_errno);
    }
    
    if(outData) free(outData);
    if(pRoot) cJSON_Delete(pRoot);
#endif
    return 0;
}

int get_upnpd_config(cgi_request_t *req, cgi_response_t *resp)
{
    int ret = 0;
    upnp_cfg_t cfg;
   
    memset(&cfg, 0x0, sizeof(upnp_cfg_t));

    ret = libgw_get_upnp_cfg(&cfg);
    if (ret < 0)
    {    
        cgi_errno = CGI_ERR_CFG_PARAM;
        goto out;
    }

    webs_json_header(req->out);
    webs_write(req->out, "{\"code\":%d,\"data\":{", cgi_errno);
    webs_write(req->out, "\"enabled\":%d,\"interval\":%d,\"time_to_live\":%d",
            cfg.enabled, cfg.intval, cfg.ttl);
    webs_write(req->out, "}}");
    
out:

    if (cgi_errno != CGI_ERR_OK)
    {
        webs_json_header(req->out);
        webs_write(req->out, "{\"code\":%d,\"data\":{}}", cgi_errno);
    }
    
    return ret;
}

int set_upnpd_config(cgi_request_t *req, cgi_response_t *resp)
{
    int ret = 0;
    int method = 0;
    cJSON *params = NULL;
    upnp_cfg_t cfg;
    
    ret = param_init(req->post_data, &method, &params);
    if (ret < 0)
    {
        cgi_errno = CGI_ERR_PARAM;
        goto out;
    }

    memset(&cfg, 0x0, sizeof(upnp_cfg_t));
    
    ret = parse_json_upnp_cfg(params, &cfg);
    if (ret < 0)
    {
        cgi_errno = CGI_ERR_CFG_PARAM;
        goto out;
    }
    
    ret = libgw_set_upnp_cfg(&cfg);
    if (ret < 0)
    {
        cgi_errno = CGI_ERR_CFG_FILE;
        goto out;
    }

    fork_exec(1, "/etc/init.d/miniupnpd restart");
    
out:
    param_free();

    webs_json_header(req->out);
    webs_write(req->out, "{\"code\":%d,\"data\":{}}", cgi_errno);
    
    return ret;
}
