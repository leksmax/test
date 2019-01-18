
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "webcgi.h"
#include "services.h"

const char *ddns_services[_DDNS_MAX] = {
    "(BUG)",
    "www.no-ip.com",
    "www.DynDNS.org",
};

struct json_ddns {
    int enabled;
    char *service;
    int updatetime;
    char *domainname;
    char *username;
    char *password;
};

struct json_upnpd {
    int enabled;
    int interval;
    int time_to_live;
};

const struct json_val json_ddns_opts[] = {
    JSON_VAL("enabled", int, ddns, enabled),
    JSON_VAL("service", string, ddns, service),        
    JSON_VAL("updatetime", int, ddns, updatetime),
    JSON_VAL("domainname", string, ddns, domainname),
    JSON_VAL("username", string, ddns, username),
    JSON_VAL("password", string, ddns, password),
    {  }
};

const struct json_val json_upnpd_opts[] = {
    JSON_VAL("enabled", int, upnpd, enabled),
    JSON_VAL("interval", int, upnpd, interval),        
    JSON_VAL("time_to_live", int, upnpd, time_to_live),
    {  }
};


int libgw_get_ddns_cfg(ddns_cfg_t *cfg)
{
    cfg->enabled = config_get_int(DDNS_ENABLED);
    strncpy(cfg->service, config_get(DDNS_SERVICES), sizeof(cfg->service) - 1);
    cfg->updatetime = config_get_int(DDNS_UPDATE_TIME);
    strncpy(cfg->host, config_get(DDNS_DOMAIN_NAME), sizeof(cfg->host) - 1);
    strncpy(cfg->username, config_get(DDNS_USERNAME), sizeof(cfg->username) - 1);
    strncpy(cfg->password, config_get(DDNS_PASSWORD), sizeof(cfg->password) - 1);
    strncpy(cfg->interface, config_get(DDNS_INTERFACE), sizeof(cfg->interface) - 1);
    
    return 0;
}

int libgw_set_ddns_cfg(ddns_cfg_t *cfg)
{
    config_set_int(DDNS_ENABLED, cfg->enabled);
    config_set(DDNS_SERVICES, cfg->service);
    config_set_int(DDNS_UPDATE_TIME, cfg->updatetime);
    config_set(DDNS_DOMAIN_NAME, cfg->host);
    config_set(DDNS_USERNAME, cfg->username);
    config_set(DDNS_PASSWORD, cfg->password);
    //config_set(DDNS_INTERFACE, cfg->interface);
    
    return 0;
}

int libgw_get_upnp_cfg(upnp_cfg_t *cfg)
{
    cfg->enabled = config_get_int(UPNPD_ENABLED);
    cfg->intval = config_get_int(UPNPD_INTERVAL);
    cfg->ttl = config_get_int(UPNPD_TIME_TO_LIVE);

    return 0;
}

int libgw_set_upnp_cfg(upnp_cfg_t *cfg)
{
    config_set_int(UPNPD_ENABLED, cfg->enabled);
    config_set_int(UPNPD_INTERVAL, cfg->intval);
    config_set_int(UPNPD_TIME_TO_LIVE, cfg->ttl);

    return 0;
}

int parse_json_ddns_cfg(cJSON *param, ddns_cfg_t *cfg)
{
    struct json_ddns p;

    memset(&p, 0x0, sizeof(struct json_ddns));
    json_parse_vals((void *)&p, json_ddns_opts, param);

    /* 检查参数, TODO */
    cfg->enabled = p.enabled;
    strncpy(cfg->service, p.service, sizeof(cfg->service) - 1);
    cfg->updatetime = p.updatetime;
    strncpy(cfg->host, p.domainname, sizeof(cfg->host) - 1);
    strncpy(cfg->username, p.username, sizeof(cfg->username) - 1);
    strncpy(cfg->password, p.password, sizeof(cfg->password) - 1);

    return 0;
}

int parse_json_upnp_cfg(cJSON *param, upnp_cfg_t *cfg)
{
    struct json_upnpd p;

    memset(&p, 0x0, sizeof(struct json_upnpd));
    json_parse_vals((void *)&p, json_upnpd_opts, param);

    /* 检查参数, TODO */
    cfg->enabled = p.enabled;
    cfg->intval = p.interval;
    cfg->ttl = p.time_to_live;

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
    webs_write(req->out, "\"enabled\":%d,\"service\":\"%s\",\"updatetime\":%d,"
            "\"domainname\":\"%s\",\"username\":\"%s\",\"password\":\"%s\"",
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

void save_upnp_rules_data()
{
	char cmdbuf[128] = {0};
	if(access(UPNPD_RULE_DATA_SAVE, F_OK) == -1)
	{
		snprintf(cmdbuf, sizeof(cmdbuf), "touch %s;killall -USR2 miniupnpd", UPNPD_RULE_DATA_SAVE);
	}
	else
	{
		snprintf(cmdbuf, sizeof(cmdbuf), "killall -USR2 miniupnpd");
	}
	system(cmdbuf);
}

void delete_upnp_rules_data(char *databuf)
{
	char cmdbuf[2048] = {0};
	if(access(UPNPD_RULE_DATE_DEL, F_OK) == -1)
	{
		snprintf(cmdbuf, sizeof(cmdbuf), "echo -e \"%s\" > %s;killall -USR2 miniupnpd", databuf, UPNPD_RULE_DATE_DEL);
	}
	else
	{
		snprintf(cmdbuf, sizeof(cmdbuf), "killall -USR2 miniupnpd");
	}
	system(cmdbuf);
}

int libgw_get_upnp_rules(upnp_rule_t *upnp)
{
	FILE *fp = NULL;
	int matchs = 0, i = 0;
	int enabled = 0, eport = 0, iport = 0, timestamp = 0;
	char protocol[10] = {0}, ipaddr[16]={0}, desc[64] = {0};
	char line[1024] = {0};
	
	save_upnp_rules_data();

	fp = fopen(UPNPD_RULE_DATA_FILE, "r");
	if(fp != NULL)
	{
		while(fgets(line, sizeof(line), fp))
		{
			matchs = sscanf(line, "%d:%[^:]:%d:%[^:]:%d:%d:%s", &enabled, protocol,
				&eport, ipaddr, &iport, &timestamp, desc);

			if(matchs != 7 || i >= MAX_UPNP_RULES_NUM)
				continue;
			
			upnp[i].status = enabled;
			upnp[i].ext_port = eport;
			upnp[i].in_port = iport;
			
			memcpy(upnp[i].in_ip4addr, ipaddr, sizeof(upnp[i].in_ip4addr));
			strncpy(upnp[i].proto, protocol, sizeof(upnp[i].proto));
			strncpy(upnp[i].name, desc, sizeof(upnp[i].name));

			i++;
		}
		fclose(fp);
	}

	return i;
}

int get_upnpd_rules(cgi_request_t *req, cgi_response_t *resp)
{
	int i = 0, num = 0;

	upnp_rule_t upnp[MAX_UPNP_RULES_NUM];

	for(i = 0; i < MAX_UPNP_RULES_NUM; i++)
	{
		memset(&upnp[i], 0x0, sizeof(upnp_rule_t));
	}
	
	num = libgw_get_upnp_rules(upnp);

    webs_json_header(req->out);
    webs_write(req->out, "{\"code\":%d,\"data\":{\"num\":%d, \"rules\":[", cgi_errno, num);
	for(i = 0; i < num; i++)
	{
		if((i + 1) == num)
			webs_write(req->out, "{\"id\":%d, \"status\":%d, \"internalPort\":%d, \"externalPort\":%d, "
									"\"protocol\":\"%s\", \"internalClient\":\"%s\", \"name\":\"%s\"}",
								i + 1, upnp[i].status, upnp[i].in_port, upnp[i].ext_port, upnp[i].proto,
								upnp[i].in_ip4addr, upnp[i].name);
		else
			webs_write(req->out, "{\"id\":%d, \"status\":%d, \"internalPort\":%d, \"externalPort\":%d, "
								"\"protocol\":\"%s\", \"internalClient\":\"%s\", \"name\":\"%s\"},",
							i + 1, upnp[i].status, upnp[i].in_port, upnp[i].ext_port, upnp[i].proto,
							upnp[i].in_ip4addr, upnp[i].name);
	}

	webs_write(req->out, "]}}");

	return 0;
}

int del_upnpd_rules(cgi_request_t *req, cgi_response_t *resp)
{
	int ret = CGI_ERR_OK, len = 0;
	int method = 0, externalPort = 0;		
	char databuf[1024] = {0};
	char *protocol = NULL;
    cJSON *params = NULL, *rules = NULL, *jsonVal = NULL;
	
	ret = param_init(req->post_data, &method, &params);
	if (ret < 0)
	{
		cgi_errno = CGI_ERR_PARAM;
		goto out;
	}
	
	rules = cJSON_GetObjectItem(params, "rules");
	if(NULL == rules || rules->type != cJSON_Array)
	{
		cgi_errno = CGI_ERR_CFG_PARAM;
		goto out;
	}

	jsonVal = rules->child;

	while(jsonVal && jsonVal->type == cJSON_Object)
	{	
		ret = cjson_get_int(jsonVal, "externalPort", &externalPort);
		if(ret < 0)
		{
			cgi_errno = CGI_ERR_CFG_PARAM;
			goto out;
		}		
		protocol = cjson_get_string(jsonVal, "protocol");
		if(protocol == NULL)
		{
			cgi_errno = CGI_ERR_CFG_PARAM;
			goto out;
		}		
        jsonVal = jsonVal->next;

		if(jsonVal == NULL)
			len += snprintf(databuf+len, sizeof(databuf) - len, "%s %d", protocol, externalPort);
		else
			len += snprintf(databuf+len, sizeof(databuf) - len, "%s %d\n", protocol, externalPort);
	}
	
	if(strlen(databuf) != 0)
		delete_upnp_rules_data(databuf);
	
out:

	param_free();
	
    webs_json_header(req->out);
    webs_write(req->out, "{\"code\":%d,\"data\":{}}", cgi_errno);

	return ret;
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

	if(cfg.enabled == 0)
	{
		unlink(UPNPD_RULE_DATA_FILE);
	}
	
    fork_exec(1, "/etc/init.d/miniupnpd restart");
    
out:
    param_free();

    webs_json_header(req->out);
    webs_write(req->out, "{\"code\":%d,\"data\":{}}", cgi_errno);
    
    return ret;
}
