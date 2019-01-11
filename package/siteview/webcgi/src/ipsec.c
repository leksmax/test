
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "webcgi.h"
#include "ipsec.h"

struct ipsec_state ipsec_st;

struct json_ipsec {
    int id;
    int enabled;
    char *name;
    char *mode;
    char *local_subnet;
    char *local_netmask;
    char *remote_host;
    char *remote_subnet;
    char *remote_netmask;
    char *psk;
    char *ike_proposal_1;
    char *ike_proposal_2;
    char *ike_proposal_3;
    char *ike_proposal_4;
    char *exchange_mode;
    char *negotiate_mode;
    int ikelifetime;
    int dpd_enable;
    int dpd_interval;
    char *protocol;
    char *encap_mode;
    char *ph2_proposal_1;
    char *ph2_proposal_2;
    char *ph2_proposal_3;    
    char *ph2_proposal_4;
    char *pfs;
    int salifetime;
};

/* json接口参数 */
const struct json_val json_ipsec_vals[] = {
    JSON_VAL("id", int, ipsec, id),
    JSON_VAL("enabled", int, ipsec, enabled),
    JSON_VAL("name", string, ipsec, name),
    JSON_VAL("mode", string, ipsec, mode),
    JSON_VAL("local_subnet", string, ipsec, local_subnet),
    JSON_VAL("local_netmask", string, ipsec, local_netmask),
    JSON_VAL("remote_host", string, ipsec, remote_host),
    JSON_VAL("remote_subnet", string, ipsec, remote_subnet),
    JSON_VAL("remote_netmask", string, ipsec, remote_netmask),
    JSON_VAL("psk", string, ipsec, psk),
    
    JSON_VAL("ike_proposal_1", string, ipsec, ike_proposal_1),
    JSON_VAL("ike_proposal_2", string, ipsec, ike_proposal_2),
    JSON_VAL("ike_proposal_3", string, ipsec, ike_proposal_3),
    JSON_VAL("ike_proposal_4", string, ipsec, ike_proposal_4),
    JSON_VAL("exchange_mode", string, ipsec, exchange_mode),
    JSON_VAL("negotiate_mode", string, ipsec, negotiate_mode),
    JSON_VAL("ikelifetime", int, ipsec, ikelifetime),
    JSON_VAL("dpd_enable", int, ipsec, dpd_enable),
    JSON_VAL("dpd_interval", int, ipsec, dpd_interval),
    
    JSON_VAL("protocol", string, ipsec, protocol),
    JSON_VAL("encap_mode", string, ipsec, encap_mode),
    JSON_VAL("ph2_proposal_1", string, ipsec, ph2_proposal_1),
    JSON_VAL("ph2_proposal_2", string, ipsec, ph2_proposal_2),
    JSON_VAL("ph2_proposal_3", string, ipsec, ph2_proposal_3),
    JSON_VAL("ph2_proposal_4", string, ipsec, ph2_proposal_4),
    JSON_VAL("pfs", string, ipsec, pfs),
    JSON_VAL("salifetime", int, ipsec, salifetime),
    {  }
};

int ipsec_config_init()
{
    int ret = 0;
    struct uci_context *ctx;
    struct uci_package *pkg = NULL;
    struct uci_element *e;
    ipsec_rule_t *ipsec;
    
    ipsec_st.ipsec_nums = 0;
    INIT_LIST_HEAD(&ipsec_st.ipsec_rules);
  
    ctx = uci_alloc_context();
    if (!ctx)
    {
        return -1;
    }

    uci_load(ctx, "ipsec", &pkg);
    if (!pkg) 
    {
        ret = -1;
        goto out;
    }
    
    uci_foreach_element(&pkg->sections, e)
    {  
        struct uci_element *n;
        struct uci_section *s = uci_to_section(e);

        if (!strcmp(s->type, "rule"))
        {
            ipsec = (ipsec_rule_t *)malloc(sizeof(ipsec_rule_t));
            if (!ipsec)
            {
                continue;
            }
            
            memset(ipsec, 0x0, sizeof(ipsec_rule_t));
            
            uci_foreach_element(&s->options, n) 
            {
                struct uci_option *o = uci_to_option(n);

                if (o->type != UCI_TYPE_STRING)
                {
                    continue;
                }
                if (!strcmp(o->e.name, "enabled"))
                {
                    ipsec->enabled = atoi(o->v.string);
                }
                else if (!strcmp(o->e.name, "name"))
                {
                    strncpy(ipsec->name, o->v.string, sizeof(ipsec->name) - 1);
                }
                else if (!strcmp(o->e.name, "mode"))
                {
                    strncpy(ipsec->mode, o->v.string, sizeof(ipsec->mode) - 1);
                }
                else if (!strcmp(o->e.name, "local_subnet"))
                {
                    strncpy(ipsec->local_subnet, o->v.string, sizeof(ipsec->local_subnet) - 1);
                }
                else if (!strcmp(o->e.name, "local_netmask"))
                {
                    strncpy(ipsec->local_netmask, o->v.string, sizeof(ipsec->local_netmask) - 1);
                }
                else if (!strcmp(o->e.name, "remote_host"))
                {
                    strncpy(ipsec->remote_host, o->v.string, sizeof(ipsec->remote_host) - 1);
                }
                else if (!strcmp(o->e.name, "remote_subnet"))
                {
                    strncpy(ipsec->remote_subnet, o->v.string, sizeof(ipsec->remote_subnet) - 1);
                }
                else if (!strcmp(o->e.name, "remote_netmask"))
                {
                    strncpy(ipsec->remote_netmask, o->v.string, sizeof(ipsec->remote_netmask) - 1);
                }
                else if (!strcmp(o->e.name, "psk"))
                {
                    strncpy(ipsec->psk, o->v.string, sizeof(ipsec->psk) - 1);
                }
                else if (!strcmp(o->e.name, "ike_proposal_1"))
                {
                    strncpy(ipsec->ike_proposal_1, o->v.string, sizeof(ipsec->ike_proposal_1) - 1);
                }
                else if (!strcmp(o->e.name, "ike_proposal_2"))
                {
                    strncpy(ipsec->ike_proposal_2, o->v.string, sizeof(ipsec->ike_proposal_2) - 1);
                }
                else if (!strcmp(o->e.name, "ike_proposal_3"))
                {
                    strncpy(ipsec->ike_proposal_3, o->v.string, sizeof(ipsec->ike_proposal_3) - 1);
                }
                else if (!strcmp(o->e.name, "ike_proposal_4"))
                {
                    strncpy(ipsec->ike_proposal_4, o->v.string, sizeof(ipsec->ike_proposal_4) - 1);
                }
                else if (!strcmp(o->e.name, "exchange_mode"))
                {
                    strncpy(ipsec->exchange_mode, o->v.string, sizeof(ipsec->exchange_mode) - 1);
                }
                else if (!strcmp(o->e.name, "negotiate_mode"))
                {
                    strncpy(ipsec->negotiate_mode, o->v.string, sizeof(ipsec->negotiate_mode) - 1);
                }
                else if (!strcmp(o->e.name, "ikelifetime"))
                {
                    ipsec->ikelifetime = atoi(o->v.string);
                }
                else if (!strcmp(o->e.name, "dpd_enable"))
                {
                    ipsec->dpd_enable = atoi(o->v.string);
                }
                else if (!strcmp(o->e.name, "dpd_interval"))
                {
                    ipsec->dpd_interval = atoi(o->v.string);
                }
                else if (!strcmp(o->e.name, "protocol"))
                {
                    strncpy(ipsec->protocol, o->v.string, sizeof(ipsec->protocol) - 1);
                }
                else if (!strcmp(o->e.name, "encap_mode"))
                {
                    strncpy(ipsec->encap_mode, o->v.string, sizeof(ipsec->encap_mode) - 1);
                }
                else if (!strcmp(o->e.name, "ph2_proposal_1"))
                {
                    strncpy(ipsec->ph2_proposal_1, o->v.string, sizeof(ipsec->ph2_proposal_1) - 1);
                }
                else if (!strcmp(o->e.name, "ph2_proposal_2"))
                {
                    strncpy(ipsec->ph2_proposal_2, o->v.string, sizeof(ipsec->ph2_proposal_2) - 1);
                }
                else if (!strcmp(o->e.name, "ph2_proposal_3"))
                {
                    strncpy(ipsec->ph2_proposal_3, o->v.string, sizeof(ipsec->ph2_proposal_3) - 1);
                }
                else if (!strcmp(o->e.name, "ph2_proposal_4"))
                {
                    strncpy(ipsec->ph2_proposal_4, o->v.string, sizeof(ipsec->ph2_proposal_4) - 1);
                }
                else if (!strcmp(o->e.name, "pfs"))
                {
                    strncpy(ipsec->pfs, o->v.string, sizeof(ipsec->pfs) - 1);
                }
                else if (!strcmp(o->e.name, "salifetime"))
                {
                    ipsec->salifetime = atoi(o->v.string);
                }
            }

            ipsec->id = ipsec_st.ipsec_nums + 1;
            list_add_tail(&ipsec->list, &ipsec_st.ipsec_rules);
            ipsec_st.ipsec_nums += 1;
        }
    } 

    uci_unload(ctx, pkg);
out:
    uci_free_context(ctx);

    return ret;
}

void ipsec_rule_free(ipsec_rule_t *ipsec)
{
    list_del(&ipsec->list);
    free(ipsec);
}

void ipsec_config_free()
{
    ipsec_rule_t *ipsec, *tmp;
    
    list_for_each_entry_safe(ipsec, tmp, &ipsec_st.ipsec_rules, list)
    {
        ipsec_rule_free(ipsec);
    }
    ipsec_st.ipsec_nums = 0;
}

void _uci_ipsec_add_rule(FILE *fp, ipsec_rule_t *ipsec)
{
    fprintf(fp, "config rule\n");
    fprintf(fp, "\toption enabled '%d'\n", ipsec->enabled);
    fprintf(fp, "\toption name '%s'\n", ipsec->name);
    fprintf(fp, "\toption mode '%s'\n", ipsec->mode);
    fprintf(fp, "\toption local_subnet '%s'\n", ipsec->local_subnet);
    fprintf(fp, "\toption local_netmask '%s'\n", ipsec->local_netmask);
    fprintf(fp, "\toption remote_host '%s'\n", ipsec->remote_host);    
    fprintf(fp, "\toption remote_subnet '%s'\n", ipsec->remote_host);
    fprintf(fp, "\toption remote_netmask '%s'\n", ipsec->remote_netmask);
    fprintf(fp, "\toption psk '%s'\n", ipsec->psk);
    
    fprintf(fp, "\toption ike_proposal_1 '%s'\n", ipsec->ike_proposal_1);    
    fprintf(fp, "\toption ike_proposal_2 '%s'\n", ipsec->ike_proposal_2);
    fprintf(fp, "\toption ike_proposal_3 '%s'\n", ipsec->ike_proposal_3);    
    fprintf(fp, "\toption ike_proposal_4 '%s'\n", ipsec->ike_proposal_4);
    fprintf(fp, "\toption exchange_mode '%s'\n", ipsec->exchange_mode);
    fprintf(fp, "\toption negotiate_mode '%s'\n", ipsec->negotiate_mode);
    fprintf(fp, "\toption ikelifetime '%d'\n", ipsec->ikelifetime);
    fprintf(fp, "\toption dpd_enable '%d'\n", ipsec->dpd_enable);
    fprintf(fp, "\toption dpd_interval '%d'\n", ipsec->dpd_interval);

    fprintf(fp, "\toption protocol '%s'\n", ipsec->protocol);    
    fprintf(fp, "\toption encap_mode '%s'\n", ipsec->encap_mode);
    fprintf(fp, "\toption ph2_proposal_1 '%s'\n", ipsec->ph2_proposal_1);    
    fprintf(fp, "\toption ph2_proposal_2 '%s'\n", ipsec->ph2_proposal_2);
    fprintf(fp, "\toption ph2_proposal_3 '%s'\n", ipsec->ph2_proposal_3);
    fprintf(fp, "\toption ph2_proposal_4 '%s'\n", ipsec->ph2_proposal_4);
    fprintf(fp, "\toption pfs '%s'\n", ipsec->pfs);
    fprintf(fp, "\toption salifetime '%d'\n", ipsec->salifetime);

    fprintf(fp, "\n");  
}

void ipsec_config_commit()
{
    FILE *fp = NULL;
    ipsec_rule_t *ipsec = NULL;

    fp = fopen("/etc/config/ipsec", "w");
    if (!fp)
    {
        return;
    }

    list_for_each_entry(ipsec, &ipsec_st.ipsec_rules, list)
    {
        _uci_ipsec_add_rule(fp, ipsec);
    }

    fclose(fp);
}

static int ipsec_policy_add(cJSON *params)
{
    int ret = 0;
    ipsec_rule_t *ipsec;
    struct json_ipsec p;

    json_parse_vals((void *)&p, json_ipsec_vals, params);
    if (ipsec_st.ipsec_nums >= MAX_IPSEC_RULE)
    {
        return CGI_ERR_CFG_OVERMUCH;
    }

    ipsec = (ipsec_rule_t *)malloc(sizeof(ipsec_rule_t));
    if (!ipsec)
    {
        return CGI_ERR_INTERNAL;
    }

	ipsec->enabled = p.enabled;
    strncpy(ipsec->name, p.name, sizeof(ipsec->name) - 1);
    strncpy(ipsec->mode, p.mode, sizeof(ipsec->mode) - 1);
    strncpy(ipsec->local_subnet, p.local_subnet, sizeof(ipsec->local_subnet) - 1);
    strncpy(ipsec->local_netmask, p.local_netmask, sizeof(ipsec->local_netmask) - 1);
    strncpy(ipsec->remote_host, p.remote_host, sizeof(ipsec->remote_host) - 1);
    strncpy(ipsec->remote_subnet, p.remote_subnet, sizeof(ipsec->remote_subnet) - 1);
    strncpy(ipsec->remote_netmask, p.remote_netmask, sizeof(ipsec->remote_netmask) - 1);
    strncpy(ipsec->psk, p.psk, sizeof(ipsec->psk) - 1);
    
    strncpy(ipsec->ike_proposal_1, p.ike_proposal_1, sizeof(ipsec->ike_proposal_1) - 1);
    strncpy(ipsec->ike_proposal_2, p.ike_proposal_2, sizeof(ipsec->ike_proposal_2) - 1);
    strncpy(ipsec->ike_proposal_3, p.ike_proposal_3, sizeof(ipsec->ike_proposal_3) - 1);
    strncpy(ipsec->ike_proposal_4, p.ike_proposal_4, sizeof(ipsec->ike_proposal_4) - 1);
    strncpy(ipsec->exchange_mode, p.exchange_mode, sizeof(ipsec->exchange_mode) - 1);
    strncpy(ipsec->negotiate_mode, p.negotiate_mode, sizeof(ipsec->negotiate_mode) - 1);
    ipsec->ikelifetime = p.ikelifetime;
    ipsec->dpd_enable = p.dpd_enable;
    ipsec->dpd_interval = p.dpd_interval;

    strncpy(ipsec->protocol, p.protocol, sizeof(ipsec->protocol) - 1);
    strncpy(ipsec->encap_mode, p.encap_mode, sizeof(ipsec->encap_mode) - 1);
    strncpy(ipsec->ph2_proposal_1, p.ph2_proposal_1, sizeof(ipsec->ph2_proposal_1) - 1);
    strncpy(ipsec->ph2_proposal_2, p.ph2_proposal_2, sizeof(ipsec->ph2_proposal_2) - 1);
    strncpy(ipsec->ph2_proposal_3, p.ph2_proposal_3, sizeof(ipsec->ph2_proposal_3) - 1);
    strncpy(ipsec->ph2_proposal_4, p.ph2_proposal_4, sizeof(ipsec->ph2_proposal_4) - 1);
    strncpy(ipsec->pfs, p.pfs, sizeof(ipsec->pfs) - 1);
    ipsec->salifetime = p.salifetime;

    list_add_tail(&ipsec->list, &ipsec_st.ipsec_rules);
    ipsec_st.ipsec_nums += 1;
    
    return CGI_ERR_OK;
}

static int ipsec_policy_edit(cJSON *params)
{
    int ret = 0;
    ipsec_rule_t *ipsec;
    struct json_ipsec p;

    json_parse_vals((void *)&p, json_ipsec_vals, params);
    list_for_each_entry(ipsec, &ipsec_st.ipsec_rules, list)
    {
        if (p.id == ipsec->id)
        {
            break;
        }
    }

    if (!ipsec)
    {
        return CGI_ERR_CFG_PARAM;
    }

    /* ipsec有效性检查 */
    //ipsec_rule_check();
    
	ipsec->enabled = p.enabled;
    strncpy(ipsec->name, p.name, sizeof(ipsec->name) - 1);
    strncpy(ipsec->mode, p.mode, sizeof(ipsec->mode) - 1);
    strncpy(ipsec->local_subnet, p.local_subnet, sizeof(ipsec->local_subnet) - 1);
    strncpy(ipsec->local_netmask, p.local_netmask, sizeof(ipsec->local_netmask) - 1);
    strncpy(ipsec->remote_host, p.remote_host, sizeof(ipsec->remote_host) - 1);
    strncpy(ipsec->remote_subnet, p.remote_subnet, sizeof(ipsec->remote_subnet) - 1);
    strncpy(ipsec->remote_netmask, p.remote_netmask, sizeof(ipsec->remote_netmask) - 1);
    strncpy(ipsec->psk, p.psk, sizeof(ipsec->psk) - 1);
    strncpy(ipsec->ike_proposal_1, p.ike_proposal_1, sizeof(ipsec->ike_proposal_1) - 1);
    strncpy(ipsec->ike_proposal_2, p.ike_proposal_2, sizeof(ipsec->ike_proposal_2) - 1);
    strncpy(ipsec->ike_proposal_3, p.ike_proposal_3, sizeof(ipsec->ike_proposal_3) - 1);
    strncpy(ipsec->ike_proposal_4, p.ike_proposal_4, sizeof(ipsec->ike_proposal_4) - 1);
    strncpy(ipsec->exchange_mode, p.exchange_mode, sizeof(ipsec->exchange_mode) - 1);
    strncpy(ipsec->negotiate_mode, p.negotiate_mode, sizeof(ipsec->negotiate_mode) - 1);
    ipsec->ikelifetime = p.ikelifetime;
    ipsec->dpd_enable = p.dpd_enable;
    ipsec->dpd_interval = p.dpd_interval;
    strncpy(ipsec->protocol, p.protocol, sizeof(ipsec->protocol) - 1);
    strncpy(ipsec->encap_mode, p.encap_mode, sizeof(ipsec->encap_mode) - 1);
    strncpy(ipsec->ph2_proposal_1, p.ph2_proposal_1, sizeof(ipsec->ph2_proposal_1) - 1);
    strncpy(ipsec->ph2_proposal_2, p.ph2_proposal_2, sizeof(ipsec->ph2_proposal_2) - 1);
    strncpy(ipsec->ph2_proposal_3, p.ph2_proposal_3, sizeof(ipsec->ph2_proposal_3) - 1);
    strncpy(ipsec->ph2_proposal_4, p.ph2_proposal_4, sizeof(ipsec->ph2_proposal_4) - 1);
    strncpy(ipsec->pfs, p.pfs, sizeof(ipsec->pfs) - 1);
    ipsec->salifetime = p.salifetime;  

    return CGI_ERR_OK;
}

static int ipsec_policy_del(cJSON *params)
{
    int ret = 0;
    cJSON *rules;
    cJSON *jsonVal = NULL;
    int intVal = 0;
    ipsec_rule_t *ipsec, *tmp;

    rules = cJSON_GetObjectItem(params, "rules");
    if (!rules || rules->type != cJSON_Array)
    {
        return CGI_ERR_CFG_PARAM;
    }

    jsonVal = rules->child;
    while (jsonVal)
    {
        ret = cjson_get_int(jsonVal, "id", &intVal);
        if (ret < 0)
        {
            continue;
        }

        list_for_each_entry_safe(ipsec, tmp, &ipsec_st.ipsec_rules, list)
        {
            if (intVal == ipsec->id)
            {
                ipsec_st.ipsec_nums -= 1;
                ipsec_rule_free(ipsec);
            }
        }
    
        jsonVal = jsonVal->next;
    }

    return CGI_ERR_OK;
}

#define IPSEC_API

int get_ipsec_policy(cgi_request_t *req, cgi_response_t *resp)
{
    int ret = 0;
    int i = 0;
    ipsec_rule_t *ipsec = NULL;

    ret = ipsec_config_init();
    if (ret < 0)
    {
        cgi_errno = CGI_ERR_CFG_FILE;
        goto out;
    }

    webs_json_header(req->out);
    webs_write(req->out, "{\"code\":%d,\"data\":{", cgi_errno);
    webs_write(req->out, "\"num\":%d", ipsec_st.ipsec_nums);
    webs_write(req->out, ",\"rules\":[");

    list_for_each_entry(ipsec, &ipsec_st.ipsec_rules, list) 
    {   
        webs_write(req->out, "%s{", ((i > 0) ? "," : ""));
        webs_write(req->out, "\"id\":%d"
            ",\"enabled\":%d"
            ",\"name\":\"%s\""
            ",\"mode\":\"%s\""
            ",\"local_subnet\":\"%s\""
            ",\"local_netmask\":\"%s\""
            ",\"remote_host\":\"%s\""
            ",\"remote_subnet\":\"%s\""
            ",\"remote_netmask\":\"%s\""
            ",\"psk\":\"%s\"",
            ipsec->id,
            ipsec->enabled, 
            ipsec->name, 
            ipsec->mode, 
            ipsec->local_subnet, 
            ipsec->local_netmask, 
            ipsec->remote_host,
            ipsec->remote_subnet,
            ipsec->remote_netmask,
            ipsec->psk
        );
        
        webs_write(req->out, 
            ",\"ike_proposal_1\":\"%s\""
            ",\"ike_proposal_2\":\"%s\""
            ",\"ike_proposal_3\":\"%s\""
            ",\"ike_proposal_4\":\"%s\""
            ",\"exchange_mode\":\"%s\""
            ",\"negotiate_mode\":\"%s\""
            ",\"ikelifetime\":%d"
            ",\"dpd_enable\":%d"
            ",\"dpd_interval\":%d",
            ipsec->ike_proposal_1,
            ipsec->ike_proposal_2,
            ipsec->ike_proposal_3,
            ipsec->ike_proposal_4,
            ipsec->exchange_mode,
            ipsec->negotiate_mode,
            ipsec->ikelifetime,
            ipsec->dpd_enable,
            ipsec->dpd_interval
        );

        webs_write(req->out, 
            ",\"protocol\":\"%s\""
            ",\"encap_mode\":\"%s\""
            ",\"ph2_proposal_1\":\"%s\""
            ",\"ph2_proposal_2\":\"%s\""
            ",\"ph2_proposal_3\":\"%s\""
            ",\"ph2_proposal_4\":\"%s\""
            ",\"pfs\":\"%s\""
            ",\"salifetime\":%d",
            ipsec->protocol,
            ipsec->encap_mode,
            ipsec->ph2_proposal_1,
            ipsec->ph2_proposal_2,
            ipsec->ph2_proposal_3,
            ipsec->ph2_proposal_4,
            ipsec->pfs,
            ipsec->salifetime
        );
        webs_write(req->out, "}");
        i ++;
    }

    webs_write(req->out, "]}}");    

out:
    ipsec_config_free();

    if (cgi_errno != CGI_ERR_OK)
    {
        webs_json_header(req->out);
        webs_write(req->out, "{\"code\":%d,\"data\":{}}", cgi_errno);
    }
    
    return 0;
}

int ipsec_policy_config(cgi_request_t *req, cgi_response_t *resp)
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

    ret = ipsec_config_init();
    if (ret < 0)
    {
        cgi_errno = CGI_ERR_CFG_FILE;
        goto out;
    }

    switch(method)
    {
        case CGI_ADD:
            cgi_errno = ipsec_policy_add(params);
            break;
        case CGI_SET:
            cgi_errno = ipsec_policy_edit(params);
            break;
        case CGI_DEL:
            cgi_errno = ipsec_policy_del(params);
            break;
        default:
            cgi_errno = CGI_ERR_NOT_FOUND;
            break;
    }

    if (cgi_errno == CGI_ERR_OK)
    {
        ipsec_config_commit();
        //fork_exec(1, "/etc/init.d/ipsec restart");
    }
    
out:
    param_free();
    ipsec_config_free();

    webs_json_header(req->out);
    webs_write(req->out, "{\"code\":%d,\"data\":{}}", cgi_errno);
    
    return 0;
}
