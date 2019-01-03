
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "webcgi.h"
#include "ipsec.h"
#include "config.h"

struct list_head ipsec_rules;

struct _uci_ipsec {
    int id;
    ipsec_policy_t ipsec;
    struct list_head list;
};

struct json_ipsec {
    int id;
    ipsec_policy_t ipsec;
};

const struct _uci_opt uci_ipsec_opts[] = {
    _UCI_OPT("enabled", int, ipsec, ipsec.enabled),
    _UCI_OPT("name", string, ipsec, ipsec.name),
    _UCI_OPT("mode", string, ipsec, ipsec.mode),
    _UCI_OPT("local_subnet", string, ipsec, ipsec.local_subnet),
    _UCI_OPT("local_netmask", string, ipsec, ipsec.local_netmask),
    _UCI_OPT("remote_host", string, ipsec, ipsec.remote_host),
    _UCI_OPT("remote_subnet", string, ipsec, ipsec.remote_subnet),
    _UCI_OPT("remote_netmask", string, ipsec, ipsec.remote_netmask),
    _UCI_OPT("psk", string, ipsec, psk),
    
    _UCI_OPT("ike_proposal_1", string, ipsec, ipsec.ike_proposal_1),
    _UCI_OPT("ike_proposal_2", string, ipsec, ipsec.ike_proposal_2),
    _UCI_OPT("ike_proposal_3", string, ipsec, ipsec.ike_proposal_3),
    _UCI_OPT("ike_proposal_4", string, ipsec, ipsec.ike_proposal_4),
    _UCI_OPT("exchange_mode", string, ipsec, ipsec.exchange_mode),
    _UCI_OPT("negotiate_mode", string, ipsec, ipsec.negotiate_mode),
    _UCI_OPT("ikelifetime", int, ipsec, ipsec.ikelifetime),
    _UCI_OPT("dpd_enable", int, ipsec, ipsec.dpd_enable),
    _UCI_OPT("dpd_interval", int, ipsec, ipsec.dpd_interval),
    
    _UCI_OPT("protocol", string, ipsec, ipsec.protocol),
    _UCI_OPT("encap_mode", string, ipsec, ipsec.encap_mode),
    _UCI_OPT("ph2_proposal_1", string, ipsec, ipsec.ph2_proposal_1),
    _UCI_OPT("ph2_proposal_2", string, ipsec, ipsec.ph2_proposal_2),
    _UCI_OPT("ph2_proposal_3", string, ipsec, ipsec.ph2_proposal_3),
    _UCI_OPT("ph2_proposal_4", string, ipsec, ipsec.ph2_proposal_4),
    _UCI_OPT("pfs", string, ipsec, ipsec.pfs),
    _UCI_OPT("salifetime", int, ipsec, ipsec.salifetime),
    {  }
};

/* json接口参数 */
const struct json_val json_ipsec_vals[] = {
    JSON_VAL("id", int, ipsec, id),
    JSON_VAL("enabled", int, ipsec, ipsec.enabled),
    JSON_VAL("name", string, ipsec, ipsec.name),
    JSON_VAL("mode", string, ipsec, ipsec.mode),
    JSON_VAL("local_subnet", string, ipsec, ipsec.local_subnet),
    JSON_VAL("local_netmask", string, ipsec, ipsec.local_netmask),
    JSON_VAL("remote_host", string, ipsec, ipsec.remote_host),
    JSON_VAL("remote_subnet", string, ipsec, ipsec.remote_subnet),
    JSON_VAL("remote_netmask", string, ipsec, ipsec.remote_netmask),
    JSON_VAL("psk", string, ipsec, psk),
    
    JSON_VAL("ike_proposal_1", string, ipsec, ipsec.ike_proposal_1),
    JSON_VAL("ike_proposal_2", string, ipsec, ipsec.ike_proposal_2),
    JSON_VAL("ike_proposal_3", string, ipsec, ipsec.ike_proposal_3),
    JSON_VAL("ike_proposal_4", string, ipsec, ipsec.ike_proposal_4),
    JSON_VAL("exchange_mode", string, ipsec, ipsec.exchange_mode),
    JSON_VAL("negotiate_mode", string, ipsec, ipsec.negotiate_mode),
    JSON_VAL("ikelifetime", int, ipsec, ipsec.ikelifetime),
    JSON_VAL("dpd_enable", int, ipsec, ipsec.dpd_enable),
    JSON_VAL("dpd_interval", int, ipsec, ipsec.dpd_interval),
    
    JSON_VAL("protocol", string, ipsec, ipsec.protocol),
    JSON_VAL("encap_mode", string, ipsec, ipsec.encap_mode),
    JSON_VAL("ph2_proposal_1", string, ipsec, ipsec.ph2_proposal_1),
    JSON_VAL("ph2_proposal_2", string, ipsec, ipsec.ph2_proposal_2),
    JSON_VAL("ph2_proposal_3", string, ipsec, ipsec.ph2_proposal_3),
    JSON_VAL("ph2_proposal_4", string, ipsec, ipsec.ph2_proposal_4),
    JSON_VAL("pfs", string, ipsec, ipsec.pfs),
    JSON_VAL("salifetime", int, ipsec, ipsec.salifetime),
    {  }
};

int ipsec_config_init()
{
    int ret = 0;
    struct uci_context *ctx;
    struct uci_package *pkg = NULL;
    
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

    uci_unload(ctx, pkg);
out:
    uci_free_context(ctx);

    return ret;
}

static int ipsec_config_init()
{
    int i = 0;

    struct uci_element *e;



    INIT_LIST_HEAD(&ipsec_rules);



    uci_foreach_element(&pkg->sections, e)
    {      
        struct _uci_ipsec *uci;
        struct uci_section *s = uci_to_section(e);

        if (!strcmp(s->type, "rule"))
        {
            uci = calloc(1, sizeof(struct _uci_ipsec));
            if (!uci)
                continue;

            memset(uci, 0x0, sizeof(struct _uci_ipsec));
            
            uci->id = i + 1;
            
            _uci_parse_options(uci, uci_ipsec_opts, s);
            
        }

        list_add_tail(&uci->list, &ipsec_rules);
        
        i ++;
    }
    uci_unload(ctx, pkg);
out:
    
    uci_free_context(ctx);
}

static int ipsec_policy_add(cJSON *params)
{
    int ret = 0;
    ipsec_policy_t *ipsec;
    struct json_ipsec json;

    ret = json_parse_vals((void *)&json, json_ipsec_vals, params);
    if (!ret)
    {
        return CGI_ERR_PARAM;
    }

    ipsec = &json.ipsec;

    
    
    return CGI_ERR_OK;
}

static int ipsec_policy_edit(cJSON *params)
{
    int ret = 0;
    ipsec_policy_t *ipsec;
    struct json_ipsec json;

    ret = json_parse_vals((void *)&json, json_ipsec_vals, params);
    if (!ret)
    {
        return CGI_ERR_PARAM;
    }

    ipsec = &json->ipsec;

    return CGI_ERR_OK;
}

static int ipsec_policy_del(cJSON *params)
{
    return CGI_ERR_OK;
}

#define IPSEC_API

int get_ipsec_policy(cgi_request_t *req, cgi_response_t *resp)
{
    int ret = 0;
    struct _uci_ipsec *uci;
    ipsec_policy_t *ipsec = NULL;

    ret = ipsec_config_init();
    if (ret < 0)
    {
        cgi_errno = CGI_ERR_CFG_FILE;
        goto out;
    }

    webs_json_header(req->out);
    webs_write(req->out, "{\"code\":%d,\"data\":{", cgi_errno);
    //webs_write(req->out, "\"num\":%d,", ipsec_rule_num);
    webs_write(req->out, "\"rules\":[");

    list_for_each_entry(uci, &ipsec_rules, list) 
    {
        ipsec = &uci->ipsec;
        
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
            uci->id,
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
    }

    webs_write(req->out, "]}}");    

out:
    //ipsec_config_free();

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

out:
    param_free();
    
    //ipsec_config_free();

    webs_json_header(req->out);
    webs_write(req->out, "{\"code\":%d,\"data\":{}}", cgi_errno);
    
    return 0;
}
