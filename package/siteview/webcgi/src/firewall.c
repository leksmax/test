
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "webcgi.h"
#include "firewall.h"

struct fw_state fw;

int firewall_config_init()
{
    int i = 0;
    struct uci_context *ctx;
    struct uci_package *pkg = NULL;
    struct uci_element *e;
    pf_rule_t *pf = NULL;
    pt_rule_t *pt = NULL;

    fw.pf_num = 0;
    INIT_LIST_HEAD(&fw.pf_rules);
    
    fw.pt_num = 0;
    INIT_LIST_HEAD(&fw.pt_rules);

    ctx = uci_alloc_context();
    if (!ctx)
    {
        return -1;
    }

    uci_load(ctx, "firewall_ext", &pkg);
    if (!pkg) 
    {
        goto out;
    }
    
    uci_foreach_element(&pkg->sections, e)
    {  
        struct uci_element *n;
        struct uci_section *s = uci_to_section(e);

        if (!strcmp(s->type, "forward"))
        {
            pf = (pf_rule_t *)malloc(sizeof(pf_rule_t));
            if (!pf)
            {
                continue;
            }
            
            memset(pf, 0x0, sizeof(pf_rule_t));
            
            uci_foreach_element(&s->options, n) 
            {
                struct uci_option *o = uci_to_option(n);
                
                if (o->type != UCI_TYPE_STRING)
                {
                    continue;
                }
                
                if (!strcmp(o->e.name, "name"))
                {
                    strncpy(pf->name, o->v.string, sizeof(pf->name) - 1);
                }
                else if (!strcmp(o->e.name, "interface"))
                {
                    strncpy(pf->interface, o->v.string, sizeof(pf->interface) - 1);
                }
                else if (!strcmp(o->e.name, "internal_port"))
                {
                    strncpy(pf->int_port, o->v.string, sizeof(pf->int_port) - 1);
                }
                else if (!strcmp(o->e.name, "internal_ip"))
                {
                    strncpy(pf->int_ip, o->v.string, sizeof(pf->int_ip) - 1);
                }
                else if (!strcmp(o->e.name, "external_port"))
                {
                    strncpy(pf->ext_port, o->v.string, sizeof(pf->ext_port) - 1);
                }
                else if (!strcmp(o->e.name, "protocol"))
                {
                     strncpy(pf->proto, o->v.string, sizeof(pf->proto) - 1);
                }
            }

            pf->id ++;
            list_add_tail(&pf->list, &fw.pf_rules);
            fw.pf_num ++;
        }
        else if (!strcmp(s->type, "trigger"))
        {
            pt = (pt_rule_t *)malloc(sizeof(pt_rule_t));
            if (!pt)
            {
                continue;
            }
            
            memset(pt, 0x0, sizeof(pt_rule_t));
            
            uci_foreach_element(&s->options, n) 
            {
                struct uci_option *o = uci_to_option(n);
                
                if (o->type != UCI_TYPE_STRING)
                {
                    continue;
                }
                
                if (!strcmp(o->e.name, "name"))
                {
                    strncpy(pt->name, o->v.string, sizeof(pt->name) - 1);
                }
                else if (!strcmp(o->e.name, "interface"))
                {
                    strncpy(pt->interface, o->v.string, sizeof(pt->interface) - 1);
                }
                else if (!strcmp(o->e.name, "trigger_port"))
                {
                    strncpy(pt->trig_port, o->v.string, sizeof(pt->trig_port) - 1);
                }
                else if (!strcmp(o->e.name, "trigger_proto"))
                {
                    strncpy(pt->trig_proto, o->v.string, sizeof(pt->trig_proto) - 1);
                }
                else if (!strcmp(o->e.name, "external_port"))
                {
                    strncpy(pt->ext_port, o->v.string, sizeof(pt->ext_port) - 1);
                }
                else if (!strcmp(o->e.name, "external_proto"))
                {
                     strncpy(pt->ext_proto, o->v.string, sizeof(pt->ext_proto) - 1);
                }
            }
        
            list_add_tail(&pt->list, &fw.pt_rules);
            fw.pt_num ++;            
        }
    } 

    uci_unload(ctx, pkg);
out:
    uci_free_context(ctx);

    return 0;
}

void firewall_config_free()
{
}

void _uci_firewall_add_forward(FILE *fp, pf_rule_t *pf)
{
    fprintf(fp, "config forward\n");
    fprintf(fp, "\toption name '%s'\n", pf->name);
    fprintf(fp, "\toption interface '%s'\n", pf->interface);
    fprintf(fp, "\toption internal_port '%s'\n", pf->int_port);
    fprintf(fp, "\toption internal_ip '%s'\n", pf->int_ip);
    fprintf(fp, "\toption external_port '%s'\n", pf->ext_port);
    fprintf(fp, "\toption protocol '%s'\n", pf->proto);
    fprintf(fp, "\n");
}

void _uci_firewall_add_trigger(FILE *fp, pt_rule_t *pt)
{
    fprintf(fp, "config trigger\n");
    fprintf(fp, "\toption name '%s'\n", pt->name);
    fprintf(fp, "\toption interface '%s'\n", pt->interface);
    fprintf(fp, "\toption trigger_port '%s'\n", pt->trig_port);
    fprintf(fp, "\toption trigger_proto '%s'\n", pt->trig_proto);
    fprintf(fp, "\toption external_port '%s'\n", pt->ext_port);
    fprintf(fp, "\toption external_proto '%s'\n", pt->ext_proto);
    fprintf(fp, "\n");  
}

void firewall_config_commit()
{
    FILE *fp = NULL;
    pf_rule_t *pf = NULL;
    pt_rule_t *pt = NULL;

    fp = fopen("/etc/config/firewall_ext", "w");
    if (!fp)
    {
        return;
    }

    /* 端口转发配置 */
    list_for_each_entry(pf, &fw.pf_rules, list)
    {
        _uci_firewall_add_forward(fp, pf);
    }
    
    /* 端口触发配置 */
    list_for_each_entry(pt, &fw.pt_rules, list)
    {
        _uci_firewall_add_trigger(fp, pt);
    }

    fclose(fp);
}

struct json_pf_rule {
    int id;
    char *name;
    char *interface;
    char *int_port;
    char *int_ip;
    char *ext_port;
    char *proto;
};

struct json_pt_rule {
    int id;
    char *name;
    char *interface;
    char *trig_port;
    char *trig_proto;
    char *ext_port;
    char *ext_proto;
};

const struct json_val json_pf_vals[] = {
    JSON_VAL("id", int, pf_rule, id),
    JSON_VAL("name", string, pf_rule, name),        
    JSON_VAL("interface", string, pf_rule, interface),
    JSON_VAL("internal_port", string, pf_rule, int_port),
    JSON_VAL("internal_ip", string, pf_rule, int_ip),
    JSON_VAL("external_port", string, pf_rule, ext_port),
    JSON_VAL("protocol", string, pf_rule, proto),
    {  }
};

const struct json_val json_pt_vals[] = {
    JSON_VAL("id", int, pt_rule, id),
    JSON_VAL("name", string, pt_rule, name),        
    JSON_VAL("interface", string, pt_rule, interface),
    JSON_VAL("trigger_port", string, pt_rule, trig_port),
    JSON_VAL("trigger_proto", string, pt_rule, trig_proto),
    JSON_VAL("external_port", string, pt_rule, ext_port),
    JSON_VAL("external_proto", string, pt_rule, ext_proto),
    {  }
};

#define PORT_FORWARD_API

int port_forward_list(cgi_request_t *req, cgi_response_t *resp)
{
    int i = 0;
    int ret = 0;
    pf_rule_t *pf = NULL;

    ret = firewall_config_init();
    if (ret < 0)
    {
        cgi_errno = CGI_ERR_CFG_FILE;
        goto out;
    }
    
    webs_json_header(req->out);
    webs_write(req->out, "{\"code\":%d,\"data\":{", cgi_errno);
    webs_write(req->out, "\"num\":%d", fw.pf_num);
    webs_write(req->out, ",\"rule\":[");

    list_for_each_entry(pf, &fw.pf_rules, list) {
        webs_write(req->out, "%s{\"id\":%d,\"name\":\"%s\",\"interface\":\"%s\",\"internal_port\":\"%s\","
            "\"internal_ip\":\"%s\",\"external_port\":\"%s\",\"protocol\":\"%s\"}", (i > 0) ? "," : "", pf->id, pf->name, pf->interface, 
            pf->int_port, pf->int_ip, pf->ext_port, pf->proto);
        i ++;
    }

    webs_write(req->out, "]}}");
            
out:
    firewall_config_free();

    if (cgi_errno != CGI_ERR_OK)
    {
        webs_json_header(req->out);
        webs_write(req->out, "{\"code\":%d,\"data\":{}}", cgi_errno);    
    }
        
    return 0;
}

int port_forward_add(cJSON *params)
{
    int ret = 0;
    pf_rule_t *pf = NULL;
    struct json_pf_rule p;

    if (fw.pf_num >= MAX_PORT_FORWARD)
    {
        return -1;
    }
        
    memset(&p, 0x0, sizeof(struct json_pf_rule));
    
    json_parse_vals((void *)&p, json_pf_vals, params);

    /*
     * 这里需要对解析出来的数据坐下处理，添加的条目有效性检查
     */
    pf = (pf_rule_t *)malloc(sizeof(pf_rule_t));
    if (!pf)
    {
        return -1;
    }

    pf->id = fw.pf_num;
    strncpy(pf->name, p.name, sizeof(pf->name) - 1);
    strncpy(pf->interface, p.interface, sizeof(pf->interface) - 1);
    strncpy(pf->int_port, p.int_port, sizeof(pf->int_port) - 1);
    strncpy(pf->int_ip, p.int_ip, sizeof(pf->int_ip) - 1);
    strncpy(pf->ext_port, p.ext_port, sizeof(pf->ext_port) - 1);
    strncpy(pf->proto, p.proto, sizeof(pf->proto) - 1);

    list_add_tail(&pf->list, &fw.pf_rules);
    fw.pf_num += 1;

    return ret;
}

int port_forward_edit(cJSON *params)
{
    int ret = 0;
    pf_rule_t *pf = NULL;
    struct json_pf_rule p;

    memset(&p, 0x0, sizeof(struct json_pf_rule));    
    json_parse_vals((void *)&p, json_pf_vals, params);

    list_for_each_entry(pf, &fw.pf_rules, list)
    {
        if (p.id == pf->id)
        {
            break;
        }
    }

    cgi_debug("p.id = %d\n", p.id);

    if (!pf)
    {
        return -1;
    }

    strncpy(pf->name, p.name, sizeof(pf->name) - 1);
    strncpy(pf->interface, p.interface, sizeof(pf->interface) - 1);
    strncpy(pf->int_port, p.int_port, sizeof(pf->int_port) - 1);
    strncpy(pf->int_ip, p.int_ip, sizeof(pf->int_ip) - 1);
    strncpy(pf->ext_port, p.ext_port, sizeof(pf->ext_port) - 1);
    strncpy(pf->proto, p.proto, sizeof(pf->proto) - 1);

    return 0;
}

int port_forward_del(cJSON *params)
{
    return 0;
}

int port_forward_config(cgi_request_t *req, cgi_response_t *resp)
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

    ret = firewall_config_init();
    if (ret < 0)
    {
        cgi_errno = CGI_ERR_CFG_FILE;
        goto out;
    }
    
    switch(method)
    {
        case CGI_ADD:
            ret = port_forward_add(params);
            break;
        case CGI_SET:
            ret = port_forward_edit(params);
            break;
        case CGI_DEL:
            ret = port_forward_del(params);
            break;
        default:
            cgi_errno = CGI_ERR_NOT_FOUND;
            break;
    }

    //if (ret)
    {
        firewall_config_commit();
       //fork_exec(1, "/etc/init.d/firewall restart");
    }
    
out:
    param_free();
    firewall_config_free();

    webs_json_header(req->out);
    webs_write(req->out, "{\"code\":%d,\"data\":{}}", cgi_errno);

    return 0;
}


#define PORT_TRIGGER_API

int port_trigger_list(cgi_request_t *req, cgi_response_t *resp)
{
    int i = 0;
    int ret = 0;
    pt_rule_t *pt = NULL;

    ret = firewall_config_init();
    if (ret < 0)
    {
        cgi_errno = CGI_ERR_CFG_FILE;
        goto out;
    }
    
    webs_json_header(req->out);
    webs_write(req->out, "{\"code\":%d,\"data\":{", cgi_errno);
    webs_write(req->out, "\"num\":%d", fw.pt_num);
    webs_write(req->out, ",\"rule\":[");

    list_for_each_entry(pt, &fw.pt_rules, list) {
        webs_write(req->out, "%s{\"id\":%d,\"name\":\"%s\",\"interface\":\"%s\",\"trigger_port\":\"%s\","
            "\"trigger_proto\":\"%s\",\"external_port\":\"%s\",\"external_proto\":\"%s\"}", (i > 0) ? "," : "", pt->id, pt->name, pt->interface, 
            pt->trig_port, pt->trig_proto, pt->ext_port, pt->ext_proto);
        i ++;
    }

    webs_write(req->out, "]}}");
            
out:
    if (cgi_errno != CGI_ERR_OK)
    {
        webs_json_header(req->out);
        webs_write(req->out, "{\"code\":%d,\"data\":{}}", cgi_errno);    
    }
    
    firewall_config_free();
    
    return 0;
}

int port_trigger_add(cJSON *params)
{
    int ret = 0;
    pt_rule_t *pt = NULL;
    struct json_pt_rule p;

    if (fw.pf_num >= MAX_PORT_TRIGGER)
    {
        return -1;
    }
        
    memset(&p, 0x0, sizeof(struct json_pt_rule));
    json_parse_vals((void *)&p, json_pt_vals, params);

    /*
     * 这里需要对解析出来的数据坐下处理，添加的条目有效性检查
     */
    pt = (pt_rule_t *)malloc(sizeof(pt_rule_t));
    if (!pt)
    {
        return -1;
    }

    pt->id = fw.pt_num;
    strncpy(pt->name, p.name, sizeof(pt->name) - 1);
    strncpy(pt->interface, p.interface, sizeof(pt->interface) - 1);
    strncpy(pt->trig_port, p.trig_port, sizeof(pt->trig_port) - 1);
    strncpy(pt->trig_proto, p.trig_proto, sizeof(pt->trig_proto) - 1);
    strncpy(pt->ext_port, p.ext_port, sizeof(pt->ext_port) - 1);
    strncpy(pt->ext_proto, p.ext_proto, sizeof(pt->ext_proto) - 1);

    list_add_tail(&pt->list, &fw.pt_rules);
    fw.pt_num += 1;

    return ret;
}

int port_trigger_edit(cJSON *params)
{
    int ret = 0;
    pt_rule_t *pt = NULL;
    struct json_pt_rule p;

    memset(&p, 0x0, sizeof(struct json_pt_rule));    
    json_parse_vals((void *)&p, json_pt_vals, params);

    list_for_each_entry(pt, &fw.pt_rules, list)
    {
        if (p.id == pt->id)
        {
            break;
        }
    }

    if (!pt)
    {
        return -1;
    }

    strncpy(pt->name, p.name, sizeof(pt->name) - 1);
    strncpy(pt->interface, p.interface, sizeof(pt->interface) - 1);
    strncpy(pt->trig_port, p.trig_port, sizeof(pt->trig_port) - 1);
    strncpy(pt->trig_proto, p.trig_proto, sizeof(pt->trig_proto) - 1);
    strncpy(pt->ext_port, p.ext_port, sizeof(pt->ext_port) - 1);
    strncpy(pt->ext_proto, p.ext_proto, sizeof(pt->ext_proto) - 1);

    return 0;
}

int port_trigger_del(cJSON *params)
{
    return 0;
}

int port_trigger_config(cgi_request_t *req, cgi_response_t *resp)
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

    ret = firewall_config_init();
    if (ret < 0)
    {
        cgi_errno = CGI_ERR_CFG_FILE;
        goto out;
    }
    
    switch(method)
    {
        case CGI_ADD:
            ret = port_trigger_add(params);
            break;
        case CGI_SET:
            ret = port_trigger_edit(params);
            break;
        case CGI_DEL:
            ret = port_trigger_del(params);
            break;
        default:
            cgi_errno = CGI_ERR_NOT_FOUND;
            break;
    }

    //if (ret)
    {
        firewall_config_commit();
        //fork_exec(1, "/etc/init.d/firewall restart");
    }
    
out:
    param_free();
    firewall_config_free();

    webs_json_header(req->out);
    webs_write(req->out, "{\"code\":%d,\"data\":{}}", cgi_errno);

    return 0;
}
