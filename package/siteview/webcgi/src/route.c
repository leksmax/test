
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "webcgi.h"
#include "route.h"

struct route_state rs;

struct json_st_route {
    int id;
    char *name;
    char *interface;
    char *target;
    char *netmask;
    char *gateway;
    int metric;
};

const struct json_val json_st_route_vals[] = {
    JSON_VAL("id", int, st_route, id),
    JSON_VAL("name", string, st_route, name),        
    JSON_VAL("interface", string, st_route, interface),
    JSON_VAL("target", string, st_route, target),
    JSON_VAL("netmask", string, st_route, netmask),
    JSON_VAL("gateway", string, st_route, gateway),
    JSON_VAL("metric", int, st_route, metric),
    {  }
};

const char *interface_names[MAX_INTERFACE_NUM] = {
	"LAN1",
	"LAN2",
	"LAN3",
	"LAN4",
	"WAN1",
	"WAN2",
};

int check_interface_name(const char *name)
{
	int i = 0;

	for(i = 0; i < MAX_INTERFACE_NUM; i++)
	{
		if(strcmp(interface_names[i], name) == 0)
			return 1;
	}
	return 0;
}

/*  
 *  路由配置：
 *      1.静态路由；
 *      2.策略路由；
 */
int route_config_init()
{
    int ret = 0;
    struct uci_context *ctx;
    struct uci_package *pkg = NULL;
    struct uci_element *e;
    st_route_t *st;
    
    rs.st_route_num = 0;
    INIT_LIST_HEAD(&rs.st_routes);
  
    ctx = uci_alloc_context();
    if (!ctx)
    {
        return -1;
    }

    uci_load(ctx, "route", &pkg);
    if (!pkg) 
    {
        ret = -1;
        goto out;
    }
    
    uci_foreach_element(&pkg->sections, e)
    {  
        struct uci_element *n;
        struct uci_section *s = uci_to_section(e);

        if (!strcmp(s->type, "static"))
        {
            st = (st_route_t *)malloc(sizeof(st_route_t));
            if (!st)
            {
                continue;
            }
            
            memset(st, 0x0, sizeof(st_route_t));
            
            uci_foreach_element(&s->options, n) 
            {
                struct uci_option *o = uci_to_option(n);
                
                if (o->type != UCI_TYPE_STRING)
                {
                    continue;
                }
                if (!strcmp(o->e.name, "name"))
                {
                    strncpy(st->name, o->v.string, sizeof(st->name) - 1);
                }
                else if (!strcmp(o->e.name, "interface"))
                {
                    strncpy(st->interface, o->v.string, sizeof(st->interface) - 1);
                }
                else if (!strcmp(o->e.name, "target"))
                {
                    strncpy(st->target, o->v.string, sizeof(st->target) - 1);
                }
                else if (!strcmp(o->e.name, "netmask"))
                {
                    strncpy(st->netmask, o->v.string, sizeof(st->netmask) - 1);
                }
                else if (!strcmp(o->e.name, "gateway"))
                {
                    strncpy(st->gateway, o->v.string, sizeof(st->gateway) - 1);
                }
                else if (!strcmp(o->e.name, "metric"))
                {
                    st->metric = atoi(o->v.string);
                }
            }

            st->id = rs.st_route_num + 1;
            list_add_tail(&st->list, &rs.st_routes);
            rs.st_route_num += 1;
        }
    } 

    uci_unload(ctx, pkg);
out:
    uci_free_context(ctx);

    return ret;
}

void st_route_rule_free(st_route_t *st)
{
    list_del(&st->list);
    free(st);
}

static void route_config_free()
{
    st_route_t *st, *tmp;
    
    list_for_each_entry_safe(st, tmp, &rs.st_routes, list)
    {
        st_route_rule_free(st);
    }
    rs.po_route_num = 0;
}

void _uci_route_add_static(FILE *fp, st_route_t *st)
{
    fprintf(fp, "config static\n");
    fprintf(fp, "\toption name '%s'\n", st->name);
    fprintf(fp, "\toption interface '%s'\n", st->interface);
    fprintf(fp, "\toption target '%s'\n", st->target);
    fprintf(fp, "\toption netmask '%s'\n", st->netmask);
    fprintf(fp, "\toption gateway '%s'\n", st->gateway);
    fprintf(fp, "\toption metric '%d'\n", st->metric);
    fprintf(fp, "\n");  
}

static void route_config_commit()
{
    FILE *fp = NULL;
    st_route_t *st = NULL;

    fp = fopen("/etc/config/route", "w");
    if (!fp)
    {
        return;
    }

    /* 
     * static route
     */
    list_for_each_entry(st, &rs.st_routes, list)
    {
        _uci_route_add_static(fp, st);
    }

    fclose(fp);
}

int static_route_list(cgi_request_t *req, cgi_response_t *resp)
{
    int i = 0;
    int ret = 0;
    st_route_t *st;
 
    ret = route_config_init();
    if (ret < 0)
    {
        cgi_errno = CGI_ERR_CFG_FILE;
        goto out;
    }

    webs_json_header(req->out);
    webs_write(req->out, "{\"code\":%d,\"data\":{", cgi_errno);
    webs_write(req->out, "\"num\":%d", rs.st_route_num);
    webs_write(req->out, ",\"rules\":[");

    list_for_each_entry(st, &rs.st_routes, list) {
        webs_write(req->out, "%s{\"id\":%d,\"name\":\"%s\",\"interface\":\"%s\",\"target\":\"%s\","
            "\"netmask\":\"%s\",\"gateway\":\"%s\",\"metric\":%d}", ((i > 0) ? "," : ""), st->id, st->name, st->interface, 
            st->target, st->netmask, st->gateway, st->metric);
        i ++;
    }

    webs_write(req->out, "]}}");
    
out:
    if (cgi_errno != CGI_ERR_OK)
    {
        webs_json_header(req->out);
        webs_write(req->out, "{\"code\":%d,\"data\":{}}", cgi_errno);    
    }
    
    route_config_free();
    
    return 0;
}

int check_st_route_data_vaild(struct json_st_route *p)
{
	if(p->target == NULL || p->interface == NULL || p->name == NULL)
		return -1;
	
	if(check_interface_name(p->interface) == 0)
		return -1;

	VAR_IS_NULL_DEFAULT_VAL(p->netmask, "");
	VAR_IS_NULL_DEFAULT_VAL(p->gateway, "");

	if(p->metric < 0 || p->metric > 255)
		p->metric = 0;

	return 0;
}

int check_data_is_exist(struct json_st_route p)
{
    st_route_t *st = NULL;
    list_for_each_entry(st, &rs.st_routes, list)
    {
        if (strcmp(st->target, p.target) == 0 &&
			strcmp(st->netmask, p.netmask) == 0 &&
			strcmp(st->interface, p.interface) == 0)
        {
            return -1;
        }
    }
	return 0;
}

int static_route_add(cJSON *params)
{
    st_route_t *st = NULL;
    struct json_st_route p;

    if (rs.st_route_num >= MAX_STATIC_ROUTE)
    {
        return CGI_ERR_CFG_OVERMUCH;
    }
        
    memset(&p, 0x0, sizeof(struct json_st_route));
    json_parse_vals((void *)&p, json_st_route_vals, params);

	if (check_st_route_data_vaild(&p) < 0)
	{
		return CGI_ERR_CFG_PARAM;
	}

	if (check_data_is_exist(p) < 0)
	{
		return CGI_ERR_CFG_DUPLICATE;
	}

    st = (st_route_t *)malloc(sizeof(st_route_t));
    if (!st)
    {
        return CGI_ERR_INTERNAL;
    }
	memset(st, 0x0, sizeof(st_route_t));

    st->id = rs.st_route_num + 1;
    strncpy(st->name, p.name, sizeof(st->name) - 1);
    strncpy(st->interface, p.interface, sizeof(st->interface) - 1);
    strncpy(st->target, p.target, sizeof(st->target) - 1);
    strncpy(st->netmask, p.netmask, sizeof(st->netmask) - 1);
    strncpy(st->gateway, p.gateway, sizeof(st->gateway) - 1);
    st->metric = p.metric;

    list_add_tail(&st->list, &rs.st_routes);
    rs.st_route_num += 1;

    return CGI_ERR_OK;
}

int static_route_edit(cJSON *params)
{
    st_route_t *st = NULL;
    struct json_st_route p;

    memset(&p, 0x0, sizeof(struct json_st_route));
    json_parse_vals((void *)&p, json_st_route_vals, params);

	if (check_st_route_data_vaild(&p) < 0)
	{
		return CGI_ERR_CFG_PARAM;
	}

    list_for_each_entry(st, &rs.st_routes, list)
    {
        if (p.id == st->id)
        {
            break;
        }
    }

    if (!st)
    {
        return CGI_ERR_CFG_PARAM;
    }

    strncpy(st->name, p.name, sizeof(st->name) - 1);
    strncpy(st->interface, p.interface, sizeof(st->interface) - 1);
    strncpy(st->target, p.target, sizeof(st->target) - 1);
    strncpy(st->netmask, p.netmask, sizeof(st->netmask) - 1);
    strncpy(st->gateway, p.gateway, sizeof(st->gateway) - 1);
    st->metric = p.metric;

    return CGI_ERR_OK;
}

int static_route_del(cJSON *params)
{
    int ret = 0;
    cJSON *rules;
    cJSON *jsonVal = NULL;
    int intVal = 0;
    st_route_t *st, *tmp;

    rules = cJSON_GetObjectItem(params, "rules");
    if (!rules || rules->type != cJSON_Array)
    {
        return CGI_ERR_CFG_PARAM;
    }

    jsonVal = rules->child;
    while (jsonVal && jsonVal->type == cJSON_Object)
    {
        ret = cjson_get_int(jsonVal, "id", &intVal);
        if (ret < 0)
        {
            return CGI_ERR_CFG_PARAM;
        }

        list_for_each_entry_safe(st, tmp, &rs.st_routes, list)
        {
            if (intVal == st->id)
            {
                rs.st_route_num -= 1;
                st_route_rule_free(st);
            }
        }
    
        jsonVal = jsonVal->next;
    }

    return CGI_ERR_OK;
}

int static_route_config(cgi_request_t *req, cgi_response_t *resp)
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

    ret = route_config_init();
    if (ret < 0)
    {
        cgi_errno = CGI_ERR_CFG_FILE;
        goto out;
    }
    
    switch(method)
    {
        case CGI_ADD:
            cgi_errno = static_route_add(params);
            break;
        case CGI_SET:
            cgi_errno = static_route_edit(params);
            break;
        case CGI_DEL:
            cgi_errno = static_route_del(params);
            break;
        default:
            cgi_errno = CGI_ERR_NOT_FOUND;
            break;
    }

    if (cgi_errno == CGI_ERR_OK)
    {
        route_config_commit();
        fork_exec(1, "/etc/init.d/route restart");
    }
    
out:
    param_free();
    route_config_free();

    webs_json_header(req->out);
    webs_write(req->out, "{\"code\":%d,\"data\":{}}", cgi_errno);

    return 0;
}

int policy_route_list(cgi_request_t *req, cgi_response_t *resp)
{    
    return 0;
}

int policy_route_add(cJSON *params)
{    
    return 0;
}

int policy_route_edit(cJSON *params)
{
    return 0;
}

int policy_route_del(cJSON *params)
{
    return 0;
}

int policy_route_config(cgi_request_t *req, cgi_response_t *resp)
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

    ret = route_config_init();
    if (ret < 0)
    {
        cgi_errno = CGI_ERR_CFG_FILE;
        goto out;
    }
    
    switch(method)
    {
        case CGI_ADD:
            ret = policy_route_add(params);
            break;
        case CGI_SET:
            ret = policy_route_edit(params);
            break;
        case CGI_DEL:
            ret = policy_route_del(params);
            break;
        default:
            cgi_errno = CGI_ERR_NOT_FOUND;
            break;
    }

out:
    param_free();
    route_config_free();

    webs_json_header(req->out);
    webs_write(req->out, "{\"code\":%d,\"data\":{}}", cgi_errno);
    
    return 0;
}

