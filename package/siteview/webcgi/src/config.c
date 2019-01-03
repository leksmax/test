
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "config.h"

int _uci_parse_int(void *ptr, size_t ptr_size, const char *val)
{
    char *e;
    int n = strtol(val, &e, 0);

    if (e == val || *e)
        return false;

    *((int *)ptr) = n;

    return true;
}

int _uci_parse_string(void *ptr, size_t ptr_size, const char *val)
{
    strncpy((char *)ptr, val, ptr_size - 1);
    return true;
}

int json_parse_int(void *ptr, size_t ptr_size, const char *val)
{
    *((int *)ptr) = *((int *)val);
    return true;
}

int json_parse_string(void *ptr, size_t ptr_size, const char *val)
{
    strncpy(ptr, val, ptr_size - 1);
    return true;
}

int _uci_parse_options(void *s, const struct _uci_opt *opts, struct uci_section *sec)
{
	char *val;
	struct uci_element *e;
	struct uci_option *o;
	const struct _uci_opt *opt;
	bool valid = true;

	uci_foreach_element(&sec->options, e)
	{
		o = uci_to_option(e);

		for (opt = opts; opt->name; opt ++)
		{
			if (!opt->parse)
				continue;

			if (strcmp(opt->name, e->name))
				continue;

			if (o->type == UCI_TYPE_STRING)
			{
				val = o->v.string;

				if (!val)
					continue;

				if (!opt->parse((char *)s + opt->offset, opt->size, o->v.string))
				{
					valid = false;
				}
			}

			break;
		}
	}

	return valid;
}

int json_parse_vals(void *s, const struct json_val *vals, cJSON *item)
{
    cJSON *json = NULL;
    const struct json_val *val;
    bool valid = true;
    
    json = item->child;
    while (json)
    {
        for (val = vals; val->name; val ++)
        {
            if (!val->parse)
                continue;

            if (strcmp(val->name, json->string))
                continue;

            if (json->type == cJSON_Array || json->type == cJSON_Object)
            {
                /* to do */
            }
            else if (json->type == cJSON_String)
            {
                if (!val->parse((char *)s + val->offset, val->size, json->valuestring))
                {
                    valid = false;
                }
            }
            else if (json->type == cJSON_Number)
            {
                if (!val->parse((char *)s + val->offset, val->size, (char *)&json->valueint))
                {
                    valid = false;
                }
            }
        }
        
        json = json->next;
    }

    return valid;
}


#if 0
int main(int argc, char *argv[])
{
    int i = 0;
    struct uci_context *ctx;
    struct uci_package *pkg = NULL;    
    struct uci_element *e;

    ctx = uci_alloc_context();
    if (!ctx)
    {
        return -1;
    }

    INIT_LIST_HEAD(&routes);

    uci_load(ctx, "network", &pkg);
    if (!pkg) 
    {
        goto out;
    }    

#if 1
    uci_foreach_element(&pkg->sections, e)
    {      
        struct _uci_route *route;
        struct uci_section *s = uci_to_section(e);

        if (!strcmp(s->type, "route"))
        {
            route = calloc(1, sizeof(*route));
            if (!route)
                continue;

            memset(route, 0x0, sizeof(struct _uci_route));
            
            
            route->id = i + 1;            
            _uci_parse_options(route, _uci_route_opts, s);
            
        }

        list_add_tail(&route->list, &routes);
        
        i ++;
    }

    _uci_print_forwards();
#endif


    int ret = 0;

#if 1
    struct uci_ptr ptr;
	struct uci_section *s_new = NULL;
    struct _uci_route route_new;

    memset(&route_new, 0x0, sizeof(struct _uci_route ));

    route_new.cfg.enabled = 1;
    route_new.cfg.metric = 255;
    strcpy(route_new.cfg.name, "test1");    
    strcpy(route_new.cfg.interface, "WAN1");
    strcpy(route_new.cfg.target, "192.168.2.11");
    strcpy(route_new.cfg.netmask, "255.255.255.255");
    strcpy(route_new.cfg.gateway, "192.168.1.1");
    
    uci_add_section(ctx, pkg, "route", &s_new);

    _uci_save_options((void *)&route_new, _uci_route_opts, s_new);

#if 0    
    struct uci_ptr ptr;
    char anonSecName[32] = {0};

    snprintf(anonSecName, sizeof(anonSecName), "network.@route[%d]", 0);

    uci_lookup_ptr(ctx, &ptr, anonSecName, true);

    uci_delete(ctx, &ptr);
#endif

	ret = uci_save(ctx, pkg);
    uci_commit(ctx, &pkg, false);
#endif

    uci_unload(ctx, pkg);
out:
    
    uci_free_context(ctx); 

    return 0;
}

#endif


