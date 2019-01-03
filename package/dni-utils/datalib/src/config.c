
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <uci.h>
#include "config.h"

int config_show()
{
    int ret = 0;
    struct uci_context *ctx = NULL;
    struct uci_package *pkg = NULL;

    ctx = uci_alloc_context();
    if (!ctx)
    {
        return -1;
    }

    ret = uci_load(ctx, CONFIG_FILE, &pkg);
    if (!pkg)
    {
        goto out;
    }

    struct uci_element *e;
    
	uci_foreach_element(&pkg->sections, e) {
	    struct uci_element *n;
		struct uci_section *s = uci_to_section(e);

        if (strcmp(s->type, SECTION_TYPE) != 0)
            continue;

        uci_foreach_element(&s->options, n) {
            struct uci_option *o = uci_to_option(n);

            if (o->type != UCI_TYPE_STRING)
                continue;

            printf("%s=%s\n", o->e.name, o->v.string);
        }
	}

out:
    uci_free_context(ctx);

    return ret;
}

int sys_exec(const char *fmt, ...)
{
    va_list args;
    char cmdbuf[512] = {0};

    va_start(args, fmt);
    vsnprintf(cmdbuf, sizeof(cmdbuf), fmt, args);
    va_end(args);

    return system(cmdbuf);
}

char *config_get(const char *name)
{
    int ret = -1;    
    struct uci_context *ctx = NULL;
    struct uci_ptr ptr;
    char path[CONFIG_MAX_PARAM_LEN];
    static char cfg_cache[CONFIG_MAX_VALUE_LEN];
    
    memset(path, 0x0, CONFIG_MAX_PARAM_LEN);
    memset(cfg_cache, 0x0, CONFIG_MAX_VALUE_LEN);
    
    snprintf(path, CONFIG_MAX_PARAM_LEN, "%s.dni.%s", SECTION_TYPE, name);

    ctx = uci_alloc_context();
    if (!ctx)
    {
        return cfg_cache;
    }

    ret = uci_lookup_ptr(ctx, &ptr, path, true);
    if(ret != UCI_OK)
    {   
        goto out;
    }

    if ((ptr.option && !ptr.o) || !ptr.s)
    {
        goto out;
    }
    
    strncpy(cfg_cache, ptr.o->v.string, CONFIG_MAX_VALUE_LEN - 1);

out:
    uci_free_context(ctx);

    return cfg_cache;
}

int config_set(const char *name, const char *value)
{
    return sys_exec("uci set %s%s=\"%s\"", UCI_PREFIX, name, (value ? value : ""));
}

int config_unset(const char *name)
{
    return sys_exec("uci delete %s%s", UCI_PREFIX, name);    
}

int config_match(const char *name, char *match)
{
    const char *value = config_get(name);
	return (value && !strcmp(value, match));
}

int config_inmatch(const char *name, char *invmatch)
{
	const char *value = config_get(name);
	return (value && strcmp(value, invmatch));    
}

int config_commit()
{
    return sys_exec("uci commit %s", CONFIG_FILE);
}

int config_uncommit()
{
    return sys_exec("uci revert %s", CONFIG_FILE);
}
