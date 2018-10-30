
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <uci.h>
#include "utils.h"

int cgi_type = 0;
int cgi_errno = CGI_ERR_OK;
int cgi_cmd = 0;

#define SYSTEM_API

int sys_exec(const char *fmt, ...)
{
    va_list args;
    char cmdbuf[512] = {0};

    va_start(args, fmt);
    vsnprintf(cmdbuf, sizeof(cmdbuf), fmt, args);
    va_end(args);

    return system(cmdbuf);
}

/*
 * 子进程延时执行
 * 对于cgi来说有些操作需要在返回前端处理之后再初始化，
 * 这样初始化动作需要后台延时执行
 */
int fork_exec(int wait, const char *fmt, ...)
{
    int i;    
    pid_t pid;
    va_list args;
    char cmdbuf[512] = {0};

    pid = fork();
    if(pid <  0)
    {
        exit(1);
    }
    else if(pid == 0)
    {
        setsid();

        for(i = 0; i <= 2; i ++)
        {
            close(i);
        }      
        umask(0);

        if(wait > 0)
        {
            sleep(wait);
        }
        
        va_start(args, fmt);
        vsnprintf(cmdbuf, sizeof(cmdbuf), fmt, args);
        va_end(args);

        return system(cmdbuf);
    }

    return 0;
}


#define CONFIG_API

char *config_get(const char *name)
{
    int ret = -1;    
    struct uci_context *ctx = NULL;
    struct uci_ptr ptr;    
    char path[CONFIG_MAX_PARAM_LEN];
    static char cfg_cache[CONFIG_MAX_VALUE_LEN];
    
    memset(path, 0x0, CONFIG_MAX_PARAM_LEN);
    memset(cfg_cache, 0x0, CONFIG_MAX_VALUE_LEN);
    
    snprintf(path, CONFIG_MAX_PARAM_LEN, "%s", name);

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

int config_get_int(const char *name)
{
    char *value = config_get(name);
    if(value[0] != '\0')
        return atoi(value);
    else
        return 0;
}

int config_set(const char *name, const char *value)
{
    return sys_exec("uci set %s=\"%s\"", name, (value ? value : ""));
}

int config_set_int(const char *name, int value)
{
    char intStr[16] = {0};
    snprintf(intStr, sizeof(intStr), "%d", value);
    return config_set(name, intStr);
}

int config_unset(const char *name)
{
    return sys_exec("uci delete %s", name);    
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
    return sys_exec("uci commit", CONFIG_FILE);
}

int config_uncommit()
{
    return sys_exec("uci revert %s", CONFIG_FILE);
}

#define CJSON_API

int cjson_get_int(cJSON *obj, char *key, int *val)
{
    cJSON *tmp = NULL;

    tmp = cJSON_GetObjectItem(obj, key);
    if(!tmp || tmp->type != cJSON_Number)
    {
        return -1;
    }

    *val = tmp->valueint;

    return 0;
}

int cjson_get_double(cJSON *obj, char *key, double *val)
{
    cJSON *tmp = NULL;

    tmp = cJSON_GetObjectItem(obj, key);
    if(!tmp || tmp->type != cJSON_Number)
    {
        return -1;
    }

    *val = tmp->valuedouble;

    return 0;
}

char *cjson_get_string(cJSON *obj, char *key)
{
    cJSON *tmp = NULL;

    tmp = cJSON_GetObjectItem(obj, key);
    if(!tmp || tmp->type != cJSON_String)
    {
        return NULL;
    }

    return tmp->valuestring;
}

#define PARAM_CHECK

int is_valid_port(int port)
{
    if(port < 0 || port > 65535)
        return INVALID_PARAM;
    return VALID_PARAM;
}

#define WEB_API

void webs_json_header(wp_t *wp)
{
    fprintf(wp, "Status: 200 OK\r\n");
    fprintf(wp, "Content-type: application/json; charset=utf-8\r\n");
    fprintf(wp, "Pragma: no-cache\r\n");
    fprintf(wp, "Cache-Control: no-cache\r\n");
    fprintf(wp, "\r\n");
}

void webs_text_header(wp_t *wp)
{
    fprintf(wp, "Status: 200 OK\r\n");
    fprintf(wp, "Content-type: text/plain; charset=utf-8\r\n");
    fprintf(wp, "Pragma: no-cache\r\n");
    fprintf(wp, "Cache-Control: no-cache\r\n");
    fprintf(wp, "\r\n");
}

void webs_write(wp_t *wp, char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    vfprintf(wp, fmt, args);
    va_end(args);
}

#define DATALEN 65

void unencode(char *src, char *last, char *dest)
{
    for(; src != last; src++, dest++)
        if(*src == '+')
            *dest = ' ';
        else if(*src == '%') {
            int code;
            if(sscanf(src+1, "%2x", &code) != 1) code = '?';
            *dest = code;
            src +=2;
        } else
            *dest = *src;
    *dest = '\0';
}

char *web_get(char *tag, char *input, int dbg)
{
    char *e_begin, *v_begin, *v_end;
    static char ret[DATALEN];
    int v_len;

    sprintf(ret, "&%s=", tag);
    
    if (NULL == (e_begin = strstr(input, ret))) {
        sprintf(ret, "%s=", tag);
    if (NULL == (e_begin = strstr(input, ret)) || e_begin != input)
        return "";
    }
    
    memset(ret, 0, DATALEN);
    v_begin = strchr(e_begin, '=') + 1;
    
    if (v_begin == NULL) v_begin = "";
    if ((NULL != (v_end = strchr(v_begin, '&')) ||
        NULL != (v_end = strchr(v_begin, '\0'))) &&
        (0 < (v_len = v_end - v_begin)))
            unencode(v_begin, v_end, ret);
    
    /* for WebUI debug*/
    if (dbg == 1)
        printf("%s = %s\n", tag, ret);
    else if (dbg == 2)
        cgi_debug("[DBG]%s = %s\n", tag, ret);

    return ret;
}


