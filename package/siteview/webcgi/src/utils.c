
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <uci.h>
#include "utils.h"

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
    if(pid < 0)
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
    struct uci_element *e;
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

    e = ptr.last;
    if (e->type == UCI_TYPE_SECTION)
    {
        strncpy(cfg_cache, ptr.s->type, CONFIG_MAX_VALUE_LEN - 1);
    }
    else
    {
        strncpy(cfg_cache, ptr.o->v.string, CONFIG_MAX_VALUE_LEN - 1);
    }
    
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

int config_commit(const char *config)
{
    return sys_exec("uci commit %s", config);
}

int config_uncommit(const char *name)
{
    return sys_exec("uci revert %s", name);
}

#define WEB_API

void webs_file_header(wp_t *wp, const char *filename)
{
    fprintf(wp, "Status: 200 OK\r\n");
    fprintf(wp, "Content-Type: application/octet-stream\r\n");
    fprintf(wp, "Content-Disposition: attachment; filename=\"%s\"\r\n", filename);
    fprintf(wp, "Pragma: no-cache\r\n");
    fprintf(wp, "Cache-Control: no-cache\r\n");
    fprintf(wp, "\r\n");
}

void webs_json_header(wp_t *wp)
{
    fprintf(wp, "Status: 200 OK\r\n");
    fprintf(wp, "Content-Type: application/json; charset=utf-8\r\n");
    fprintf(wp, "Pragma: no-cache\r\n");
    fprintf(wp, "Cache-Control: no-cache\r\n");
    fprintf(wp, "\r\n");
}

void webs_text_header(wp_t *wp)
{
    fprintf(wp, "Status: 200 OK\r\n");
    fprintf(wp, "Content-Type: text/plain; charset=utf-8\r\n");
    fprintf(wp, "Pragma: no-cache\r\n");
    fprintf(wp, "Cache-Control: no-cache\r\n");
    fprintf(wp, "\r\n");
}

void webs_redirect(wp_t *wp, char *html)
{
    fprintf(wp, "Status: 307 OK\r\n");
    fprintf(wp, "Content-Type: text/plain; charset=utf-8\r\n");
    fprintf(wp, "\r\n");    
}

void webs_write(wp_t *wp, char *fmt, ...)
{
    va_list args;
    
    va_start(args, fmt);
    vfprintf(wp, fmt, args);
    va_end(args);
}

#define CJSON_API

cJSON *pRoot = NULL;

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

#define MISC_API

char *cat_file(const char *file)
{
    int i = 0;
    FILE *fp = NULL;
    static char buf[512];

    buf[0] = '\0';

    fp = fopen(file, "r");
    if (!fp)
    {
        return buf;
    }

    fgets(buf, sizeof(buf), fp);
    fclose(fp);

    while (buf[i] != '\0' && 
        buf[i] != '\r' && 
        buf[i] != '\n')
    {
        i ++;
    }

    buf[i] = '\0';

    return buf;
}

void echo_file(char *value, char *file)
{
    FILE *fp = NULL;

    fp = fopen(file, "w");
    if (!fp)
    {
        return;
    }

    fputs(value, fp);
    fclose(fp);
}

int param_init(char *data, int *method, cJSON **params)
{
    cJSON *jsonVal = NULL;
    char *strVal = NULL;
    
    pRoot = cJSON_Parse(data);
    if (!pRoot)
    {
        return -1;
    }

    strVal = cjson_get_string(pRoot, "method");
    if (!strVal)
    {
        return -1;
    }

    if (strcmp(strVal, "set") == 0)
    {
        *method = CGI_SET;
    }
    else if (strcmp(strVal, "add") == 0)
    {
        *method = CGI_ADD;
    }
    else if (strcmp(strVal, "delete") == 0)
    {
        *method = CGI_DEL;
    }
    else
    {
        *method = CGI_GET;
    }
    
    jsonVal = cJSON_GetObjectItem(pRoot, "params");
    if (!jsonVal)
    {
        return -1;
    }

    *params = jsonVal;

    return 0;
}

void param_free()
{
    if (pRoot)
    {
        cJSON_Delete(pRoot);
        pRoot = NULL;
    }
}

