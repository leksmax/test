
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysinfo.h>
#include <uci.h>

#include "utils.h"
#include "servlet.h"
#include "auth.h"

struct list_head userDb;

static void userDb_init()
{
    INIT_LIST_HEAD(&userDb);
}

static void userDb_add(int i, user_t *user)
{
    userDb_t *item;

    item = (void *)malloc(sizeof(userDb_t));
    if (!item)
    {
        return;
    }

    memset(item, 0x0, sizeof(userDb_t));
    
    item->id = i + 1;
    memcpy(&item->user, user, sizeof(user_t));

    INIT_LIST_HEAD(&item->list);
    list_add_tail(&item->list, &userDb);
}

static userDb_t *userDb_find(char *name, char *pwd)
{
    userDb_t *item = NULL;

    list_for_each_entry(item, &userDb, list)
    {   
        if (!strcmp(item->user.name, name) &&
            !strcmp(item->user.pwd, pwd))
        {
            return item;
        }
    }

    return NULL;
}

static void userDb_del(userDb_t *item)
{
    list_del(&item->list);
    free(item);
}

static int auth_config_init()
{
    int i = 0;
    user_t user;
    
    struct uci_context *ctx;
    struct uci_package *pkg = NULL;
    struct uci_element *e;

    userDb_init();

    ctx = uci_alloc_context();
    if (!ctx)
    {
        return -1;
    }

    uci_load(ctx, "webcgi", &pkg);
    if (!pkg) 
    {
        goto out;
    }
    
    uci_foreach_element(&pkg->sections, e)
    {  
        struct uci_element *n;
        struct uci_section *s = uci_to_section(e);

        if (!strcmp(s->type, "auth"))
        {
            memset(&user, 0x0, sizeof(user_t));
            
            uci_foreach_element(&s->options, n) 
            {
                struct uci_option *o = uci_to_option(n);
                
                if (o->type != UCI_TYPE_STRING)
                {
                    continue;
                }
                if (!strcmp(o->e.name, "priv"))
                {
                    if (!strcmp(o->v.string, "admin"))
                    {
                        user.priv = PRIV_ADMIN;
                    }
                    else
                    {
                        user.priv = PRIV_GUEST;
                    }
                }
                else if (!strcmp(o->e.name, "username"))
                {
                    strncpy(user.name, o->v.string, sizeof(user.name) - 1);
                }
                else if (!strcmp(o->e.name, "password"))
                {
                    strncpy(user.pwd, o->v.string, sizeof(user.pwd) - 1);
                }
            }
            
            userDb_add(i, &user);
            
            i ++;
        }
    } 

    uci_unload(ctx, pkg);
out:
    uci_free_context(ctx);

    return 0;
}

static void auth_config_free()
{
    userDb_t *item, *tmp;

    list_for_each_entry_safe(item, tmp, &userDb, list)
    {
        userDb_del(item);
    }
}

#define AUTH_API

int handle_login(cgi_request_t *req, cgi_response_t *resp)
{
    int ret = 0;
    int method;
    cJSON *params;
    char *user = NULL;
    char *pwd = NULL;
    userDb_t *item = NULL;

    struct sysinfo s_info;

    ret = param_init(req->post_data, &method, &params);
    if (ret < 0)
    {
        cgi_errno = CGI_ERR_PARAM;
        goto out;
    }
    
    /* 从配置文件中获取用户名密码 */
    ret = auth_config_init();
    if (ret < 0)
    {
        cgi_errno = CFI_ERR_CFG_FILE;
        goto out;
    }

    user = cjson_get_string(params, "username");
    if (ret < 0)
    {
        cgi_errno = CGI_ERR_CFG_PARAM;
        goto out;
    }

    pwd = cjson_get_string(params, "password");
    if (ret < 0)
    {
        cgi_errno = CGI_ERR_CFG_PARAM;
        goto out;
    } 

    /* 查找   */
    item = userDb_find(user, pwd);
    if (!item)
    {
        cgi_errno = CGI_ERR_AUTH_CHECK;
        goto out;
    }

    sysinfo(&s_info);

    strncpy(req->sess->username, user, sizeof(req->sess->username) - 1);
    req->sess->priv = item->user.priv;
    
    strncpy(req->sess->macaddr, "00:11:22:33:44:55", sizeof(req->sess->macaddr) - 1);
    strncpy(req->sess->ipaddr, req->ipaddr, sizeof(req->sess->ipaddr) - 1);
    req->sess->last_active = s_info.uptime;
    
    update_cgi_session(req->sess);
    
out:
    webs_json_header(req->out);
    webs_write(req->out, "{\"code\":%d,\"data\":{}}", cgi_errno);

    auth_config_free();
    
    return 0;
}

int handle_logout(cgi_request_t *req, cgi_response_t *resp)
{
    clear_cgi_session(req->sess);

    webs_json_header(req->out);
    webs_write(req->out, "{\"code\":0,\"data\":{}}");
    
    return 0;
}

/* 获取登录信息 */
int get_login_info(cgi_request_t *req, cgi_response_t *resp)
{
    webs_json_header(req->out);
    webs_write(req->out, "{\"code\":0,\"data\":{");
    webs_write(req->out, "\"loginIp\":\"%s\",", req->sess->ipaddr);
    webs_write(req->out, "\"username\":\"%s\"", req->sess->username);
    webs_write(req->out, "}}");

    return 0;
}
