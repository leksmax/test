
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>

#include "list.h"
#include "plugin.h"

static LIST_HEAD(plugin_dls);
static LIST_HEAD(plugins);

struct plugin_dl {
    struct list_head list;
    void *dlh;
};

struct cgi_plugin_h {
    struct list_head list;
    struct cgi_handler *handler;
};

int cgi_plugin_register(struct cgi_plugin *plugin)
{
    int ret = 0;
    cgi_handler_t *handler = NULL;
    struct cgi_plugin_h *plugin_h = NULL;
    
    for (handler = plugin->handlers; handler->url != NULL;
            handler ++)
    {
        plugin_h = calloc(1, sizeof(struct cgi_plugin_h));
        if (!plugin_h)
        {
            return -1;
        }
        
        INIT_LIST_HEAD(&plugin_h->list);
        plugin_h->handler = handler;
        
        list_add_tail(&plugin_h->list, &plugins);
    }

    return ret;
}

int cgi_plugin_register_library(char *path)
{
    int ret = 0;
    void *dlh = NULL;
    struct plugin_dl *dl = NULL;
    struct cgi_plugin *plugin = NULL;
    
    dlh = dlopen(path, RTLD_NOW);
    if (dlh == NULL) 
    {
        return -1;     
    }

    plugin = dlsym(dlh, "plugin");
    if (!plugin)
    {  
        dlclose(dlh);
        return -1;
    }  

    ret = cgi_plugin_register(plugin);
    if (ret < 0)
    {
        dlclose(dlh);
        return -1;
    }

    dl = calloc(1, sizeof(struct plugin_dl));
    if (dl)
    {
        dl->dlh = dlh;
        INIT_LIST_HEAD(&dl->list);
        list_add_tail(&dl->list, &plugin_dls);
    }
    
    return ret;
}

/* CGI Plugin 初始化 */
int cgi_plugin_api_init()
{
    DIR *d;
    int ret = 0;
    struct stat s;
    struct dirent *e;
    char path[128] = {0};

    if ((d = opendir(WEBCGI_LIB_DIR)) != NULL)
    {   
        while ((e = readdir(d)) != NULL)
        {   
            snprintf(path, sizeof(path) - 1, WEBCGI_LIB_DIR "/%s", e->d_name);

            if (stat(path, &s) || !S_ISREG(s.st_mode))
                continue;

            ret |= cgi_plugin_register_library(path);
        }   

        closedir(d);
    }

    return ret; 
}

/* CGI Plugin 释放 */
void cgi_plugin_api_destroy()
{
    struct plugin_dl *dl, *tmp;
    struct cgi_plugin_h *ph, *ptmp;
    
    list_for_each_entry_safe(dl, tmp, &plugin_dls, list) {
        dlclose(dl->dlh);
        list_del(&dl->list);
        free(dl);
    }

    list_for_each_entry_safe(ph, ptmp, &plugins, list) {
        list_del(&ph->list);
        free(ph);
    }
}

struct cgi_handler *cgi_plugin_api_find(char *url)
{
    struct cgi_plugin_h *ph;
    
    list_for_each_entry(ph, &plugins, list) {
        if (!strcmp(ph->handler->url, url))
        {
            return ph->handler;
        }
    }

    return NULL;
}

#if 0
int main(int argc, char *argv[])
{
    int ret = 0;
    struct cgi_plugin_h *ph;

    ret = cgi_plugin_api_init();
    if (ret < 0)
    {
        return -1;
    }

    list_for_each_entry(ph, &plugins, list) {
        printf("%s\n", ph->handler->url);
    }

    cgi_plugin_api_destroy();

    return 0;
}
#endif
