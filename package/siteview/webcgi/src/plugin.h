
#ifndef __WEBCGI_PLUGIN_H
#define __WEBCGI_PLUGIN_H

#include "servlet.h"

#define WEBCGI_LIB_DIR   "/usr/lib/webcgi" 

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

struct cgi_plugin {
    char *name;
    cgi_handler_t *handlers;
    int n_handlers;
};

int cgi_plugin_api_init();
void cgi_plugin_api_destroy();
struct cgi_handler *cgi_plugin_api_find(char *url);

#endif
