
#ifndef __SERVLET_H_
#define __SERVLET_H_

#include "session.h"

enum {
    WEB_CGI = 0, /* default */
    SHELL_CLI = 1
};

#define MULTIPART_CONTENT_TYPE "multipart/form-data"

typedef struct cgi_request {
    char *url;
    char method[10];
    char ipaddr[46];
    int post_len;
    int file_upload;
    char *post_data;
    FILE *out;
    session_t *sess;
} cgi_request_t;

typedef struct cgi_response {
    int status;
} cgi_response_t;

typedef struct cgi_handler {
    char *url;
    int (*handler)(cgi_request_t *req, cgi_response_t *resp);
    int auth;
} cgi_handler_t;

int cgi_servlet_init(cgi_handler_t * handler_map[]);

#endif
