
#ifndef __AUTH_H_
#define __AUTH_H_

#include "session.h"
#include "list.h"

typedef struct {
    int id;
    user_t user;
    struct list_head list;
} userDb_t;

int handle_login(cgi_request_t * req, cgi_response_t * resp);
int handle_logout(cgi_request_t * req, cgi_response_t * resp);
int get_login_info(cgi_request_t * req, cgi_response_t * resp);

#endif
