
#ifndef __ROUTE_H_
#define __ROUTE_H_

#define MAX_STATIC_ROUTE 20
#define MAX_POLICY_ROUTE 20
#define MAX_INTERFACE_NUM 6

#define VAR_IS_NULL_DEFAULT_VAL(var, defVal) \
{ \
	if(var == NULL) \
		var = defVal; \
}

typedef struct {
    int id;
    char name[33];
    char interface[10];
    char target[16];
    char netmask[16];
    char gateway[16];
    int metric;    
    struct list_head list; 
} st_route_t;

typedef struct {
    char name[33];
    struct list_head list; 
} po_route_t;

struct route_state {
    int st_route_num;
    struct list_head st_routes;
    int po_route_num;
    struct list_head po_routes;
};

int static_route_list(cgi_request_t * req, cgi_response_t * resp);
int static_route_config(cgi_request_t * req, cgi_response_t * resp);
int policy_route_list(cgi_request_t * req, cgi_response_t * resp);
int policy_route_config(cgi_request_t * req, cgi_response_t * resp);

#endif
