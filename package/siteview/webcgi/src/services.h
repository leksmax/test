
#ifndef __SERVICES_H_
#define __SERVICES_H_

enum {
    DYN_DDNS = 1,
    NOIP_DDNS = 2,
    _DDNS_MAX
};

typedef struct {
    int enabled;
    char service[128];
    int updatetime;
    char host[128];
    char username[64];
    char password[64];
} ddns_cfg_t;

typedef struct {
    int enabled;
    int intval;
    int ttl;
} upnp_cfg_t;

typedef struct {
    int in_port;
    int ext_port;
    char proto[10];
    int in_ip4addr[16];
    char name[64];      /* ·þÎñÃû */
} upnp_rule_t;

int get_ddns_services(cgi_request_t * req, cgi_response_t * resp);
int get_ddns_config(cgi_request_t * req, cgi_response_t * resp);
int set_ddns_config(cgi_request_t * req, cgi_response_t * resp);

int get_upnpd_rules(cgi_request_t * req, cgi_response_t * resp);
int del_upnpd_rules(cgi_request_t * req, cgi_response_t * resp);
int get_upnpd_config(cgi_request_t * req, cgi_response_t * resp);
int set_upnpd_config(cgi_request_t * req, cgi_response_t * resp);

#endif
