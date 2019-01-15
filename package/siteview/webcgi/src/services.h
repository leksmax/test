
#ifndef __SERVICES_H_
#define __SERVICES_H_

enum {
    DYN_DDNS = 1,
    NOIP_DDNS = 2,
//    ORAY_DDNS = 3,
    _DDNS_MAX
};

typedef struct {
    int enabled;
    char service[128];
    int updatetime;
    char host[128];
    char username[64];
    char password[64];
    char interface[10];
} ddns_cfg_t;

#define DDNS_ENABLED "ddns.@ddns[0].enabled"
#define DDNS_SERVICES "ddns.@ddns[0].service"
#define DDNS_DOMAIN_NAME "ddns.@ddns[0].domain_name"
#define DDNS_USERNAME "ddns.@ddns[0].username"
#define DDNS_PASSWORD "ddns.@ddns[0].password"
#define DDNS_UPDATE_TIME "ddns.@ddns[0].update_time"
#define DDNS_INTERFACE "ddns.@ddns[0].interface"

#define UPNPD_ENABLED "upnpd.config.enabled"
#define UPNPD_INTERVAL "upnpd.config.interval"
#define UPNPD_TIME_TO_LIVE "upnpd.config.time_to_live"

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
    char name[64];      /* 服务名 */
} upnp_rule_t;

int get_ddns_services(cgi_request_t * req, cgi_response_t * resp);
int get_ddns_config(cgi_request_t * req, cgi_response_t * resp);
int set_ddns_config(cgi_request_t * req, cgi_response_t * resp);

int get_upnpd_rules(cgi_request_t * req, cgi_response_t * resp);
int del_upnpd_rules(cgi_request_t * req, cgi_response_t * resp);
int get_upnpd_config(cgi_request_t * req, cgi_response_t * resp);
int set_upnpd_config(cgi_request_t * req, cgi_response_t * resp);

#endif
