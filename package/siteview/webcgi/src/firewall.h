
#ifndef __FIREWALL_H_
#define __FIREWALL_H_

#define MAX_PORT_FORWARD 100
#define MAX_PORT_TRIGGER 100

typedef struct {
    struct list_head list;
    int id;
    char name[64];
    char interface[10];
    char int_port[12];
    char int_ip[16];
    char ext_port[12];
    char proto[10];
} pf_rule_t;

typedef struct {
    struct list_head list;
    int id;
    char name[64];
    char interface[10];
    char trig_port[12];
    char trig_proto[10];
    char ext_port[12];
    char ext_proto[10];
} pt_rule_t;

struct fw_state {
    int pf_num;
    struct list_head pf_rules;
    int pt_num;
    struct list_head pt_rules;
};

struct fw_weburl {
    char keyword[128];
    struct list_head list;
};

int port_forward_list(cgi_request_t *req, cgi_response_t *resp);
int port_forward_config(cgi_request_t *req, cgi_response_t *resp);

int port_trigger_list(cgi_request_t *req, cgi_response_t *resp);
int port_trigger_config(cgi_request_t *req, cgi_response_t *resp);

#endif
