
#ifndef __SWITCH_H_
#define __SWITCH_H_

#define MAX_PHY_PORT 7
#define MAX_PANNEL_PORT 5

#define MIN_VLAN_ID 1
#define MAX_VLAN_ID 4094

#define VLAN_UNTAG 0
#define VLAN_TAG 1

#define MAX_VLAN_ENTRY 128

enum {
    LINK_DOWN = 0,
    LINK_UP
};

enum {
    DUPLEX_HALF = 0,
    DUPLEX_FULL
};

enum {
    SPEED_10 = 1,
    SPEED_100,
    SPEED_1000
};


typedef uint16_t vlan_t;
typedef uint16_t pbmp_t;

struct vlan_alias {
    int vlan;
    char name[33];
    char desc[33];
    struct list_head list;
};

struct port_alias {
    int port;
    char name[33];
    struct list_head list;
};

struct switch_vlan {
    int vlan_entry;
    vlan_t pvid[MAX_PHY_PORT];
    vlan_t vid[MAX_VLAN_ENTRY];
    pbmp_t vlan_bmp[MAX_VLAN_ENTRY];
    pbmp_t t_vlan_bmp[MAX_VLAN_ENTRY];
    struct list_head vlans;
    struct list_head ports;
};

typedef struct {
    char name[33];
    int vlan;
    int vid;
    char ports[128];
    char desc[33];
} vlan_cfg_t;


typedef struct {
    char name[33];
    int port;
    int pvid;
} port_cfg_t;

typedef struct {
    int port;
    int link;
    int speed;
    int duplex;
} port_info_t;

int get_port_status(cgi_request_t * req, cgi_response_t * resp);

int get_vlan_entry(cgi_request_t * req, cgi_response_t * resp);
int vlan_entry_config(cgi_request_t * req, cgi_response_t * resp);
int port_vlan_list(cgi_request_t * req, cgi_response_t * resp);
int port_vlan_config(cgi_request_t * req, cgi_response_t * resp);

#endif
