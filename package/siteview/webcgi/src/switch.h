
#ifndef __SWITCH_H_
#define __SWITCH_H_

#define MAX_PHY_PORT 7
#define MAX_PANNEL_PORT 5

#define MIN_VLAN_ID 1
#define MAX_VLAN_ID 4094

#define VLAN_UNTAG 0
#define VLAN_TAG 1

#define MAX_VLAN_ENTRY 128

typedef uint16_t vlan_t;
typedef uint16_t pbmp_t;

struct switch_vlan {
    int vlan_entry;
    vlan_t pvid[MAX_PHY_PORT];
    vlan_t vid[MAX_VLAN_ENTRY];
    pbmp_t vlan_bmp[MAX_VLAN_ENTRY];
    pbmp_t t_vlan_bmp[MAX_VLAN_ENTRY];
};

typedef struct {
    char name[33];
    int vlan;
    int vid;
    char ports[128];
} switch_vlan_t;

typedef struct {
    char name[33];
    int port;
    int pvid;
} switch_port_t;

#endif
