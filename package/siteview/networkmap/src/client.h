
#ifndef __CLIENT_H_
#define __CLIENT_H_

#include "list.h"

typedef struct {
    int lan_unit;
    unsigned char lan_ip[4];
    unsigned char lan_mask[4];
    unsigned char lan_mac[6];
    int total_num;
    int active_num;
    struct list_head head;
} client_list_t;

typedef struct {
    struct list_head list;
    int status;
    int uptime;
    int offtime;
    char device[20];
    char ipaddr[16];
    char macaddr[18];
    char hostname[65];
    char vendor[65];
    char devtype[20];
    char conntype[10];
} net_client_t;

#endif
