#ifndef _NET_TOOL_H_
#define _NET_TOOL_H_

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/route.h>
#include <net/if.h>
#include "cJSON.h"

int 
net_tool_get_if_ip(char *if_name, char *buf);

int 
net_tool_get_if_addr(char *if_name, struct sockaddr*);

int 
net_tool_get_if_hwaddr(char *if_name, char *buf);

double 
net_tool_ping_host(const char* host, int timeout);

void 
net_tool_reset_routes(char *dev);

char *
net_tool_tcp_client(char *host, int port, char *send_buf, int send_len, int *recv_len);

cJSON *
net_tool_tcp_json_client(char *host, int port, cJSON *req);

char *
net_tool_http_client_raw(char *host, int port, char *uri, void *body, int body_len, int *recv_len);

cJSON *
net_tool_http_json_client(char *host, int port, char *uri, cJSON *req);

#endif
