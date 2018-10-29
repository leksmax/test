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


int net_tool_num_to_netmask(int num, char* out);
uint32_t net_tool_netmask_to_num(char *netmask);
int net_tool_ip_to_subnet(char *ip, int mask_num, char *out);

/* 
 * Get the ip that represented by xxx.xxx.xxx.xxx of specified interface
 * */
int 
net_tool_get_if_ip(char *if_name, char *buf);

int 
net_tool_get_if_netmask(char *if_name, char *buf);

int 
net_tool_get_if_subnet(char *if_name, char *buf);

/*
 * Get the ip that represented by a socket structure of specified interface
 */
int 
net_tool_get_if_addr(char *if_name, struct sockaddr*);

/**
 * @brief  : Get the mac of interface
 *
 * @Param  :if_name
 * @Param  :buf
 *
 * @Returns  : 0 on success, otherwise return -1
 */
int 
net_tool_get_if_hwaddr(char *if_name, char *buf);

/**
 * @brief  : Get the ping latency of host
 *
 * @Param  :host
 * @Param  :timeout
 *
 * @Returns  : 0 on fail, otherwise return the real latency
 */
double 
net_tool_ping_host(const char* host, int timeout);


/**
 * @brief  : Get each ping latency of a host list
 *
 * @Param  :hosts
 * 			before ping, the hosts should be represented in a json like this:
 * 			[
 * 				{
 *					"ip":"10.100.16.5"
 *				},
 *				{
 *					"ip":"10.100.16.6"
 *				}
 * 			]
 * 			after ping, the hosts will be like this
 * 			[
 *				{
 *					"ip":"10.100.16.5",
 *					"latency":1.09
 *				},
 *				{
 *					"ip":"10.100.16.6"
 *					"latency":2.57
 *				}
 * 			]
 *
 * @Param  :timeout
 */
void
net_tool_ping_hosts(cJSON* hosts, int timeout);
void
net_tool_ping_hosts2(cJSON *hosts, char *ip_name, char*latency_name, int timeout);
void
net_tool_ping_hosts3(cJSON *hosts, char *ip_name, char*latency_name, char*latency_list_name, char* loss_name, int timeout, int cnt);
/**
 * @brief  : Reset the route table
 *
 * @Param  :dev
 */
void 
net_tool_reset_routes(char *dev);

/**
 * @brief  : Send a string data to host and recv the response string data of host
 *
 * @Param  :host
 * @Param  :port
 * @Param  :send_buf
 * @Param  :send_len
 * @Param  :recv_len
 *
 * @Returns  :
 */
char *
net_tool_tcp_client(char *host, int port, char *send_buf, int send_len, int *recv_len);

/**
 * @brief  : Send a json data to host and recv the response json data of host
 *
 * @Param  :host
 * @Param  :port
 * @Param  :req
 *
 * @Returns  :
 */
cJSON *
net_tool_tcp_json_client(char *host, int port, cJSON *req);
cJSON *
net_tool_tcp_json_client_with_size(char *host, int port, cJSON *req, char *prefix, int prefix_size);

/**
 * @brief  : Send a string data to a http server in http protocol and recv the response data of http
 * server
 *
 * @Param  :host
 * @Param  :port
 * @Param  :uri
 * @Param  :body
 * @Param  :body_len
 * @Param  :recv_len
 *
 * @Returns  :
 */
char *
net_tool_http_client_raw(char *host, int port, char *uri, void *body, int body_len, int *recv_len);

int net_tool_tcp_port_reachable(char *host, int port);

char *net_tool_http_client2(int method, char *host, int port, char *uri, char *body, int body_len, char* header, int *recv_len);

cJSON* net_tool_http_json_client2(int method, char *host, int port, char *uri, cJSON* req, char* header);

char* net_tool_https_client(int method, char *host, int port, char *uri, char* str_req, int req_len, char** headers, int headers_cnt, int *recv_len, char* ca_file);

cJSON* net_tool_https_json_client(int method, char *host, int port, char *uri, cJSON* req, char** headers, int headers_cnt, char* ca_file);

/**
 * @brief  : Send a json data to a http server and recv the response data of http
 *
 * @Param  :host
 * @Param  :port
 * @Param  :uri
 * @Param  :req
 *
 * @Returns  :
 */
cJSON *
net_tool_http_json_client(char *host, int port, char *uri, cJSON *req);

/**
 * @brief  : Send a dns request to a specified dns server
 *
 * @Param  :dns_server
 * @Param  :request_name
 *
 * @Returns  :
 */
cJSON *
net_tool_dns_request(char *dns_server, char *request_name);

#endif
