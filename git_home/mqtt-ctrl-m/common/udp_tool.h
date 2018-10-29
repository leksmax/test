/*
 * udp_tool.h
 *
 *  Created on: Sep 19, 2018
 *      Author: pp
 */

#ifndef _SRC_UDP_TOOL_H_
#define _SRC_UDP_TOOL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int create_udp_client();
int create_udp_server(unsigned short port);

void delete_udp_client(int sock);
void delete_udp_server(int sock);

void udp_sendto(int sock, char* buf, size_t buf_len, char* ip, unsigned short port);

#ifdef __cplusplus
}
#endif

#endif /* UDP_TOOL_H_ */
