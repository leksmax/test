/*
 * udp_tool.cpp
 *
 *  Created on: Sep 19, 2018
 *      Author: pp
 */

#include "udp_tool.h"

int create_udp_client()
{
	int ret = -1;
	ret = socket(AF_INET, SOCK_DGRAM, 0);
	return ret;
}

int create_udp_server(unsigned short port)
{
	int ret = -1;
	ret = socket(PF_INET, SOCK_DGRAM, 0);
	if (ret >= 0)
	{
		int sock_opt = 1;
		setsockopt(ret, SOL_SOCKET, SO_REUSEADDR, (void *) &sock_opt, sizeof (sock_opt));

	    struct sockaddr_in servaddr;
	    memset(&servaddr, 0, sizeof(servaddr));
	    servaddr.sin_family = AF_INET;
	    servaddr.sin_port = htons(port);
	    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	    bind(ret, (struct sockaddr *)&servaddr, sizeof(servaddr));
	}
	return ret;
}

void delete_udp_client(int sock)
{
	close(sock);
}

void delete_udp_server(int sock)
{
	close(sock);
}

void udp_sendto(int sock, char* buf, size_t buf_len, char* ip, unsigned short port)
{
	struct sockaddr_in peer_addr;
	socklen_t peer_len = sizeof(peer_addr);
	memset(&peer_addr, 0, sizeof(peer_addr));
	peer_addr.sin_family = AF_INET;
	peer_addr.sin_addr.s_addr = inet_addr(ip);
	peer_addr.sin_port = htons(port);
	//printf("sendto <%s>: %s", peer, buf);
	sendto(sock, buf, buf_len, 0, (struct sockaddr*)&peer_addr, peer_len);
}

