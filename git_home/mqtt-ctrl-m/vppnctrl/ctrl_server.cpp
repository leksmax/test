/*
 * ctrl_server.c
 *
 *  Created on: Jun 2, 2017
 *      Author: pp
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <pthread.h>
#include <strings.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>
#include "ctrl_server.h"
#include "ctrl_server_json.h"
#include "ctrl-interface.h"
#include "vpn_config.h"
#include "cJSON.h"
#include "net_tool.h"
#include "my_debug.h"

#define MAX_ALLOC_ONCE_LEN (409600)

#ifndef FREE_PTR
#define FREE_PTR(ptr) do{if (ptr) {free((ptr)); (ptr)=NULL;}}while(0);
#endif

int ctrl_running = 1;

size_t recv_client_data_len(int sockfd)
{
	unsigned char buf[4];
	size_t ret_len = 0;
	memset(buf, 0 , 4);
	ssize_t recv_len = recv(sockfd, buf, 4, 0);
	if (recv_len == 4)
	{
#if 1
		ret_len = (size_t)ntohl(*(uint32_t*)buf);
#else
		size_t tmp0 = (unsigned int)(buf[0]) & 0xff;
		tmp0 *= 256 *256 *256;
		size_t tmp1 = (unsigned int)(buf[1]) & 0xff;
		tmp1 *= 256 *256;
		size_t tmp2 = (unsigned int)(buf[2]) & 0xff;
		tmp2 *= 256;
		size_t tmp3 = (unsigned int)(buf[3]) & 0xff;
		tmp3 *= 1;
		ret_len = tmp0 + tmp1 + tmp2 + tmp3;
#endif
	}
	return ret_len;
}

void *recv_client_data(int sockfd, int *len)
{
    ssize_t recv_len = 0;
    ssize_t recv_len_total = 0;
    char *recv_ptr = NULL;
    if (sockfd > 0)
    {
		/* recv 5 seconds at most */
		socklen_t optlen = sizeof(struct timeval);
		struct timeval tv;
		tv.tv_sec = 5;
		tv.tv_usec = 0;
		setsockopt(sockfd, SOL_SOCKET,SO_SNDTIMEO, &tv, optlen);
		setsockopt(sockfd, SOL_SOCKET,SO_RCVTIMEO, &tv, optlen);
		size_t need_recv_len = recv_client_data_len(sockfd);
		if (need_recv_len > 0 && need_recv_len < MAX_ALLOC_ONCE_LEN)
		{
			recv_ptr = (char*)realloc(recv_ptr, recv_len_total + need_recv_len);
			if (recv_ptr)
			{
				/* dailei:防止recv_len为0时，后面跟一串乱码 */
				memset(recv_ptr + recv_len_total, 0, need_recv_len);
				recv_len = recv(sockfd, recv_ptr + recv_len_total, need_recv_len, 0);
				if (recv_len > 0)
				{
					recv_len_total += recv_len;
				}
				else
				{
					free(recv_ptr);
					recv_ptr = NULL;
				}
			}
		}
    }
    *len = recv_len_total;
    return (void*)recv_ptr;
}

void handle_request(ctrl_request_t *request)
{
	MY_DEBUG_INFO("handle_request\n");
	if (request->data_size >= 2 && strncmp((const char*)request->data, "ts", 2) == 0)
	{
		MY_DEBUG_INFO("get test\n");
		/* send back */
		send(request->client_fd, "world", 5, 0);
		return;
	}
	else if (request->data_size >= 4 && strncmp((const char*)request->data, "json", 4) == 0)
	{
		MY_DEBUG_INFO("get jsonreq\n");
		cJSON *jsonreq = new_vpn_jsonreq(request);
		if (jsonreq)
		{
			MY_DEBUG_INFO("handle jsonreq\n");
			handle_vpn_jsonreq(jsonreq, request);
			delete_vpn_jsonreq(jsonreq);
		}
		return;
	}
	system("vppnconfig saveconfig vppn");
	return;
}

ctrl_request_t *new_request()
{
	ctrl_request_t*		req = NULL;
	req = (ctrl_request_t*)malloc(sizeof(ctrl_request_t));
	if (req)
	{
		bzero(req, sizeof(ctrl_request_t));
	}
	return req;
}

void delete_request(ctrl_request_t *req)
{
	if (req)
	{
		if (req->data)
		{
			free(req->data);
		}
		if (req->client_fd > 0)
		{
			close(req->client_fd);
		}
		free(req);
	}
	return;
}

ctrl_request_t *ctrl_get_request(ctrl_server_t *server, struct timeval *timeout)
{
	ctrl_request_t*		req = NULL;
	int 				client_fd;
	struct sockaddr_in	addr;
	socklen_t addr_len = sizeof(addr);
	fd_set			read_fds;
	int			select_ret;

	/* wait client connect */
	//MY_DEBUG_INFO("select_fd = %d\n", server->listen_fd);
	//MY_DEBUG_INFO("start accept\n");
#if 1
	FD_ZERO(&read_fds);
	FD_SET(server->listen_fd, &read_fds);
	struct timeval select_timeout;
	select_timeout.tv_sec = 3;
	select_timeout.tv_usec = 0;
	//MY_DEBUG_INFO("select_fd = %d\n", server->listen_fd);
	select_ret = select(server->listen_fd + 1, &read_fds, 0, 0, &select_timeout);
	//MY_DEBUG_INFO("select ret = %d\n", select_ret);
#endif
	if (select_ret > 0)
	{
		//MY_DEBUG_INFO("listen_fd = %d\n", server->listen_fd);
		client_fd = accept(server->listen_fd, (struct sockaddr *)&addr, (socklen_t*)&addr_len);
		//MY_DEBUG_INFO("client_fd = %d\n", client_fd);
		if (client_fd >= 0)
		{
			void*	data;
			int 	data_len;
			data = recv_client_data(client_fd, &data_len);
			MY_DEBUG_INFO("recv data :%p len%d\n",data, data_len);
			if (data)
			{
				req = new_request();
				if (req)
				{
					req->data = data;
					req->data_size = data_len;
					req->client_fd = client_fd;
				}
				else
				{
					free(data);
					close(client_fd);
				}
			}
		}
		else
		{
			//if err occur, sleep 1 second, avoiding cpu high load
			sleep(1);
			MY_DEBUG_INFO("accept error code:%d\n", errno);
		}
	}
	return req;
}

void* handle_request_thread(void *arg)
{
	ctrl_request_t *request = (ctrl_request_t *)arg;
	if (request)
	{
		handle_request(request);
		delete_request(request);
	}
	return NULL;
}

void *ctrl_server_mainloop(void *arg)
{
	ctrl_request_t *req;
	ctrl_server_t *serv = (ctrl_server_t *)arg;
	static struct timeval timeout = {5, 0};
	while(ctrl_running)
	{
		req = ctrl_get_request(serv, &timeout);
		//MY_DEBUG_INFO("get req = %p\n", req);
		if (req)
		{
#if 0
			pthread_t handle_tid;
			int ret = pthread_create(&handle_tid, NULL, handle_request_thread, req);
			if(ret < 0)
			{
				MY_DEBUG_ERR("Can't create thread to handle_request\n");
				delete_request(req);
			}
			else
			{
				pthread_detach(handle_tid);
			}
#endif
			handle_request(req);
			delete_request(req);
		}
		usleep(50000);
	}
	pthread_exit(NULL);
	return NULL;
}

static int create_listen_socket(char *host, u_short port)
{
	int listen_fd = -1;
	struct  sockaddr_in     addr;

	listen_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (listen_fd > 0)
	{
		MY_DEBUG_INFO("listen_fd = %d\n", listen_fd);
		int sock_opt = 1;
		if ((setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, (void *) &sock_opt,
			sizeof (sock_opt))) == -1) {
			MY_DEBUG_INFO("set reuse wrong\n");
		}
		MY_DEBUG_INFO("host = %s, port = %d\n", host, port);
		bzero(&addr, sizeof addr);
		addr.sin_family = AF_INET;
		if (!host)
		{
			//addr.sin_addr.s_addr = htonl(INADDR_ANY);
			addr.sin_addr.s_addr = inet_addr("0.0.0.0");
		}
		else
		{
			addr.sin_addr.s_addr = inet_addr(host);
		}
		addr.sin_port = htons((u_short)port);
		int bind_ret = bind(listen_fd, (struct sockaddr *)&addr,sizeof(addr));
		MY_DEBUG_INFO("bind_ret = %d\n", bind_ret);
		if (bind_ret < 0)
		{
			close(listen_fd);
			listen_fd = -1;
		}
		else
		{
			listen(listen_fd, 80);
		}
	}
	return listen_fd;
}

void ctrl_server_delete(ctrl_server_t *serv)
{
	if (serv)
	{
		if (serv->listen_fd > 0)
		{
			close(serv->listen_fd);
		}
		free(serv);
	}
	return;
}

ctrl_server_t * ctrl_server_create(char *host, u_short port)
{
	ctrl_server_t* 			ret = NULL;
	int 					listen_fd = -1;

	listen_fd = create_listen_socket(host, port);
	if (listen_fd > 0)
	{
		ret = (ctrl_server_t*)malloc(sizeof(ctrl_server_t));
		if (ret)
		{
			bzero(ret, sizeof(ctrl_server_t));
			ret->listen_fd = listen_fd;
		}
	}
	return ret;
}

struct ctrl_addr_s
{
	char *host;
	u_short port;
};
ctrl_server_t *ctrl_server;

int ctrl_server_init(char *host, u_short port)
{
	int ret = -1;
	struct ctrl_addr_s *addr = (struct ctrl_addr_s*)malloc(sizeof(struct ctrl_addr_s));
	addr->host = host?host:NULL;
	addr->port = port;
	ctrl_server = ctrl_server_create(addr->host, addr->port);
	if (ctrl_server)
	{
		MY_DEBUG_INFO("create server ok\n");
		pthread_create(&ctrl_server->loop_tid, NULL, ctrl_server_mainloop, ctrl_server);
		ret = 0;
	}
	return ret;
}

void ctrl_server_exit()
{
	if (ctrl_server)
	{
		ctrl_running = 0;
		MY_DEBUG_ERR("wait ctrl-server with pthread id[%d] to exit\n", ctrl_server->loop_tid);
		if (ctrl_server->loop_tid > 0)
		{
			pthread_join(ctrl_server->loop_tid, NULL);
		}
		MY_DEBUG_ERR("close ctrl-server listen socket[%d]\n", ctrl_server->listen_fd);
		if (ctrl_server->listen_fd)
		{
			close(ctrl_server->listen_fd);
		}
		free(ctrl_server);
	}
	return;
}
