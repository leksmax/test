#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ev.h>
#include "file_tool.h"
#include "my-device.h"
#include "net_tool.h"
#include "cJSON.h"
#include "str_tool.h"
#include "udp_tool.h"

#define SWAP_PORT 8654
#define PEERS_FILE "/etc/site/vppn0_peers.conf"

// 建立我们刚刚说的需要监听的事件，这些事件类型是libev提供的
// with the name ev_TYPE
//ev_io和ev_timer最为常用，ev_io为监听控制台输入，ev_timer为时间事件

ev_timer timeout_watcher;
ev_io 	socket_watcher;

// 以下为自定义的回调函数，当触发监听事件时，调用执行对应的函数
// 时间事件的自定义回调函数，可定时触发

static void send_udp_data(int sock, char* buf, size_t buf_len, char* peer)
{
	struct sockaddr_in peer_addr;
	socklen_t peer_len = sizeof(peer_addr);
	memset(&peer_addr, 0, sizeof(peer_addr));
	peer_addr.sin_family = AF_INET;
	peer_addr.sin_addr.s_addr = inet_addr(peer);
	peer_addr.sin_port = htons(SWAP_PORT);
	//printf("sendto <%s>: %s", peer, buf);
	sendto(sock, buf, buf_len, 0, (struct sockaddr*)&peer_addr, peer_len);
}

int subnet_confilict(char* subnet, cJSON* local_subnets)
{
	int ret = 0;
	int cnt = cJSON_GetArraySize(local_subnets);
	int i;
	for(i = 0; i < cnt; i++)
	{
		cJSON* subnet_item = cJSON_GetArrayItem(local_subnets, i);
		cJSON* lan_subnet_item = cJSON_GetObjectItem(subnet_item, "lan_subnet");
		if (lan_subnet_item)
		{
			if (strcmp(subnet, lan_subnet_item->valuestring) == 0)
			{
				ret = 1;
				break;
			}
		}
	}
	return ret;
}

static void handle_recv_udp_data(char* buf, ssize_t buf_len, cJSON* local_subnets)
{
	char* sep = strchr(buf, ' ');
	if (sep)
	{
		char* gw = buf;
		char* subnet = sep + 1;
		*sep = 0;
		str_tool_replaceAll(subnet, '\n', '\0');
		if (subnet_confilict(subnet, local_subnets) == 0)
		{
			add_route_gw_by_cmd(subnet, gw);
		}
	}
}

static void udp_server_cb(struct ev_loop *main_loop, ev_io* watcher, int e)
{
	char buf[200];
	ssize_t recv_len;

	struct sockaddr_in src;
	socklen_t len = sizeof(src);

	recv_len = recvfrom(watcher->fd, buf, sizeof(buf) - 1, 0, (struct sockaddr*)&src, &len);
	if (recv_len > 0 && recv_len < (ssize_t)(sizeof(buf) - 1))
	{
		cJSON* local_subnets = get_all_lan_subnets();
		if (local_subnets)
		{
			//printf("recvd %d bytes: %s", recv_len, buf);
			buf[recv_len] = 0;
			handle_recv_udp_data(buf, recv_len, local_subnets);
			cJSON_Delete(local_subnets);
		}
	}
	return;
}

static void send_subnet_to_peer(int fd, char* subnet, char* peer, char* myip)
{
	char buf[100];
	sprintf(buf, "%s %s\n", myip, subnet);
	send_udp_data(fd, buf, strlen(buf), peer);
}

static void send_subnets_to_peer(int fd, cJSON* subnets, char* peer, char* myip)
{
	int cnt = cJSON_GetArraySize(subnets);
	int i;
	for(i = 0; i < cnt; i++)
	{
		cJSON* subnet = cJSON_GetArrayItem(subnets, i);
		cJSON* subnet_item = cJSON_GetObjectItem(subnet, "lan_subnet");
		if (subnet_item)
		{
			send_subnet_to_peer(fd, subnet_item->valuestring, peer, myip);
		}
	}
}

static void handle_send_udp_data()
{

	char myip[100] = "unknown";
	int ret = net_tool_get_if_ip((char*)"site0", myip);
	if (ret == 0)
	{
		cJSON* local_subnets = get_all_lan_subnets();
		if (local_subnets)
		{
			int sock = create_udp_client();
			if (sock >= 0)
			{
				cJSON* peers = read_json_from_file((char*)PEERS_FILE);
				if (peers)
				{
					int cnt = cJSON_GetArraySize(peers);
					int i;
					for(i = 0; i < cnt; i++)
					{
						cJSON* peer_item = cJSON_GetArrayItem(peers, i);
						cJSON* peer_vip_item = cJSON_GetObjectItem(peer_item, "peer_vip");
						if (peer_vip_item)
						{
							send_subnets_to_peer(sock, local_subnets, peer_vip_item->valuestring, myip);
						}
					}
					cJSON_Delete(peers);
				}
				delete_udp_client(sock);
			}
			cJSON_Delete(local_subnets);
		}
	}
	return;
}

static void timeout_cb (EV_P_ ev_timer *w, int revents)
{
	//puts ("timeout");
	//关闭最早的一个还在运行的ev_run
	//ev_break (EV_A_ EVBREAK_ONE);
	handle_send_udp_data();
}

int main (void)
{
	//定义默认的 event loop，它就像一个大容器，可以装载着很多事件不停运行
	daemon(1, 0);
	struct ev_loop *loop = EV_DEFAULT;

	int server_fd = create_udp_server(SWAP_PORT);

	ev_io_init(&socket_watcher, udp_server_cb, server_fd, EV_READ);
	ev_io_start(loop, &socket_watcher);

	// 初始化ev_timer事件监控，设置它的回调函数，间隔时间，是否重复
	ev_timer_init (&timeout_watcher, timeout_cb, 5.5, 15.0);
	//将ev_timer事件放到event loop里面运行
	ev_timer_start (loop, &timeout_watcher);
	// 将我们的大容器event loop整体运行起来
	ev_run (loop, 0);
	// ev_run运行结束之后，才会运行到这里

	delete_udp_server(server_fd);

	return 0;
}
