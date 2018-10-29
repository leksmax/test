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

#define VPN_DEBUG_SERVER_PORT 7689
#define PEERS_FILE "/etc/site/vppn0_peers.conf"

// 建立我们刚刚说的需要监听的事件，这些事件类型是libev提供的
// with the name ev_TYPE
//ev_io和ev_timer最为常用，ev_io为监听控制台输入，ev_timer为时间事件

ev_io 	socket_watcher;

// 以下为自定义的回调函数，当触发监听事件时，调用执行对应的函数
// 时间事件的自定义回调函数，可定时触发

static void udp_server_cb(struct ev_loop *main_loop, ev_io* watcher, int e)
{
	char buf[1024];
	ssize_t recv_len;

	struct sockaddr_in src;
	socklen_t len = sizeof(src);
	memset(buf, 0, sizeof(buf));
	recv_len = recvfrom(watcher->fd, buf, sizeof(buf) - 1, 0, (struct sockaddr*)&src, &len);
	if (recv_len > 0 && recv_len < (ssize_t)(sizeof(buf) - 1))
	{
		printf("%s", buf);
	}
	return;
}

int main (void)
{
	//定义默认的 event loop，它就像一个大容器，可以装载着很多事件不停运行
	//daemon(1, 0);
	struct ev_loop *loop = EV_DEFAULT;

	int server_fd = create_udp_server(VPN_DEBUG_SERVER_PORT);

	ev_io_init(&socket_watcher, udp_server_cb, server_fd, EV_READ);
	ev_io_start(loop, &socket_watcher);

	// 初始化ev_timer事件监控，设置它的回调函数，间隔时间，是否重复
	//ev_timer_init (&timeout_watcher, timeout_cb, 5.5, 15.0);
	//将ev_timer事件放到event loop里面运行
	//ev_timer_start (loop, &timeout_watcher);
	// 将我们的大容器event loop整体运行起来
	ev_run (loop, 0);
	// ev_run运行结束之后，才会运行到这里

	delete_udp_server(server_fd);

	return 0;
}
