
#ifndef __HTTPD_H_
#define __HTTPD_H_

#include "list.h"

#define HTTPD_THREAD_NUM 		4
#define HTTPD_SERVER_NAME 		"Portal Server 1.0"
#define DEFULT_HTTPD_PORT 		8086

#define LIMIT_TRAFFIC_HTML 		"limit-traffic.html"
#define LIMIT_FIREWALL_HTML		"limit-firewall.html"
#define CONFIG_PATH				"/etc/portal"


int forbid_internet = 0;

static struct list_head user_list;
struct list_head *g_user_list = &user_list;

struct user_ip_list{
	struct list_head list;
	unsigned int inIp;
};

int httpd_server_loop(int gw_port);

#endif
