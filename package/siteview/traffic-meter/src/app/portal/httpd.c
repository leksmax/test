
/*
 * 本文件主要为实现http/https服务器
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <evhtp.h>
#include "httpd.h"
#include "ipfw.h"
#include "log.h"


/* 发送静态页面 */
void http_send_static_page(evhtp_request_t *req, char *name)
{
    int fd;
    struct stat st;
    char filepath[128] = {0};
    
    snprintf(filepath, sizeof(filepath), "/%s/%s", CONFIG_PATH, name);

    if((fd = open(filepath, O_RDONLY)) == -1)
    {
        /* 文件打开失败 */    
        log_error("open: %s", strerror(errno));
        goto err;
    }

    if (fstat(fd, &st) < 0) 
    {
        /* 获取文件信息失败 */
        log_error("fstat: %s", strerror(errno));
        goto err;
    }

    evbuffer_add_file(req->buffer_out, fd, 0, st.st_size);
    evhtp_headers_add_header(req->headers_out, evhtp_header_new("Content-Type", "text/html", 0, 0));
    evhtp_headers_add_header(req->headers_out, evhtp_header_new("Connection", "close", 0, 0));
    evhtp_send_reply(req, EVHTP_RES_OK);

    return;
    
err:
    if(fd > 0)
    {
        close(fd);
    }
}

/*释放链表*/
void destory_list()
{
	struct list_head *pos, *n;
	struct user_ip_list *new;

	list_for_each_safe(pos, n, g_user_list){
		//delete node
       	list_del(pos);
       	new = list_entry(pos, struct user_ip_list, list);
       	//free node
	   	free(new);
	}
	return ;

}

/*判断链表是否在链表中*/
int is_ip_exist_list(unsigned int in_ip)
{
	struct list_head *pos;
	list_for_each(pos, g_user_list) {
		struct user_ip_list *new = list_entry(pos,
			struct user_ip_list, list);
		if (new->inIp == in_ip)
			return 1;
	}
	return 0;
}

/*将ip添加到链表中*/
void add_ip_to_list(unsigned int in_ip)
{
	struct user_ip_list *new = (struct user_ip_list *) malloc(sizeof(struct user_ip_list)) ;

	if(new != NULL)
	{
		new->inIp = in_ip;

		list_add(&new->list, g_user_list);
	}

	return ;
}

/* 发送流量限制提示页面 */
void http_limit_traffic_page(evhtp_request_t *req)
{
	unsigned int in_ip = 0;
	char user_ip[16] = {0};	
	struct sockaddr_in *sin = NULL;
	
	sin = (struct sockaddr_in *)req->conn->saddr;
	evutil_inet_ntop(AF_INET, &sin->sin_addr, user_ip, sizeof(user_ip));

	in_ip = inet_addr(user_ip);
	
	//log_error("in_ip = 0x%x, %d\n", in_ip, is_ip_exist_list(in_ip));
	if(is_ip_exist_list(in_ip) == 0) 
	    http_send_static_page(req, LIMIT_TRAFFIC_HTML);
	
	return;	
}

/* 发送防火墙禁止上网提示页面 */
void http_limit_firewall_block_page(evhtp_request_t *req)
{
    http_send_static_page(req, LIMIT_FIREWALL_HTML);
}

void http_callback_redirect(evhtp_request_t *request, void *arg)
{ 
	unsigned int in_ip = 0;
	char user_ip[16] = {0};	
	struct sockaddr_in *sin = NULL;
	
	sin = (struct sockaddr_in *)request->conn->saddr;
	evutil_inet_ntop(AF_INET, &sin->sin_addr, user_ip, sizeof(user_ip));

	in_ip = inet_addr(user_ip);

	//log_error("in_ip = 0x%x, %d\n", in_ip, is_ip_exist_list(in_ip));
	if(is_ip_exist_list(in_ip) == 0) 
	{
		// 不存在就跳转，添加到链表中		
		add_ip_to_list(in_ip);
	}
	
	evhtp_headers_add_header(request->headers_out, evhtp_header_new("Content-Type", "text/html", 0, 0));    
    evhtp_headers_add_header(request->headers_out, evhtp_header_new("Connection", "close", 0, 0));	
	
    evhtp_send_reply(request, EVHTP_RES_OK);   
    evhtp_request_free(request);


	/*删除用户对应的规则*/
	if(forbid_internet == 0)
		ipfw_allow_user(user_ip);
	//system("/lib/traffic/traffic_meter.script deldnat");
}

void http_callback_404(evhtp_request_t *request, void *arg)
{
	http_limit_traffic_page(request);

    evhtp_request_free(request);
}

/* http服务器初始化 */
evhtp_t *http_server_init(evbase_t *evbase, int port)
{
    int ret = 0;
    evhtp_t *evhtp = NULL;

    evhtp = evhtp_new(evbase, NULL);
    if(!evhtp)
    {
        log_error("create http evhtp failed!");
        return NULL;
    }

    /* 可重用套接字 */
    evhtp_enable_flag(evhtp, EVHTP_FLAG_ENABLE_REUSEPORT);

    /* http服务器接口回调 */
    evhtp_set_cb(evhtp, "/redirect_html", http_callback_redirect, NULL);
    evhtp_set_gencb(evhtp, http_callback_404, NULL);
    
    ret = evhtp_bind_socket(evhtp, "0.0.0.0", port, 1024);
    if (ret < 0)
    {
        log_error("Could not bind socket");
        exit(-1);
    }

    return evhtp;
}

int httpd_server_loop(int gw_port)
{
    evhtp_t *evhtp = NULL;
    evbase_t *evbase = NULL;
    
	evbase = event_base_new();
    if(!evbase)
    {
        log_error("create event base new failed!\n");
        return -1;
    }
    
    evhtp = http_server_init(evbase, gw_port);
    event_base_loop(evbase, 0);
    
    evhtp_unbind_socket(evhtp);

    if(evhtp)
        evhtp_free(evhtp);
    
    if(evbase)
        event_base_free(evbase);

    return 0;
}

void show_usage(char *name)
{
	fprintf(stderr, "%s \n"
		"	-p PORT, server port\n"
		"	-r IPADDR, route gw address\n"
		"	-f, close daemon\n"
		"	-F, jump forbid internet html\n"
 		"	-h, print this help\n",
		name);
}

/* 守护进程 */
static void daemon_init()
{
    pid_t pid;

    if(getppid() == 1)
    {
        return;
    }
    
    pid = fork();
    if(pid < 0)
    {
        exit(EXIT_FAILURE);
    }
    else if(pid > 0)
    {
        exit(EXIT_SUCCESS);
    }

    umask(0);
    
    if ((setsid()) < 0)
    {
        exit(EXIT_FAILURE);    
    }
    
    if ((chdir("/www/")) < 0) 
    {
        exit(EXIT_FAILURE);
    }

    freopen("/dev/null", "r", stdin);
    freopen("/dev/null", "w", stdout);
    freopen("/dev/null", "w", stderr); 
}


void sig_exit()
{    
	destory_list();
	ipfw_destroy();
    exit(0);
}

void signal_init()
{
    struct sigaction sa;

    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    sigaddset(&sa.sa_mask, SIGTERM);
    sigaddset(&sa.sa_mask, SIGINT);

    sa.sa_handler = sig_exit;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
}

int main(int argc, char *argv[])
{
	int ch = 0;
	int daemon_ = 1;
	int gw_port = DEFULT_HTTPD_PORT;
	char *gw_address = "192.168.1.1";

	while((ch = getopt(argc, argv, "fhp:r:F")) != -1)
	{
		switch(ch)
		{
			case 'f':
				daemon_ = 0;
				break;
			case 'p':
				gw_port = atoi(optarg);
				break;
			case 'r':
				gw_address = optarg;
				break;
			case 'F':
				forbid_internet = 1;
				break;
			case 'h':
				show_usage(argv[0]);
				exit(0);
			default:
				exit(-1);
		}
	}

	if(daemon_ == 1)
		daemon_init();

	signal_init();

	INIT_LIST_HEAD(g_user_list);
	
	ipfw_init(gw_address, gw_port);

 	httpd_server_loop(gw_port);

	return 0;
}
