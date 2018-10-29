#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <net/route.h>
#include <net/if.h>
#include <linux/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <strings.h>
#include <string.h>
#include <stdlib.h>
#include <netdb.h>
#include <arpa/inet.h>
#include "cJSON.h"

#define PACKET_SIZE (4096)
#define MAX_ALLOC_LEN (4096)

#ifndef FREE_PTR
#define FREE_PTR(ptr) do{if (ptr) {free((ptr)); (ptr)=NULL;}}while(0);
#endif

int get_if_addr(char *if_name, struct sockaddr *sock)
{
	int ret = -1; 
	struct ifreq ifr;
	struct sockaddr ip_addr;
	memset(&ip_addr, 0, sizeof(struct sockaddr));
	ifr.ifr_addr.sa_family = AF_INET;
	strcpy(ifr.ifr_name, if_name);
	int sockfd = socket(AF_INET, SOCK_DGRAM, 0); 
	if (ioctl(sockfd, SIOCGIFADDR, &ifr) == 0) {
		memcpy(sock, &ifr.ifr_addr, sizeof(struct sockaddr));
		ret = 0;
		close(sockfd);
	}   
	return ret;
}

int net_tool_get_if_ip(char *if_name, char *buf)
{
	int ret = -1; 
	struct sockaddr ip_addr;
	struct sockaddr_in *ptr = (struct sockaddr_in *)&ip_addr;
	ret = get_if_addr(if_name, &ip_addr);
	if (ret == 0)
	{
		inet_ntop(AF_INET, &ptr->sin_addr, buf, 20);
	}
	return ret;
}

int net_tool_get_if_hwaddr(char *if_name, char *buf)
{
	int ret = -1; 
	struct ifreq ifr;
	struct sockaddr ip_addr;
	memset(&ip_addr, 0, sizeof(struct sockaddr));
	ifr.ifr_addr.sa_family = AF_INET;
	strcpy(ifr.ifr_name, if_name);
	int sockfd = socket(AF_INET, SOCK_DGRAM, 0); 
	if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) == 0) {
		int i;
		for(i = 0; i < 6; i++)
		{
			sprintf(buf + 2*i, "%02x", (unsigned char)ifr.ifr_hwaddr.sa_data[i]);
		}
		ret = 0;
		close(sockfd);
	}
	return ret;
}

unsigned short cal_chksum(unsigned short *addr, int len)
{
    int nleft=len;
    int sum=0;
    unsigned short *w=addr;
    unsigned short answer=0;
    while(nleft > 1)
    {   
        sum += *w++;
        nleft -= 2;
    }   

    if( nleft == 1)
    {   
        *(unsigned char *)(&answer) = *(unsigned char *)w;
        sum += answer;
    }   

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;
    return answer;
}

//return ms
double cal_time_interval(struct timeval *old_time, struct timeval *now_time)
{
    unsigned long long interval_msec_int = 0;
    unsigned long long interval_msec_dot = 0;
    double used_time = 0;
    char buf[20];
    if (now_time->tv_usec < old_time->tv_usec)
    {   
        interval_msec_int = (now_time->tv_sec - old_time->tv_sec - 1) * 1000;
        interval_msec_int += ((now_time->tv_usec + 1000000) - old_time->tv_usec)/1000;
        interval_msec_dot = (((now_time->tv_usec + 1000000) - old_time->tv_usec))%1000;
    }
    else
    {
        interval_msec_int = (now_time->tv_sec - old_time->tv_sec) * 1000;
        interval_msec_int += ((now_time->tv_usec) - old_time->tv_usec)/1000;
        interval_msec_dot = (((now_time->tv_usec) - old_time->tv_usec))%1000;
    }
    sprintf(buf, "%llu.%llu", interval_msec_int, interval_msec_dot);
    used_time = atof(buf);
    return used_time;
}

// Ping函数
double ping(struct in_addr *dstip, int timeout)
{
	struct timeval *tval;
	int maxfds = 0;
	fd_set readfds;
	double used_time = 0;

	struct sockaddr_in addr;
	struct sockaddr_in from;
	// 设定Ip信息
	bzero(&addr,sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = dstip->s_addr;

	int sockfd;
	// 取得socket
	sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (sockfd > 0)
	{
		struct timeval timeo;
		// 设定TimeOut时间
		timeo.tv_sec = timeout;
		timeo.tv_usec = 0;

		if (setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeo, sizeof(timeo)) == 0)
		{
			char sendpacket[PACKET_SIZE];
			char recvpacket[PACKET_SIZE];
			// 设定Ping包
			memset(sendpacket, 0, sizeof(sendpacket));

			pid_t pid;
			// 取得PID，作为Ping的Sequence ID
			pid=getpid();

			struct ip *iph;
			struct icmp *icmp;

			icmp=(struct icmp*)sendpacket;
			icmp->icmp_type=ICMP_ECHO;  //回显请求
			icmp->icmp_code=0;
			icmp->icmp_cksum=0;
			icmp->icmp_seq=0;
			icmp->icmp_id=pid;
			tval= (struct timeval *)icmp->icmp_data;
			gettimeofday(tval,NULL);
			icmp->icmp_cksum=cal_chksum((unsigned short *)icmp,sizeof(struct icmp));  //校验

			int n;
			// 发包
			int i;
			for(i = 0; i < 5; i++)
			{
				n = sendto(sockfd, (char *)&sendpacket, sizeof(struct icmp), 0, (struct sockaddr *)&addr, sizeof(addr));
			}
			if (n > 0)
			{
				// 接受
				// 由于可能接受到其他Ping的应答消息，所以这里要用循环
				while(1)
				{
					// 设定TimeOut时间，这次才是真正起作用的
					FD_ZERO(&readfds);
					FD_SET(sockfd, &readfds);
					maxfds = sockfd + 1;
					n = select(maxfds, &readfds, NULL, NULL, &timeo);
					if (n > 0 && FD_ISSET(sockfd, &readfds))
					{
						// 接受
						memset(recvpacket, 0, sizeof(recvpacket));
						int fromlen = sizeof(from);
						n = recvfrom(sockfd, recvpacket, sizeof(recvpacket), 0, (struct sockaddr *)&from, (socklen_t *)&fromlen);
						if (n > 1)
						{
							struct timeval *pkt_tv;
							struct timeval now_tv;
							gettimeofday(&now_tv, NULL);
							pkt_tv = (struct timeval *)icmp->icmp_data;
							// 判断是否是自己Ping的回复
							if (from.sin_addr.s_addr == dstip->s_addr)
							{
								iph = (struct ip *)recvpacket;
								icmp=(struct icmp *)(recvpacket + (iph->ip_hl<<2));

								// 判断Ping回复包的状态     
								if (icmp->icmp_type == ICMP_ECHOREPLY && icmp->icmp_id == pid)   //ICMP_ECHOREPLY回显应答
								{    
									// 正常就退出循环
									used_time = cal_time_interval(pkt_tv, &now_tv);
									break;
								}
							}
						}
						else
						{
							break;
						}
					}
					else
					{
						break;
					}
				}
			}
		}
		close(sockfd);
	}
	return used_time;
}

double net_tool_ping_host(const char* host, int timeout)
{
	double used_time = 0;
	struct hostent *he = gethostbyname(host);
	if (he && he->h_addrtype == AF_INET)
	{   
		used_time = ping((struct in_addr *)he->h_addr, timeout);
	}   
	else
	{   
		printf("Can't get host of %s\n", host);
	}   
	return used_time;
}


#define ROUTE_FILE "/proc/net/route"

struct route_info
{
	char interface_buf[20];
	char dst_buf[20];
	char gw_buf[20];
	char flags_buf[20];
	char ref_buf[20];
	char use_buf[20];
	char metric_buf[20];
	char mask_buf[20];
	char mtu_buf[20];
	char window_buf[20];
	struct route_info *next;
};

void dump_route(struct route_info *route)
{
	struct route_info *cur = route;
	printf("cur:%p\tnext:%p\ndst: %s\tgw:%s\tmask:%s\n", cur, cur->next, cur->dst_buf, cur->gw_buf, cur->mask_buf);
}

int check_route_if(struct route_info *one_route, char *if_name)
{
	int ret = 0;
	if (strcmp(one_route->interface_buf, if_name) == 0)
	{
		ret = 1;
	}
	return ret;
}

void get_route_info(char *buf, struct route_info *one_route)
{
	char *token = NULL;
	char *save_ptr1 = NULL;
	memset(one_route, 0, sizeof(struct route_info));
	token = strtok_r(buf, "\t", &save_ptr1);
	int i = 0;
	while(token)
	{
		switch (i)
		{
			case 0:
				strcpy(one_route->interface_buf, token);
				break;
			case 1:
				strcpy(one_route->dst_buf, token);
				break;
			case 2:
				strcpy(one_route->gw_buf, token);
				break;
			case 3:
				strcpy(one_route->flags_buf, token);
				break;
			case 4:
				strcpy(one_route->ref_buf, token);
				break;
			case 5:
				strcpy(one_route->use_buf, token);
				break;
			case 6:
				strcpy(one_route->metric_buf, token);
				break;
			case 7:
				strcpy(one_route->mask_buf, token);
				break;
			case 8:
				strcpy(one_route->mtu_buf, token);
				break;
			case 9:
				strcpy(one_route->window_buf, token);
				break;
			//case 10:
				//strcpy(one_route->irtt_buf, token);
				//break;
			default:
				break;
		}
		i++;
		token = strtok_r(NULL, "\t", &save_ptr1);
	}
	return;
}

struct route_info *get_route_list()
{
	char line_buf[1000];
	FILE *file = fopen(ROUTE_FILE, "r");
	struct route_info *ret = NULL;
	if (file)
	{
		memset(line_buf, 0, sizeof(line_buf));
		//skip 1st line
		fgets(line_buf, sizeof(line_buf),file);
		struct route_info *tmp = NULL;
		while(fgets(line_buf, sizeof(line_buf), file))
		{
			struct route_info *one_route = malloc(sizeof(struct route_info));
			get_route_info(line_buf, one_route);
			/* tmp == NULL, then find first node */
			if (tmp == NULL)
			{
				ret = one_route;
			}
			else
			{
				tmp->next = one_route;
			}
			//dump_route(one_route);
			tmp = one_route;
		}
		fclose(file);
	}
	return ret;
}

void free_route_list(struct route_info *first_route)
{
	struct route_info *cur = first_route;
	while(cur)
	{
		struct route_info *tmp = cur;
		cur = cur->next;
		free(tmp);
	}
	return;
}

struct sockaddr get_sockaddr(char *buf)
{
	char *endptr;
	struct sockaddr addr;
	long long int number = 0;
	struct sockaddr_in *ipv4_addr = (struct sockaddr_in *)&addr;
	ipv4_addr->sin_family = AF_INET;
	ipv4_addr->sin_port = 0;
	number = strtoll(buf, &endptr, 16);
   	ipv4_addr->sin_addr.s_addr = (in_addr_t)number;
	return addr;
}

void del_one_route(struct route_info *one_route)
{
	struct rtentry rt;
	memset((char *) &rt, 0, sizeof(struct rtentry));
	rt.rt_flags = (unsigned short)atoi(one_route->flags_buf);
	rt.rt_dev = one_route->interface_buf;
	rt.rt_gateway = get_sockaddr(one_route->gw_buf);
	rt.rt_genmask = get_sockaddr(one_route->mask_buf);
	rt.rt_dst = get_sockaddr(one_route->dst_buf);
	int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd > 0)
	{
		ioctl(sockfd, SIOCDELRT, &rt);
		close(sockfd);
	}
	return;
}

void add_one_route(struct route_info *one_route)
{
	struct rtentry rt;
	memset((char *) &rt, 0, sizeof(struct rtentry));
	rt.rt_flags = (unsigned short)atoi(one_route->flags_buf);
	rt.rt_dev = one_route->interface_buf;
	rt.rt_gateway = get_sockaddr(one_route->gw_buf);
	rt.rt_genmask = get_sockaddr(one_route->mask_buf);
	rt.rt_dst = get_sockaddr(one_route->dst_buf);
	int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd > 0)
	{
		ioctl(sockfd, SIOCADDRT, &rt);
		close(sockfd);
	}
	return;
}

int net_tool_get_if_addr(char *if_name, struct sockaddr *sock)
{
	int ret = -1;
	struct ifreq ifr;
	struct sockaddr ip_addr;
	memset(&ip_addr, 0, sizeof(struct sockaddr));
	ifr.ifr_addr.sa_family = AF_INET;
	strcpy(ifr.ifr_name, if_name);
	int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (ioctl(sockfd, SIOCGIFADDR, &ifr) == 0) {
		memcpy(sock, &ifr.ifr_addr, sizeof(struct sockaddr));
		ret = 0;
		close(sockfd);
	}
	return ret;
}

int route_need_delete(struct route_info *one_route, char *if_name, struct sockaddr *if_addr)
{
	int ret = 0;
	if (strcmp(one_route->interface_buf, if_name) == 0)
	{
		/* check further, avoid deleting the if_name's default route */
		struct sockaddr route_dst;
		struct sockaddr route_mask;
		route_dst = get_sockaddr(one_route->dst_buf);
		route_mask = get_sockaddr(one_route->mask_buf);
		struct sockaddr_in *in_route_dst  = (struct sockaddr_in *)&route_dst;
		struct sockaddr_in *in_route_mask = (struct sockaddr_in *)&route_mask;
		struct sockaddr_in *in_if_addr 	  = (struct sockaddr_in *)if_addr;
		if ((in_route_dst->sin_addr.s_addr & in_route_mask->sin_addr.s_addr) != 
				(in_if_addr->sin_addr.s_addr & in_route_mask->sin_addr.s_addr))
		{
			ret = 1;
		}
	}
	return ret;
}

void del_routes_by_if(struct route_info *first_route, char *dev)
{
	struct route_info *cur = first_route;
	struct sockaddr addr;
	memset(&addr, 0, sizeof(struct sockaddr));
	int ret = net_tool_get_if_addr(dev, &addr);
	if (ret == 0)
	{
		while(cur)
		{
			if (route_need_delete(cur, dev, &addr))
			{
				del_one_route(cur);
			}
			cur = cur->next;
		}
	}
	return;
}

void dump_route_list(struct route_info *first_route)
{
	struct route_info *cur = first_route;
	while(cur)
	{
		dump_route(cur);
		cur = cur->next;
	}
}

/* delete all routes that added by dnsmasq */
void net_tool_reset_routes(char *dev)
{
	struct route_info *route_list = get_route_list();
	if (route_list)
	{
		//dump_route_list(route_list);
		del_routes_by_if(route_list, dev);
		free_route_list(route_list);
	}
}

char *recv_data(int sockfd, int *len)
{
	ssize_t recv_len = 0;
	ssize_t recv_len_total = 0;
	char *recv_ptr = NULL;
	if (sockfd > 0)
	{
		while(1)
		{
			recv_ptr = realloc(recv_ptr, recv_len_total + MAX_ALLOC_LEN);
			if (recv_ptr)
			{
				/* dailei:防止recv_len为0时，后面跟一串乱码 */
				memset(recv_ptr + recv_len_total, 0, MAX_ALLOC_LEN);
				recv_len = recv(sockfd, recv_ptr + recv_len_total, MAX_ALLOC_LEN, 0);
				if (recv_len > 0)
				{
					recv_len_total += recv_len;
				}
				else if(recv_len == 0)
				{
					break;
				}
				else
				{
					FREE_PTR(recv_ptr);
					break;
				}
			}
		}
	}
	*len = recv_len_total;
	return recv_ptr;
}

char *net_tool_tcp_client(char *host, int port, char *send_buf, int send_len, int *recv_len)
{
	char *web = NULL;
	struct hostent *he;    /* structure that will get information about remote host */
	struct sockaddr_in server;
	int send_num;
	int sockfd;
	int ret;
	if((he=gethostbyname(host)))
	{   
		sockfd=socket(AF_INET,SOCK_STREAM, 0); 
		struct timeval timeout = {8, 0}; 
		setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout));
		setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));
		if(sockfd >= 0)
		{ 
			bzero(&server,sizeof(server));
			server.sin_family = AF_INET;
			server.sin_port = htons(port);
			server.sin_addr = *((struct in_addr *)he->h_addr);
			ret = connect(sockfd, (struct sockaddr *)&server, sizeof(server));
			if(ret >= 0)
			{   
				send_num = send(sockfd, send_buf, send_len, 0); 
				if (send_num > 0)
				{
					web = recv_data(sockfd, recv_len);
				}
			}
			close(sockfd);
		}
	} 
	return web;
}

cJSON *net_tool_tcp_json_client(char *host, int port, cJSON *req)
{
	cJSON *ret = NULL;
	char *str_req = cJSON_Print(req);
	if (str_req)
	{
		int recv_len = 0;
		char *response = net_tool_tcp_client(host, port, str_req, strlen(str_req) + 1, &recv_len);
		if (response && recv_len > 0)
		{
			ret = cJSON_Parse(response);
		}
		free(str_req);
	}
	return ret;
}

char *net_tool_http_client(char *host, int port, char *uri, char *body, int *recv_len)
{
	char *ret = NULL;
	char *web_head = "POST %s HTTP/1.1\r\n"
		"Host: %s\r\n"
		"User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:35.0) Gecko/20100101 Firefox/35.0\r\n"
		"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
		"Accept-Language: en-US,en;q=0.5\r\n"
		"Content-Type: application/json; charset=UTF-8\r\n"
		"Content-Length: %d\r\n"
		"Connection: close\r\n"
		"Pragma: no-cache\r\n"
		"Cache-Control: no-cache\r\n\r\n";

	char head_buf[1000];
	sprintf(head_buf, web_head, uri, host, strlen(body));

	int total_len = strlen(head_buf) + strlen(body) + 1;
	char *send_buf = malloc(total_len);
	if (send_buf)
	{
		strcpy(send_buf, head_buf);
		strcat(send_buf, body);
		send_buf[total_len - 1] = 0;
		ret = net_tool_tcp_client(host, port, send_buf, strlen(send_buf), recv_len);
		free(send_buf);
	}
	return ret;
}

char *net_tool_http_client_raw(char *host, int port, char *uri, void *body, int body_len, int *recv_len)
{
	char *ret = NULL;
	char *web_head = "POST %s HTTP/1.1\r\n"
		"Host: %s\r\n"
		"User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:35.0) Gecko/20100101 Firefox/35.0\r\n"
		"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
		"Accept-Language: en-US,en;q=0.5\r\n"
		"Content-Type: application/json; charset=UTF-8\r\n"
		"Content-Length: %d\r\n"
		"Content-Encoding: gzip\r\n"
		"Connection: close\r\n"
		"Pragma: no-cache\r\n"
		"Cache-Control: no-cache\r\n\r\n";

	char head_buf[1000];
	sprintf(head_buf, web_head, uri, host, body_len);

	int total_len = strlen(head_buf) + body_len + 1;
	char *send_buf = malloc(total_len);
	if (send_buf)
	{
		strcpy(send_buf, head_buf);
		memcpy(send_buf + strlen(head_buf), body, body_len);
		send_buf[total_len - 1] = 0;
		ret = net_tool_tcp_client(host, port, send_buf, total_len - 1, recv_len);
		free(send_buf);
	}
	return ret;
}

cJSON *net_tool_http_json_client(char *host, int port, char *uri, cJSON *req)
{
	cJSON *ret = NULL;
	char *str_req = cJSON_Print(req);
	if (str_req)
	{
		int recv_len = 0;
		char *response = net_tool_http_client(host, port, uri, str_req, &recv_len);
		if (response && recv_len > 0)
		{
			/* find \r\n\r\n or \n\n */
			char *ptr = strstr(response, "\r\n\r\n");
			if (ptr)
			{
				ptr += 4;
			}
			else
			{
				ptr = strstr(response, "\n\n");
				if (ptr)
				{
					ptr += 2;
				}
			}
			if (ptr)
			{
				ret = cJSON_Parse(ptr);
			}
			free(response);
		}
		free(str_req);
	}
	return ret;
}
