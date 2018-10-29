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
#include "my_debug.h"

#define PACKET_SIZE (200)
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

int get_if_netmask(char *if_name, struct sockaddr *sock)
{
	int ret = -1;
	struct ifreq ifr;
	struct sockaddr ip_addr;
	memset(&ip_addr, 0, sizeof(struct sockaddr));
	ifr.ifr_addr.sa_family = AF_INET;
	strcpy(ifr.ifr_name, if_name);
	int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (ioctl(sockfd, SIOCGIFNETMASK, &ifr) == 0) {
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

int net_tool_get_if_netmask(char *if_name, char *buf)
{
	int ret = -1;
	struct sockaddr ip_addr;
	struct sockaddr_in *ptr = (struct sockaddr_in *)&ip_addr;
	ret = get_if_netmask(if_name, &ip_addr);
	if (ret == 0)
	{
		inet_ntop(AF_INET, &ptr->sin_addr, buf, 20);
	}
	return ret;
}

//void convert_subnet_to_string(struct sockaddr *ip, struct sockaddr *mask, char *ret_buf)
void convert_subnet_to_string(struct in_addr* ip, struct in_addr* mask, char *ret_buf)
{
	struct in_addr *network_part = ip;;
	struct in_addr *mask_in = mask;
	int network_part_len = 0;

	network_part->s_addr = network_part->s_addr & mask_in->s_addr;
	//printf("mask = %08x\n", mask_in->sin_addr.s_addr);
	int i;
	for(i = 0; i < 32; i++)
	{
		unsigned long bit = 1 << i;
		if (mask_in->s_addr & bit)
		{
			network_part_len++;
		}
	}

	inet_ntop(AF_INET, network_part, ret_buf, 20);
	char network_part_len_buf[10];
	sprintf(network_part_len_buf, "/%d", network_part_len);
	strcat(ret_buf, network_part_len_buf);
	return;
}

uint32_t net_tool_netmask_to_num(char *netmask)
{
	uint32_t ret = 0;
	struct in_addr mask_addr;
	inet_aton(netmask, &mask_addr);
	uint32_t temp = ntohl(mask_addr.s_addr);
	while(temp)
	{
		temp = temp & (temp - 1);
		ret++;
	}
	return ret;
}

int net_tool_num_to_netmask(int num, char* out)
{
	int ret = -1;
	out[0] = 0;
	if (num > 0 && num <= 32)
	{
		uint32_t mask_num = 1 << (32 - num);
		mask_num -= 1;
		//printf("mask_num = %08x\n", mask_num);
		mask_num = ~mask_num;
		printf("mask_num = %08x\n", mask_num);
		struct in_addr mask_addr;
		mask_addr.s_addr = htonl(mask_num);
		inet_ntop(AF_INET, &mask_addr, out, 20);
		ret = 0;
	}
	return ret;
}

int net_tool_ip_to_subnet(char *ip, int mask_num, char *out)
{
	int ret = -1;
	out[0] = 0;
	if (mask_num > 0 && mask_num <= 32)
	{
		char mask_buf[100];
		net_tool_num_to_netmask(mask_num, mask_buf);
		struct in_addr ip_addr;
		struct in_addr mask_addr;
		inet_aton(ip, &ip_addr);
		inet_aton(mask_buf, &mask_addr);
		convert_subnet_to_string(&ip_addr, &mask_addr, out);
		ret = 0;
	}
	return ret;
}

int net_tool_get_if_subnet(char *if_name, char *buf)
{
	int ret = -1;
	struct sockaddr ip_addr;
	struct sockaddr mask_addr;
	struct sockaddr_in* ip_addr_ptr = (struct sockaddr_in*)(&ip_addr);
	struct sockaddr_in* mask_addr_ptr = (struct sockaddr_in*)(&mask_addr);
	ret = get_if_netmask(if_name, &mask_addr) || get_if_addr(if_name, &ip_addr);
	if (ret == 0)
	{
		convert_subnet_to_string(&ip_addr_ptr->sin_addr, &mask_addr_ptr->sin_addr, buf);
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

//return us
int cal_time_interval2(struct timeval *old_time, struct timeval *now_time)
{
	int used_time = 0;
	struct timeval intval_time;
	timersub(now_time, old_time, &intval_time);
	used_time = (int)(intval_time.tv_sec * 1000000 + intval_time.tv_usec);
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
			for(i = 0; i < 3; i++)
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

int create_ping_socket()
{
	return socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
}

void send_ping_packets(int fd, cJSON *hosts)
{
	int array_count = cJSON_GetArraySize(hosts);
	int i;
	for(i = 0; i < array_count; i++)
	{
		cJSON *itm = cJSON_GetArrayItem(hosts, i);
		if (itm)
		{
			cJSON *host_item = cJSON_GetObjectItem(itm, "ip");
			if (host_item)
			{
				struct sockaddr_in addr;

				// 设定Ip信息
				bzero(&addr,sizeof(addr));
				addr.sin_family = AF_INET;
				inet_pton(AF_INET, host_item->valuestring, &addr.sin_addr);

				char sendpacket[PACKET_SIZE];
				// 设定Ping包
				memset(sendpacket, 0, sizeof(sendpacket));

				// 取得PID，作为Ping的Sequence ID
				pid_t pid;
				pid=getpid();
				pid += i;

				struct icmp *icmp;

				icmp=(struct icmp*)sendpacket;
				icmp->icmp_type=ICMP_ECHO;  //回显请求
				icmp->icmp_code=0;
				icmp->icmp_cksum=0;
				icmp->icmp_seq=0;
				icmp->icmp_id=pid;
				struct timeval *tval= (struct timeval *)icmp->icmp_data;
				gettimeofday(tval,NULL);
				icmp->icmp_cksum=cal_chksum((unsigned short *)icmp,sizeof(struct icmp));  //校验
				/* send twice */
				int j;
				for(j = 0; j < 1; j++)
				{
					sendto(fd, (char *)&sendpacket, sizeof(struct icmp), 0, (struct sockaddr *)&addr, sizeof(addr));
				}
			}
		}
	}
	return;
}

void send_ping_packets2(int fd, cJSON *hosts, char *ip_name)
{
	int array_count = cJSON_GetArraySize(hosts);
	int i;
	for(i = 0; i < array_count; i++)
	{
		cJSON *itm = cJSON_GetArrayItem(hosts, i);
		if (itm)
		{
			cJSON *host_item = cJSON_GetObjectItem(itm, ip_name);
			if (host_item)
			{
				struct sockaddr_in addr;

				// 设定Ip信息
				bzero(&addr,sizeof(addr));
				addr.sin_family = AF_INET;
				inet_pton(AF_INET, host_item->valuestring, &addr.sin_addr);

				char sendpacket[PACKET_SIZE];
				// 设定Ping包
				memset(sendpacket, 0, sizeof(sendpacket));

				// 取得PID，作为Ping的Sequence ID
				pid_t pid;
				pid=getpid();
				pid += i;

				struct icmp *icmp;

				icmp=(struct icmp*)sendpacket;
				icmp->icmp_type=ICMP_ECHO;  //回显请求
				icmp->icmp_code=0;
				icmp->icmp_cksum=0;
				icmp->icmp_seq=0;
				icmp->icmp_id=pid;
				struct timeval *tval= (struct timeval *)icmp->icmp_data;
				gettimeofday(tval,NULL);
				icmp->icmp_cksum=cal_chksum((unsigned short *)icmp,sizeof(struct icmp));  //校验
				/* send twice */
				int j;
				for(j = 0; j < 1; j++)
				{
					sendto(fd, (char *)&sendpacket, sizeof(struct icmp), 0, (struct sockaddr *)&addr, sizeof(addr));
				}
			}
		}
	}
	return;
}

/* modify logic: add ping */
void send_ping_packets3(int fd, cJSON *hosts, char *ip_name, int cnt)
{
	int array_count = cJSON_GetArraySize(hosts);
	int i;
	// 取得PID，作为Ping的Sequence ID
	pid_t pid;
	pid=getpid();
	for(i = 0; i < array_count; i++)
	{
		cJSON *itm = cJSON_GetArrayItem(hosts, i);
		if (itm)
		{
			cJSON *host_item = cJSON_GetObjectItem(itm, ip_name);
			/* create latency list for each ip, we will use the latency list to cal avg latency */
			if (host_item)
			{
				int k;
				/* ping cnt times at once */
				for(k = 0; k < cnt; k++)
				{
					struct sockaddr_in addr;

					// 设定Ip信息
					bzero(&addr,sizeof(addr));
					addr.sin_family = AF_INET;
					inet_pton(AF_INET, host_item->valuestring, &addr.sin_addr);

					char sendpacket[PACKET_SIZE];
					// 设定Ping包
					memset(sendpacket, 0, sizeof(sendpacket));

					struct icmp *icmp;

					icmp=(struct icmp*)sendpacket;
					icmp->icmp_type=ICMP_ECHO;  //回显请求
					icmp->icmp_code=0;
					icmp->icmp_cksum=0;
					icmp->icmp_seq=k;
					icmp->icmp_id=pid + i;
					struct timeval *tval= (struct timeval *)icmp->icmp_data;
					gettimeofday(tval,NULL);
					icmp->icmp_cksum=cal_chksum((unsigned short *)icmp,sizeof(struct icmp));  //校验
					/* send once */
					int j;
					for(j = 0; j < 1; j++)
					{
						sendto(fd, (char *)&sendpacket, sizeof(struct icmp), 0, (struct sockaddr *)&addr, sizeof(addr));
					}
				}
			}
		}
	}
	return;
}

void set_defaut_latency(cJSON *hosts)
{
	int j;
	int array_count = cJSON_GetArraySize(hosts);
	for(j = 0; j < array_count; j++)
	{
		cJSON *item = cJSON_GetArrayItem(hosts, j);
		if (item)
		{
			cJSON *latency_item = cJSON_GetObjectItem(item, "latency");
			if (!latency_item)
			{
				cJSON_AddNumberToObject(item, "latency", 0);
			}
		}
	}
	return;
}

void set_defaut_latency2(cJSON *hosts, char *latency_name)
{
	int j;
	int array_count = cJSON_GetArraySize(hosts);
	for(j = 0; j < array_count; j++)
	{
		cJSON *item = cJSON_GetArrayItem(hosts, j);
		if (item)
		{
			cJSON *latency_item = cJSON_GetObjectItem(item, latency_name);
			if (!latency_item)
			{
				cJSON_AddNumberToObject(item, latency_name, 0);
			}
		}
	}
	return;
}

void set_defaut_latency3(cJSON* hosts, char* latency_name, char* latency_list_name, char* loss_name, int cnt)
{
	int i;
	int array_count = cJSON_GetArraySize(hosts);
	for(i = 0; i < array_count; i++)
	{
		cJSON *itm = cJSON_GetArrayItem(hosts, i);
		if (itm)
		{
			/* create latency list for each ip, we will use the latency list to cal avg latency */
			cJSON* latency_list = cJSON_CreateArray();
			cJSON_AddNumberToObject(itm, latency_name, 0);
			cJSON_AddNumberToObject(itm, loss_name, 100);
			cJSON_AddItemToObject(itm, latency_list_name, latency_list);
			int latency_i;
			for(latency_i = 0; latency_i < cnt; latency_i++)
			{
				cJSON_AddItemToArray(latency_list, cJSON_CreateNumber(0));
			}
		}
	}
	return;
}

/* calculate the latency and lossy for each host */
void cal_last_latency_lossy(cJSON* hosts, char* latency_name, char* latency_list_name, char* loss_name, int list_cnt)
{
	int j;
	int array_count = cJSON_GetArraySize(hosts);
	for(j = 0; j < array_count; j++)
	{
		cJSON *item = cJSON_GetArrayItem(hosts, j);
		if (item)
		{
			int latency_cnt = 0;
			int latency_total = 0;
			cJSON* latency_list = cJSON_GetObjectItem(item, latency_list_name);
			if (latency_list)
			{
				int i;
				for(i = 0; i < list_cnt; i++)
				{
					cJSON* latency_item = cJSON_GetArrayItem(latency_list, i);
					/* only to parse the ping latency between 0 and 10 seconds */
					if (latency_item->valueint > 0 && latency_item->valueint < 9999999)
					{
						latency_total += latency_item->valueint;
						latency_cnt++;
					}
				}
			}
			//TODO add "latency" in item, avg_latency
			//TODO add "loss" in item
			if (latency_cnt)
			{
				int ping_latency = latency_total/latency_cnt;
				int ping_lossy = ((list_cnt - latency_cnt) * 100) / list_cnt;
				cJSON_ReplaceItemInObject(item, latency_name, cJSON_CreateNumber(ping_latency));
				cJSON_ReplaceItemInObject(item, loss_name, cJSON_CreateNumber(ping_lossy));
			}
		}
	}
	return;
}

void recv_ping_packets(int sockfd, cJSON *hosts, int timeout)
{
	struct timeval timeo;
	// 设定TimeOut时间
	timeo.tv_sec = 0;
	timeo.tv_usec = 1000;
	struct sockaddr_in addr;
	struct sockaddr_in from;
	fd_set readfds;
	double used_time;
	pid_t pid = getpid();
	
	struct timeval start_time;
	struct timeval end_time;
	char recvpacket[PACKET_SIZE];
	gettimeofday(&start_time, NULL);
	do
	{
		// 设定TimeOut时间，这次才是真正起作用的
		FD_ZERO(&readfds);
		FD_SET(sockfd, &readfds);
		int maxfds = sockfd + 1;
		int n = select(maxfds, &readfds, NULL, NULL, &timeo);
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
				struct ip *iph;
				struct icmp *icmp;
				iph = (struct ip *)recvpacket;
				icmp=(struct icmp *)(recvpacket + (iph->ip_hl<<2));
				pkt_tv = (struct timeval *)icmp->icmp_data;
				if (icmp->icmp_type == ICMP_ECHOREPLY)   //ICMP_ECHOREPLY回显应答
				{
					int i;
					int array_count = cJSON_GetArraySize(hosts);
					for(i = 0; i < array_count; i++)
					{
						used_time = cal_time_interval(pkt_tv, &now_tv);
						cJSON *item = cJSON_GetArrayItem(hosts, i);
						if (item)
						{
							cJSON *host_item = cJSON_GetObjectItem(item, "ip");
							inet_pton(AF_INET, host_item->valuestring, &addr.sin_addr);
							// 判断是否是自己Ping的回复
							if (from.sin_addr.s_addr == addr.sin_addr.s_addr)
							{
								if (icmp->icmp_id == pid + i)
								{
									cJSON *latency_item = cJSON_GetObjectItem(item, "latency");
									if (!latency_item)
									{
										cJSON_AddNumberToObject(item, "latency", used_time);
									}
								}
							}
						}
					}
				}
			}
		}
		gettimeofday(&end_time, NULL);
	} while (end_time.tv_sec - start_time.tv_sec < timeout);
	return;
}

void recv_ping_packets2(int sockfd, cJSON *hosts, char *ip_name, char *latency_name, int timeout)
{
	struct timeval timeo;
	// 设定TimeOut时间
	timeo.tv_sec = 0;
	timeo.tv_usec = 1000;
	struct sockaddr_in addr;
	struct sockaddr_in from;
	fd_set readfds;
	double used_time;
	pid_t pid = getpid();

	struct timeval start_time;
	struct timeval end_time;
	char recvpacket[PACKET_SIZE];
	gettimeofday(&start_time, NULL);
	do
	{
		// 设定TimeOut时间，这次才是真正起作用的
		FD_ZERO(&readfds);
		FD_SET(sockfd, &readfds);
		int maxfds = sockfd + 1;
		int n = select(maxfds, &readfds, NULL, NULL, &timeo);
		if (n > 0 && FD_ISSET(sockfd, &readfds))
		{
			// 接受
			memset(recvpacket, 0, sizeof(recvpacket));
			int fromlen = sizeof(from);
			int recv_len = recvfrom(sockfd, recvpacket, sizeof(recvpacket), 0, (struct sockaddr *)&from, (socklen_t *)&fromlen);
			if (recv_len > 1)
			{
				struct timeval *pkt_tv;
				struct timeval now_tv;
				gettimeofday(&now_tv, NULL);
				struct ip *iph;
				struct icmp *icmp;
				iph = (struct ip *)recvpacket;
				icmp=(struct icmp *)(recvpacket + (iph->ip_hl<<2));
				pkt_tv = (struct timeval *)icmp->icmp_data;
				if (icmp->icmp_type == ICMP_ECHOREPLY)   //ICMP_ECHOREPLY回显应答
				{
					int i;
					int array_count = cJSON_GetArraySize(hosts);
					for(i = 0; i < array_count; i++)
					{
						used_time = cal_time_interval(pkt_tv, &now_tv);
						cJSON *item = cJSON_GetArrayItem(hosts, i);
						if (item)
						{
							cJSON *host_item = cJSON_GetObjectItem(item, ip_name);
							inet_pton(AF_INET, host_item->valuestring, &addr.sin_addr);
							// 判断是否是自己Ping的回复
							if (from.sin_addr.s_addr == addr.sin_addr.s_addr)
							{
								if (icmp->icmp_id == pid + i)
								{
									cJSON *latency_item = cJSON_GetObjectItem(item, latency_name);
									if (!latency_item)
									{
										cJSON_AddNumberToObject(item, latency_name, used_time);
									}
								}
							}
						}
					}
				}
			}
		}
		usleep(1000);
		gettimeofday(&end_time, NULL);
	} while (end_time.tv_sec - start_time.tv_sec < timeout);
	return;
}

void recv_ping_packets3(int sockfd, cJSON *hosts, char *ip_name, char *latency_list_name, int timeout, int cnt)
{
	struct timeval timeo;
	// 设定TimeOut时间
	timeo.tv_sec = 0;
	timeo.tv_usec = 1000;
	struct sockaddr_in addr;
	struct sockaddr_in from;
	fd_set readfds;
	int used_time;

	struct timeval start_time;
	struct timeval end_time;
	struct timeval now_time;
	struct timeval intval_time;
	char recvpacket[PACKET_SIZE];

	int host_cnt = cJSON_GetArraySize(hosts);
	/* get pid to determin reply from which host */
	pid_t pid = getpid();
	gettimeofday(&start_time, NULL);
	intval_time.tv_sec = (time_t)timeout;
	intval_time.tv_usec = 0;
	timeradd(&start_time, &intval_time, &end_time);
	do
	{
		// 设定TimeOut时间，这次才是真正起作用的
		FD_ZERO(&readfds);
		FD_SET(sockfd, &readfds);
		int maxfds = sockfd + 1;
		int n = select(maxfds, &readfds, NULL, NULL, &timeo);
		if (n > 0 && FD_ISSET(sockfd, &readfds))
		{
			// 接受
			memset(recvpacket, 0, sizeof(recvpacket));
			int fromlen = sizeof(from);
			int recv_len = recvfrom(sockfd, recvpacket, sizeof(recvpacket), 0, (struct sockaddr *)&from, (socklen_t *)&fromlen);
			if (recv_len > 1)
			{
				struct timeval *pkt_tv;
				struct timeval now_tv;
				gettimeofday(&now_tv, NULL);
				struct ip *iph;
				struct icmp *icmp;
				iph = (struct ip *)recvpacket;
				icmp=(struct icmp *)(recvpacket + (iph->ip_hl<<2));
				pkt_tv = (struct timeval *)icmp->icmp_data;
				used_time = cal_time_interval2(pkt_tv, &now_tv);
				if (icmp->icmp_type == ICMP_ECHOREPLY)   //ICMP_ECHOREPLY回显应答
				{
					int host_i = icmp->icmp_id - pid;
					if ((host_i < host_cnt) &&
							(host_i >= 0))
					{
						cJSON *item = cJSON_GetArrayItem(hosts, host_i);
						if (item)
						{
							cJSON *host_item = cJSON_GetObjectItem(item, ip_name);
							inet_pton(AF_INET, host_item->valuestring, &addr.sin_addr);
							// 判断是否是自己Ping的回复
							if (from.sin_addr.s_addr == addr.sin_addr.s_addr)
							{
								if ((icmp->icmp_seq < cnt) 
										&&
										(icmp->icmp_seq >= 0))
								{
									cJSON* latency_list = cJSON_GetObjectItem(item, "latency_list");
									if (latency_list)
									{
										int which = icmp->icmp_seq;
										cJSON_ReplaceItemInArray(latency_list, which, cJSON_CreateNumber(used_time));
									}
								}
							}
						}
					}
				}
			}
		}
		//usleep(1000);
		gettimeofday(&now_time, NULL);
	} while (timercmp(&now_time, &end_time, <));
	return;
}


/*
 * requres hosts:
 * [
 *		{
 *			"ip":"10.100.16.5"
 *		},
 *		{
 *			"ip":"10.100.16.6"
 *		}
 * ]
 * 
 * after call
 * the hosts will like
 *
 * [
 *		{
 *			"ip":"10.100.16.5",
 *			"latency":1.09
 *		},
 *		{
 *			"ip":"10.100.16.6"
 *			"latency":2.57
 *		}
 * ]
*/
void net_tool_ping_hosts(cJSON *hosts, int timeout)
{
	int fd = create_ping_socket();
	if (fd > 0)
	{
		send_ping_packets(fd, hosts);
		recv_ping_packets(fd, hosts, timeout);
		close(fd);
	}
	set_defaut_latency(hosts);
	return;
}

void net_tool_ping_hosts2(cJSON *hosts, char *ip_name, char*latency_name, int timeout)
{
	int fd = create_ping_socket();
	if (fd > 0)
	{
		send_ping_packets2(fd, hosts, ip_name);
		recv_ping_packets2(fd, hosts, ip_name, latency_name, timeout);
		close(fd);
	}
	set_defaut_latency2(hosts, latency_name);
	return;
}


void net_tool_ping_hosts3(cJSON *hosts, char *ip_name, char*latency_name, char*latency_list_name, char* loss_name, int timeout, int cnt)
{
	int hosts_cnt = cJSON_GetArraySize(hosts);
	if (hosts_cnt > 0)
	{
		set_defaut_latency3(hosts, latency_name, latency_list_name, loss_name, cnt);
		int fd = create_ping_socket();
		if (fd > 0)
		{
			send_ping_packets3(fd, hosts, ip_name, cnt);
			recv_ping_packets3(fd, hosts, ip_name, latency_list_name, timeout, cnt);
			close(fd);
		}
		cal_last_latency_lossy(hosts, latency_name, latency_list_name, loss_name, cnt);
	}
	return;
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

int net_tool_tcp_port_reachable(char *host, int port)
{
	int ret_reachable = 0;
	struct hostent *he;    /* structure that will get information about remote host */
	struct sockaddr_in server;
	int sockfd;
	int ret = 0;
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
				ret_reachable = 1;
			}
			close(sockfd);
		}
	} 
	return ret_reachable;
}

cJSON *net_tool_tcp_json_client_with_size(char *host, int port, cJSON *req, char *prefix, int prefix_size)
{
	cJSON *ret = NULL;
	char *str_req = cJSON_Print(req);
	if (str_req)
	{
		int send_len = prefix_size + strlen(str_req) + 1;
		/* the first 4 bytes stores the bytes count of str to sendout */
		char *send_buf = malloc(send_len + 4);
		char *send_data = send_buf + 4;
		*(uint32_t*)send_buf = htonl((uint32_t)send_len);
		memcpy(send_data, prefix, prefix_size);
		memcpy(send_data + prefix_size, str_req, strlen(str_req) + 1);
		int recv_len = 0;
		char *response = net_tool_tcp_client(host, port, send_buf, send_len + 4, &recv_len);
		if (response)
		{
			if (recv_len > 0)
			{
				ret = cJSON_Parse(response);
			}
			free(response);
		}
		free(send_buf);
		free(str_req);
	}
	return ret;
}

cJSON *net_tool_tcp_json_client(char *host, int port, cJSON *req)
{
	cJSON *ret = NULL;
	char *str_req = cJSON_Print(req);
	if (str_req)
	{
		int recv_len = 0;
		char *response = net_tool_tcp_client(host, port, str_req, strlen(str_req) + 1, &recv_len);
		if (response)
		{
			if (recv_len > 0)
			{
				ret = cJSON_Parse(response);
			}
			free(response);
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

char *net_tool_http_client2(int method, char *host, int port, char *uri, char *body, int body_len, char* header, int *recv_len)
{
	char *ret = NULL;
	char *web_head;
	char head_buf[2000];
	int total_len;
	int head_len;
	if (method == 0)
	{
		web_head = (char*)"GET %s HTTP/1.1\r\n"
		"Host: %s\r\n"
		//"User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:35.0) Gecko/20100101 Firefox/35.0\r\n"
		"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
		"Accept-Language: en-US,en;q=0.5\r\n"
		"Content-Type: application/json; charset=UTF-8\r\n"
		"Connection: close\r\n";
		//"Pragma: no-cache\r\n"
		//"Cache-Control: no-cache\r\n\r\n";
		sprintf(head_buf, web_head, uri, host);
		body = NULL;
	}
	else
	{
		web_head = (char*)"POST %s HTTP/1.1\r\n"
		"Host: %s\r\n"
		"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
		"Accept-Language: en-US,en;q=0.5\r\n"
		"Content-Type: application/json; charset=UTF-8\r\n"
		"Content-Length: %d\r\n"
		"Connection: close\r\n";
		sprintf(head_buf, web_head, uri, host, strlen(body));
	}
	if (header)
	{
		strcat(head_buf, header);
		if (!strstr(header, "\r\n"))
		{
			strcat(head_buf, "\r\n");
		}
	}
	strcat(head_buf, "\r\n");
	head_len = strlen(head_buf);
	total_len = head_len + body_len + 1;

	char *send_buf = (char*)malloc(total_len);
	if (send_buf)
	{
		strcpy(send_buf, head_buf);
		/* if GET method */
		if (body)
		{
			memcpy(send_buf + head_len, body, body_len);
		}
		send_buf[total_len - 1] = 0;
		ret = net_tool_tcp_client(host, port, send_buf, total_len - 1, recv_len);
		free(send_buf);
	}
	return ret;
}

/* method: 0 for GET, 1 for POST */
cJSON* net_tool_http_json_client2(int method, char *host, int port, char *uri, cJSON* req, char* header)
{
	cJSON *ret = NULL;
	char *str_req = NULL;
	if (req)
	{
		str_req = cJSON_Print(req);
	}
	int recv_len = 0;
	char *response = net_tool_http_client2(method, host, port, uri, str_req, str_req?strlen(str_req):0, header, &recv_len);
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
	if (str_req)
	{
		free(str_req);
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

/* the dns request */
#define DNS_HOST  0x01
#define DNS_CNAME 0x05

static cJSON *
my_dns_parse(char *dns_server, char *dns_name);

static cJSON *
parse_dns_response(int socketfd);

/**
* Generate DNS question chunk
*/
static void 
generate_question(const char *dns_name
	, unsigned char *buf , int *len);

/**
* Check whether the current byte is 
* a dns pointer or a length
*/
static int
is_pointer(int in);

/**
* Parse data chunk into dns name
* @param chunk The complete response chunk
* @param ptr The pointer points to data
* @param out This will be filled with dns name
* @param len This will be filled with the length of dns name
*/
static void
parse_dns_name(unsigned char *chunk , unsigned char *ptr
	, char *out , int *len);

cJSON *net_tool_dns_request(char *dns_server, char *request_name)
{
	cJSON *ret = NULL;
	ret = my_dns_parse(dns_server, request_name);
	return ret;
}

/*
 * return
 * {
 *	"alias":[],
 *	"ip":[]
 * }
 * */
static cJSON *parse_dns_response(int socketfd) {
	unsigned char buf[1024];
	unsigned char *ptr = buf;
	struct sockaddr_in addr;
	int n , i , flag , querys , answers;
	int type , datalen , len;
	//int ttl;
	char cname[128] , aname[128] , ip[20];
	unsigned char netip[4];
	//size_t addr_len = sizeof(struct sockaddr_in);
	socklen_t addr_len = sizeof(struct sockaddr_in);
	cJSON *ret = NULL;
	cJSON *alias_array = cJSON_CreateArray();
	cJSON *ip_array = cJSON_CreateArray();
	ret = cJSON_CreateObject();
	cJSON_AddItemToObject(ret, "alias", alias_array);
	cJSON_AddItemToObject(ret, "ip", ip_array);

	n = recvfrom(socketfd , buf , sizeof(buf) , 0
		, (struct sockaddr*)&addr , &addr_len);
	if (n > 0)
	{
		ptr += 4; /* move ptr to Questions */
		querys = ntohs(*((unsigned short*)ptr));
		ptr += 2; /* move ptr to Answer RRs */
		answers = ntohs(*((unsigned short*)ptr));
		ptr += 6; /* move ptr to Querys */
		/* move over Querys */
		for(i= 0 ; i < querys ; i ++){
			for(;;){
				flag = (int)ptr[0];
				ptr += (flag + 1);
				if(flag == 0)
					break;
			}
			ptr += 4;
		}
		//printf("-------------------------------\n");
		/* now ptr points to Answers */
		for(i = 0 ; i < answers ; i ++)
		{
			bzero(aname , sizeof(aname));
			len = 0;
			parse_dns_name(buf , ptr , aname , &len);
			ptr += 2; /* move ptr to Type*/
			type = htons(*((unsigned short*)ptr));
			ptr += 4; /* move ptr to Time to live */
			//ttl = htonl(*((unsigned int*)ptr));
			ptr += 4; /* move ptr to Data lenth */
			datalen = ntohs(*((unsigned short*)ptr));
			ptr += 2; /* move ptr to Data*/
			if(type == DNS_CNAME){
				bzero(cname , sizeof(cname));
				len = 0;
				parse_dns_name(buf , ptr , cname , &len);
				//printf("%s is an alias for %s\n" , aname , cname);
				cJSON_AddItemToArray(alias_array, cJSON_CreateString(cname));
				ptr += datalen;
			}
			if(type == DNS_HOST){
				bzero(ip , sizeof(ip));
				if(datalen == 4){
					memcpy(netip , ptr , datalen);
					inet_ntop(AF_INET , netip , ip , sizeof(struct sockaddr));
					cJSON_AddItemToArray(ip_array, cJSON_CreateString(ip));
					//printf("%s has address %s\n" , aname , ip);
					//printf("\tTime to live: %d minutes , %d seconds\n"
					//	, ttl / 60 , ttl % 60);
				}
				ptr += datalen;
			}

		}
		ptr += 2;
	}
	return ret;
}

static void
parse_dns_name(unsigned char *chunk
	, unsigned char *ptr , char *out , int *len){
	int n , flag;
	char *pos = out + (*len);

	for(;;){
		flag = (int)ptr[0];
		if(flag == 0)
			break;
		if(is_pointer(flag)){
			n = (int)ptr[1];
			ptr = chunk + n;
			parse_dns_name(chunk , ptr , out , len);
			break;
		}else{
			ptr ++;
			memcpy(pos , ptr , flag);	
			pos += flag;
			ptr += flag;
			*len += flag;
			if((int)ptr[0] != 0){
				memcpy(pos , "." , 1);
				pos += 1;
				(*len) += 1;
			}
		}
	}
	return;
}

static int is_pointer(int in){
	return ((in & 0xc0) == 0xc0);
}

static cJSON *my_dns_parse(char *dns_server, char *dns_name) {
	unsigned char request[256];
	unsigned char *ptr = request;
	unsigned char question[128];
	int question_len;
	cJSON *ret = NULL;

	struct sockaddr_in dest;
	bzero(&dest , sizeof(dest));
	dest.sin_family = AF_INET;
	dest.sin_port = htons(53);
	dest.sin_addr.s_addr = inet_addr(dns_server);

	generate_question(dns_name , question , &question_len);
	*((unsigned short*)ptr) = htons(0xff00);
	ptr += 2;
	*((unsigned short*)ptr) = htons(0x0100);
	ptr += 2;
	*((unsigned short*)ptr) = htons(1);
	ptr += 2;
	*((unsigned short*)ptr) = 0;
	ptr += 2;
	*((unsigned short*)ptr) = 0;
	ptr += 2;
	*((unsigned short*)ptr) = 0;
	ptr += 2;
	memcpy(ptr , question , question_len);
		ptr += question_len;

	int socketfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (socketfd > 0)
	{
		sendto(socketfd , request , question_len + 12 , 0
			, (struct sockaddr*)&dest , sizeof(struct sockaddr));
		ret = parse_dns_response(socketfd);
	}
	return ret;
}

static void
generate_question(const char *dns_name , unsigned char *buf , int *len){
	char *pos;
	unsigned char *ptr;
	int n;

	*len = 0;
	ptr = buf;	
	pos = (char*)dns_name; 
	for(;;){
		n = strlen(pos) - (strstr(pos , ".") ? strlen(strstr(pos , ".")) : 0);
		*ptr ++ = (unsigned char)n;
		memcpy(ptr , pos , n);
		*len += n + 1;
		ptr += n;
		if(!strstr(pos , ".")){
			*ptr = (unsigned char)0;
			ptr ++;
			*len += 1;
			break;
		}
		pos += n + 1;
	}
	*((unsigned short*)ptr) = htons(1);
	*len += 2;
	ptr += 2;
	*((unsigned short*)ptr) = htons(1);
	*len += 2;
	return;
}
/* end dns request */

char* net_tool_https_client(int method, char *host, int port, char *uri, char* str_req, int req_len, char** headers, int headers_cnt, int *recv_len, char* ca_file)
{
	char* ret = NULL;
	char buf[1024];
	char cmd_buf[1024];
	char headers_buf[1024] = "";
	int i;
	for(i = 0; i < headers_cnt; i++)
	{
		char* header = headers[i];
		char header_line[200] = "";
		sprintf(header_line, "-H '%s' ", header);
		strcat(headers_buf, header_line);
	}
	if (method)
	{
		if (ca_file)
		{
			sprintf(cmd_buf, "curl -X POST -d '%s' %s https://%s:%d%s --cacert %s", str_req, headers_buf, host, port, uri, ca_file);
		}
		else
		{
			sprintf(cmd_buf, "curl -X POST -d '%s' %s https://%s:%d%s -k", str_req, headers_buf, host, port, uri);
		}
	}
	else
	{
		if (ca_file)
		{
			sprintf(cmd_buf, "curl -X GET %s https://%s:%d%s --cacert %s", headers_buf, host, port, uri, ca_file);
		}
		else
		{
			sprintf(cmd_buf, "curl -X GET %s https://%s:%d%s -k", headers_buf, host, port, uri);
		}
	}
	//MY_DEBUG_INFO("cmd_buf = %s\n", cmd_buf);
	FILE* file = popen((const char*)cmd_buf, "r");
	if (file)
	{
		int total_len = 0;
		while(fgets(buf, sizeof(buf) - 1, file))
		{
			if (!ret)
			{
				ret = strdup(buf);
			}
			else
			{
				int old_len = strlen(ret);
				ret = realloc(ret, old_len + strlen(buf) + 1);
				strcat(ret, buf);
			}
			total_len += strlen(buf);
			memset(buf, 0, sizeof(buf));
		}
		*recv_len = total_len;
		pclose(file);
	}
	return ret;
}

cJSON* net_tool_https_json_client(int method, char *host, int port, char *uri, cJSON* req, char** headers, int headers_cnt, char* ca_file)
{
	cJSON* ret = NULL;
	char *str_req = NULL;
	int recv_len = 0;
	if (req)
	{
		str_req = cJSON_PrintUnformatted(req);
	}

	char* str_ret = net_tool_https_client(method, host, port, uri, str_req, str_req?strlen(str_req):0, headers, headers_cnt, &recv_len, ca_file);
	if (str_ret)
	{
		ret = cJSON_Parse(str_ret);
		free(str_ret);
	}
	if (str_req)
	{
		free(str_req);
	}
	return ret;
}
