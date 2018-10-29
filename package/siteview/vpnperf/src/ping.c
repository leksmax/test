  
#include <stdio.h>  
#include <stdlib.h>  
#include <string.h>  
#include <unistd.h>  
#include <errno.h>  
#include <time.h>
#include <arpa/inet.h>  
#include <sys/types.h>  
#include <sys/socket.h>  
#include <sys/time.h>
#include <netinet/in.h>  
#include <netinet/ip.h>  
#include <netinet/ip_icmp.h>  
#include <netdb.h>  

#include "log.h"
#include "ping.h"

/* 计算发送和接收的时间差，差值为ms */
int calc_rtt(struct timeval *stv, struct timeval *rtv)
{
    return (int)((rtv->tv_sec - stv->tv_sec) * 1000 + (rtv->tv_usec - stv->tv_usec) / 1000);
}

/* 校验算法 */
static uint16_t calc_cksum( uint16_t *addr, int len )
{
    int nleft = len;
    uint32_t sum = 0;
    uint16_t *w	= addr;
    uint16_t answer	= 0;

    while(nleft > 1)
    {
        sum	+= *w++;
        nleft -= 2;
    }

    if(nleft == 1)
    {
        *(unsigned char *)(&answer) = *(unsigned char *)w;
        sum += answer;
    }

    sum	= (sum >> 16) + (sum & 0xffff);
    sum	+= (sum >> 16);
    answer = ~sum;

    return(answer);
}

/* 发送  32 + 8字节icmp包 */
int send_echo_req(int sockfd, struct sockaddr_in *dstaddr, uint16_t icmp_id_nr, uint16_t icmp_seq_nr)
{
	size_t len = 0;

    char buff[40] = {0};
	struct icmp	*icmp = NULL;
	socklen_t dstlen = 0;

    len = sizeof(buff);
    dstlen = sizeof(struct sockaddr_in);

	icmp = (struct icmp *)buff;
    
    icmp->icmp_type = ICMP_ECHO;
    icmp->icmp_code = 0;
    icmp->icmp_cksum = 0;
	icmp->icmp_id = htons(icmp_id_nr);
	icmp->icmp_seq = htons(icmp_seq_nr);
	icmp->icmp_cksum = calc_cksum((uint16_t *)icmp, sizeof(struct icmp));

	return sendto(sockfd, buff, len, 0, (struct sockaddr *)dstaddr, dstlen);
}

int recv_echo_reply(int sockfd, int timeout, uint16_t icmp_id_nr, uint16_t icmp_seq_nr)
{
	int ret = 0;
    ssize_t	n;
	char buf[100] = {0};
    struct ip *ip;
	struct icmp	*icmp;
    fd_set fds;
	struct timeval tv = {timeout, 0}; 
    socklen_t fromlen;
    struct sockaddr_in from;
    
    FD_ZERO(&fds);
    FD_SET(sockfd, &fds);

    ret = select(sockfd + 1, &fds, NULL, NULL, &tv);
    if(ret <= 0)
    {
        log_error("select: %s\n", strerror(errno));
        return -1;
    }

    fromlen = sizeof(struct sockaddr_in);
    n = recvfrom(sockfd, buf,sizeof(buf), 0, (struct sockaddr *)&from, &fromlen);
    if(n < 0)
    {
        log_error("read: %s\n", strerror(errno));
        return -1;
    }

	ip = (struct ip *)buf;
	if(ip->ip_p != IPPROTO_ICMP)
	{
		log_error("protocol error!\n");
		return -1;
	}

	icmp = (struct icmp *)(buf + sizeof(struct ip));
    
	if(icmp->icmp_type == ICMP_ECHOREPLY)
	{
		if(icmp->icmp_id != htons(icmp_id_nr) || icmp->icmp_seq != htons(icmp_seq_nr))
		{
			log_error("Error: error icmp id or icmp seq.\n");
			return -1;
		}
        else
        {
			//log_debug("destination host is alive.\n");
			return 0;
		}
	}

    return ret;
}

static uint16_t get_random_xid()
{
    srandom(time(NULL));
    return (uint16_t)random();
}

int ping_rtt_avg(char *ip, int count, int timeout, int *rtt, int *loss)
{
    int ret = 0;
    int sockfd;
    uint32_t ipaddr;
    struct sockaddr_in addr;
    struct timeval stv, rtv;
    int i = 0;
    int c_rtt;
    uint16_t icmp_id_nr;
    uint16_t icmp_seq_nr;

    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if(sockfd < 0)
    {
        log_error("socket: %s\n", strerror(errno));
        return -1;
    }

    memset(&addr, 0x0, sizeof(struct sockaddr_in));
    
    ipaddr = inet_addr(ip);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(0);
    memcpy(&addr.sin_addr, &ipaddr, sizeof(uint32_t));
    
    for(i = 1; i <= count; i ++)
    {   
        icmp_id_nr = get_random_xid();
        icmp_seq_nr = (uint16_t)i;
    
        gettimeofday(&stv, NULL);

        /* 发送echo request 报文 */
        ret = send_echo_req(sockfd, &addr, icmp_id_nr, icmp_seq_nr);
        if(ret < 0)
        {
            (*loss) ++;
            log_error("send icmp echo request failed!\n");
            continue;
        }

        /* 接收echo response报文, 直至超时 */
        ret = recv_echo_reply(sockfd, timeout, icmp_id_nr, icmp_seq_nr);
        if(ret < 0)
        {  
            (*loss) ++;
            log_error("recv icmp echo response failed!\n");
            continue;
        }
        
        gettimeofday(&rtv, NULL);

        c_rtt = calc_rtt(&stv, &rtv);
        *rtt += c_rtt;
        
        //log_debug("ip [%s], cnts:[%d]: c_rtt = [%d], avg rtt = %d\n", ip, i, c_rtt, *rtt);

        sleep(1);
    }

    close(sockfd);

    return 0;

}

#if 0

int g_debug_level = LOG_ALL;

int main(int argc, char *argv[])
{
    int rtt = 0;
    int loss = 0;
    int cnt = 0;

    cnt = 20;
    ping_rtt_avg(argv[1], cnt, 4, &rtt, &loss);

    printf("loss = %d\n", loss);
    printf("loss %.2lf%%", ((double)loss / (double)cnt) * 100);
    printf("avg rtt = %d\n", rtt / cnt);
    
    return 0;
}
#endif
