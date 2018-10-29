#include <errno.h>  
#include <sys/socket.h>  
#include <netinet/in.h>  
#include <arpa/inet.h>  
#include <stdlib.h>  
#include <string.h>  
#include <netinet/in.h>  
#include <stdio.h>  
#include <unistd.h>  
#include <sys/types.h>  
#include <sys/socket.h>  

#include "../log.h"
#include "../rpcd.h"
#include "../group.h"
#include "../proto.h"

#define IPERF_CLIENT 0
#define IPERF_SERVER 1


void notify_peer_do_perf_client(char *sip, int sport)
{
    int ret = 0;
    int socketFd;  
    struct sockaddr_in svrAddr;  

    int wlen, rlen;
    perf_proto_t wbuf;
    perf_proto_t rbuf;

    memset(&wbuf, 0x0, sizeof(wbuf));
    memset(&rbuf, 0x0, sizeof(rbuf));

    socketFd = socket(AF_INET, SOCK_DGRAM, 0);  
    if ( -1 == socketFd)  
    {  
        perror( "socket:" );  
        exit(-1);  
    }  

    wlen = sizeof(perf_proto_t);

    wbuf.type = MEMBER_PERF_REQ;
    wbuf.mode = IPERF_CLIENT;
    wbuf.dst_ip = inet_addr(sip);
    wbuf.dst_port = htons(sport);
    wbuf.bandwidth = htonl(100043);

    memset(&svrAddr, 0, sizeof(svrAddr));  
    svrAddr.sin_family = AF_INET;  
    svrAddr.sin_addr.s_addr = inet_addr(sip);  
    svrAddr.sin_port = htons(sport);

    ssize_t result = sendto(socketFd, &wbuf, wlen, 0, (struct sockaddr*)&svrAddr, sizeof(svrAddr));  
    if ( -1 == result )  
    {  
        perror("sendto:");  
    }  
    else  
    {  
        printf("send data success. data len:%ld\n", result );  
    }  
    
    // 接收数据  
    struct sockaddr_in fromAddr;  
    memset((char *)&fromAddr, 0, (int)sizeof(fromAddr));  
    socklen_t fromLen = sizeof(fromAddr);  

    struct timeval tv;
    
    tv.tv_sec = 15;
    tv.tv_usec = 0;
    ret = setsockopt(socketFd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
    
    result = recvfrom(socketFd, &rbuf, sizeof(rbuf), 0, (struct sockaddr *)&fromAddr, &fromLen);      
    if ( -1 == result)  
    {  
        if(errno == EAGAIN)
        {
            printf("timeout!\n");
        }
        else
            perror("recvfrom:");  
    }

}

void notify_peer_do_perf_server(char *sip, int sport, int start)
{
    int ret = 0;
    int socketFd;  
    struct sockaddr_in svrAddr;  

    int wlen, rlen;
    perf_proto_t wbuf;
    perf_proto_t rbuf;

    memset(&wbuf, 0x0, sizeof(wbuf));
    memset(&rbuf, 0x0, sizeof(rbuf));

    socketFd = socket(AF_INET, SOCK_DGRAM, 0);  
    if ( -1 == socketFd)  
    {  
        perror( "socket:" );  
        exit(-1);  
    }  

    wlen = sizeof(perf_proto_t);

    wbuf.type = MEMBER_PERF_REQ;
    wbuf.mode = IPERF_SERVER;
    wbuf.running = start;

    memset(&svrAddr, 0, sizeof(svrAddr));  
    svrAddr.sin_family = AF_INET;  
    svrAddr.sin_addr.s_addr = inet_addr(sip);  
    svrAddr.sin_port = htons(sport);

    ssize_t result = sendto(socketFd, &wbuf, wlen, 0, (struct sockaddr*)&svrAddr, sizeof(svrAddr));  
    if ( -1 == result )  
    {  
        perror("sendto:");  
    }  
    else  
    {  
        printf("send data success. data len:%ld\n", result);  
    }  
    
    // 接收数据  
    struct sockaddr_in fromAddr;  
    memset((char *)&fromAddr, 0, (int)sizeof(fromAddr));  
    socklen_t fromLen = sizeof(fromAddr);  

    struct timeval tv;
    
    tv.tv_sec = 3;
    tv.tv_usec = 0;
    ret = setsockopt(socketFd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
    
    result = recvfrom(socketFd, &rbuf, sizeof(rbuf), 0, (struct sockaddr *)&fromAddr, &fromLen);      
    if ( -1 == result)  
    {  
        if(errno == EAGAIN)
        {
            printf("timeout!\n");
        }
        else
            perror("recvfrom:");  
    }
    
}


int main(int argc, char *argv[])
{
    int cmd = 0;
    
    if(argc < 2)
    {
        return -1;
    }

    if(strcmp(argv[1], "client") == 0)
    {
        if(argc < 4)
        {
            return -1;
        }
        
        notify_peer_do_perf_client(argv[2], atoi(argv[3]));        
    }
    else if (strcmp(argv[1], "server") == 0)
    {
        if(argc < 5)
        {
            return -1;
        }
        
        notify_peer_do_perf_server(argv[2], atoi(argv[3]), atoi(argv[4]));
    }

    return 0;
}
