
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/un.h>

#include "vpnperf_client.h"

/*
 * 返回值 
 *    1: 超时
 *    0: 正常
 *   -1: 错误
 * 
 */
int uds_client_request(char *path, 
    char *wbuf, int wlen, char *rbuf, int rlen, int timeout)
{
    int ret;
    int sockfd;
    struct sockaddr_un addr;  

    if(!path || !wbuf || !rbuf)
    {
        fprintf(stderr, "param error!\n");
        return -1;
    }

    memset(&addr, 0x0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, path);

    sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if(sockfd < 0)
    {
        fprintf(stderr, "socket: %s\n", strerror(errno));
        return -1;
    }

    ret = connect(sockfd, (struct sockaddr *)&addr, sizeof(addr));
    if(ret < 0)
    {   
        close(sockfd);
        fprintf(stderr, "connect: %s\n", strerror(errno));
        return -1;
    }

    ret = send(sockfd, wbuf, wlen, MSG_NOSIGNAL);
    if(ret < 0)
    {
        close(sockfd);
        fprintf(stderr, "send: %s\n", strerror(errno));
        return -1;
    }

    struct timeval tv;
    tv.tv_sec = timeout;
    tv.tv_usec = 0;
    
    ret = setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
    if(ret < 0)
    {
        close(sockfd);
        fprintf(stderr, "setsockopt: %s\n", strerror(errno));
        return -1;
    }

    ret = recv(sockfd, rbuf, rlen, 0);
    if(ret < 0)
    {
        close(sockfd);
        if(errno == EAGAIN)
        {
            fprintf(stderr, "recvfrom timeout!\n");
            return 1;
        }
        else
        {
            fprintf(stderr, "recvfrom: %s\n", strerror(errno));            
            return -1;
        }
    }

    close(sockfd);

    return 0;
}
