
/*
 * 同一段时间内，只允许一个测试实例
 *
 * TODO：锁控制，现阶段在服务端可做
 */

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
#include <net/if.h>

#include "log.h"
#include "utils.h"
#include "rpcd.h"
#include "ping.h"
#include "proto.h"
#include "group.h"
#include "perf.h"

group_t g_vpn_group;
pid_t g_iperfd_pid = -1;
char vpn_ifname[20] = {0};

static void group_member_init()
{
    memset(&g_vpn_group, 0x0, sizeof(g_vpn_group));
    g_vpn_group.members = calloc(MAX_GROUP_MEMBER_NUM, sizeof(group_t));
    g_vpn_group.member_nums = 0;
}

static void group_member_reinit()
{
    g_vpn_group.member_nums = 0;
}

static void group_member_destroy()
{
    if(g_vpn_group.members)
    {
        free(g_vpn_group.members);
    }
}

/* 组间udp消息服务 */
int udp_sock_server(char *ip, int port)
{
    int ret = 0;
    int sockfd = 0;
    struct ifreq if_vpn;
    struct sockaddr_in srv;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sockfd < 0)
    {
        log_error("socket： %s\n", strerror(errno));
        return -1;
    }

    strncpy(if_vpn.ifr_name, vpn_ifname, IFNAMSIZ);

    ret = setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, (char *)&if_vpn, sizeof(if_vpn));
    if(ret < 0)
    {
        close(sockfd);
        log_error("setsockopt: %s\n", strerror(errno));
        return -1;
    }

    memset(&srv, 0x0, sizeof(struct sockaddr_in));
    srv.sin_family = AF_INET;
    srv.sin_port = htons(port);
    srv.sin_addr.s_addr = inet_addr(ip);
    
    if(bind(sockfd, (struct sockaddr *)&srv, sizeof(struct sockaddr)) < 0)
    {
        close(sockfd);
        log_error("bind: %s\n", strerror(errno));
        return -1;
    }

    return sockfd;  
}

/* 进程间通信 */
int unix_sock_server(char *sock_path)
{
    int ret = 0;
    int sockfd;
    struct sockaddr_un addr;

    sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if(sockfd < 0)
    {
        log_error("socket: %s\n", strerror(errno));
        return -1;
    }

    memset(&addr, 0x0, sizeof(struct sockaddr_in));
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, sock_path);

    unlink(sock_path);
 
    ret = bind(sockfd, (struct sockaddr *)&addr, sizeof(addr));
    if(ret != 0)
    {
        ret = -1;
        log_error("bind: %s\n", strerror(errno));
        goto end_proc;
    }

    ret = listen(sockfd, UDS_BACKLOG);
    if(ret != 0)
    {
        ret = -1;
        log_error("listen: %s\n", strerror(errno));
        goto end_proc;
    }

end_proc:
    if(ret < 0)
    {
        close(sockfd);
        return -1;
    }

    return sockfd;
}

void parse_group_members(cJSON *arr)
{
    int i = 0;
    int arrNum = 0;
    cJSON *item = NULL;
    char *sn, *ip;

    if(!arr || arr->type != cJSON_Array)
    {
        return;
    }
    
    arrNum = cJSON_GetArraySize(arr);
    for(i = 0; i < arrNum; i ++)
    {
        memset(&g_vpn_group.members[i], 0x0, sizeof(member_t));

        item = cJSON_GetArrayItem(arr, i); 
        if(!item)
        {
            continue;
        }
        
        sn = cjson_get_string(item, "sn");
        if(sn)
        {
            strncpy(g_vpn_group.members[i].sn, sn, 32);     
        }
        
        ip = cjson_get_string(item, "ip");
        if(!ip)
        {
            log_error("member param error");
            continue;
        }

        strncpy(g_vpn_group.members[i].ip, ip, 16);
        g_vpn_group.member_nums ++;
    }
}

int notify_peer_do_perf_server(char *ipaddr, int running)
{
    int ret = 0;
    int sockfd;  
    struct ifreq if_vpn;
    struct sockaddr_in svrAddr;  

    int wlen, rlen;
    perf_proto_t wbuf;
    perf_proto_t rbuf;

    memset(&wbuf, 0x0, sizeof(wbuf));
    memset(&rbuf, 0x0, sizeof(rbuf));

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);  
    if(sockfd < 0)
    {  
        log_error("socket: %s\n", strerror(errno));  
        return -1;  
    }  
    
    strncpy(if_vpn.ifr_name, vpn_ifname, IFNAMSIZ);

    ret = setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, (char *)&if_vpn, sizeof(if_vpn));
    if(ret < 0)
    {
        close(sockfd);
        log_error("setsockopt: %s\n", strerror(errno));
        return -1;
    }

    memset(&svrAddr, 0, sizeof(svrAddr));  
    svrAddr.sin_family = AF_INET;  
    svrAddr.sin_addr.s_addr = inet_addr(ipaddr);  
    svrAddr.sin_port = htons(UDP_SERVER_PORT);

    wlen = sizeof(wbuf);
    wbuf.type = MEMBER_PERF_REQ;
    wbuf.mode = 1;
    wbuf.running = running;

    ret = sendto(sockfd, &wbuf, wlen, 0, (struct sockaddr *)&svrAddr, sizeof(svrAddr));  
    if(ret < 0)  
    {  
        close(sockfd);
        log_error("sendto: %s\n", strerror(errno));
        return -1;
    }
    
    struct sockaddr_in fromAddr;  
    memset((char *)&fromAddr, 0, (int)sizeof(fromAddr));  
    socklen_t fromLen = sizeof(fromAddr);  

    struct timeval tv;
    
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    
    ret = setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
    
    rlen = recvfrom(sockfd, &rbuf, sizeof(rbuf), 0, (struct sockaddr *)&fromAddr, &fromLen);      
    if(rlen < 0)  
    {  
        ret = -1;
        if(errno == EAGAIN)
        {
            log_debug("recvfrom timeout!\n");
        }
        else
        {
            log_error("recvfrom: %s\n", strerror(errno));  
        }
    }
    else
    {
        if(rbuf.type != MEMBER_PERF_RESP ||
            rbuf.mode != 1 ||
            rbuf.running != running)
        {
            ret = -1;
            log_error("error packet !\n");
        }
        else
        {
            log_debug("do perf server ok\n");
        }
    }
    
    close(sockfd);

    return ret;
}

int notify_peer_do_perf_client(char *ipaddr, int *bandwidth)
{
    int ret = 0;
    int sockfd;  
    struct ifreq if_vpn;
    struct sockaddr_in svrAddr;

    int wlen, rlen;
    perf_proto_t wbuf;
    perf_proto_t rbuf;

    memset(&wbuf, 0x0, sizeof(wbuf));
    memset(&rbuf, 0x0, sizeof(rbuf));

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);  
    if(sockfd < 0)
    {  
        log_error("socket: %s\n", strerror(errno));  
        return -1;  
    } 
    
    strncpy(if_vpn.ifr_name, vpn_ifname, IFNAMSIZ);

    ret = setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, (char *)&if_vpn, sizeof(if_vpn));
    if(ret < 0)
    {
        close(sockfd);
        log_error("setsockopt: %s\n", strerror(errno));
        return -1;
    }

    memset(&svrAddr, 0, sizeof(svrAddr));  
    svrAddr.sin_family = AF_INET;  
    svrAddr.sin_addr.s_addr = inet_addr(ipaddr);  
    svrAddr.sin_port = htons(UDP_SERVER_PORT);

    wlen = sizeof(wbuf);
    wbuf.type = MEMBER_PERF_REQ;
    wbuf.mode = 0;
    wbuf.running = 1;
    
    ret = sendto(sockfd, &wbuf, wlen, 0, (struct sockaddr *)&svrAddr, sizeof(svrAddr));  
    if(ret < 0)  
    {  
        close(sockfd);
        log_error("sendto: %s\n", strerror(errno));
        return -1;
    }  
    
    struct sockaddr_in fromAddr;  
    memset((char *)&fromAddr, 0, (int)sizeof(fromAddr));  
    socklen_t fromLen = sizeof(fromAddr);  

    struct timeval tv;

    /* 这里注意，每次iperf测试时阻塞的，
     * 故收到回复报文会在测试完成之后，这里的接收超时注意要大于等于测试时间
     */
    tv.tv_sec = 15;
    tv.tv_usec = 0;
    
    ret = setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
    
    rlen = recvfrom(sockfd, &rbuf, sizeof(rbuf), 0, (struct sockaddr *)&fromAddr, &fromLen);      
    if(rlen < 0)  
    {  
        ret = -1;

        if(errno == EAGAIN)
        {
            log_debug("recvfrom timeout!\n");
        }
        else
        {
            log_error("recvfrom: %s\n", strerror(errno));  
        }
    }
    else
    {
        if(rbuf.type != MEMBER_PERF_RESP ||
            rbuf.mode != 0 ||
            rbuf.running != 0)
        {
            ret = -1;
            log_error("error packet !\n");
        }
        else
        {
            *bandwidth = ntohl(rbuf.bandwidth);
            log_debug("bandwidth = %d kbps\n", *bandwidth);
        }
    }

    close(sockfd);

    return ret;
}

void handle_cmd_perf(int sockfd)
{
    int i = 0;
    int ret = 0;
    int code = 0;
    cJSON *rObj = NULL;
    cJSON *arr = NULL;
    cJSON *item = NULL;

    rObj = cJSON_CreateObject();
    if(!rObj)
    {
        log_error("create json obj failed!\n");
        return;
    }

    arr = cJSON_CreateArray();
    if(!arr)
    {
        cJSON_Delete(rObj);
        log_error("create json arr obj failed!\n");
        return;
    }

    for(i = 0; i < g_vpn_group.member_nums; i ++)
    {
        int iperfd_pid;
        int upload, download;

        item = cJSON_CreateObject();
        if(!item)
        {
            log_error("create json obj failed!\n");
            continue;
        }

        upload = download = 0;

        /* 下行测试 */
        ret = notify_peer_do_perf_server(g_vpn_group.members[i].ip, 1);
        if(ret < 0)
        {
            code = 1;
            log_error("do iperf server failed!\n");
            continue;
        }
        
        ret = do_perf_client(g_vpn_group.members[i].ip, &upload);
        if(ret < 0)
        {    
            code = 1;
            log_error("do iperf client failed!\n");
            continue;
        }
      
        ret = notify_peer_do_perf_server(g_vpn_group.members[i].ip, 0);
        if(ret < 0)
        {
            code = 1;
            log_error("do perf server failed!\n");
            continue;
        }

        /* 上行测试 */
        iperfd_pid = do_perf_server();
        ret = notify_peer_do_perf_client(g_vpn_group.members[i].ip, &download);
        if(ret < 0)
        {
            code = 1;
            log_error("do peer perf client failed!\n");            
            kill(iperfd_pid, SIGKILL);
            continue;
        }

        kill(iperfd_pid, SIGKILL);

        if(g_vpn_group.members[i].sn[0] != '\0')
        {
            cJSON_AddStringToObject(item, "sn", g_vpn_group.members[i].sn);
        }
        
        cJSON_AddStringToObject(item, "ip", g_vpn_group.members[i].ip);
        cJSON_AddNumberToObject(item, "upload", upload);
        cJSON_AddNumberToObject(item, "download", download);
        cJSON_AddItemToArray(arr, item);
    }

    cJSON_AddNumberToObject(rObj, "code", code);    
    cJSON_AddItemToObject(rObj, "data", arr);

    char *data = NULL;
    int datalen = 0;

    data = cJSON_PrintUnformatted(rObj);
    if(!data)
    {
        log_error("print unformatted json failed!\n");
        goto end_proc;
    }
    
    datalen = strlen(data);
    ret = send(sockfd, data, datalen, MSG_NOSIGNAL);
    if(ret < 0 || ret != datalen)
    {
        log_error("send error!\n");
    }

end_proc:
    if(data)
    {
        free(data);
    }
    
    if(rObj)
    {
        cJSON_Delete(rObj);
    }
}

void handle_cmd_ping(int sockfd)
{
    int i = 0;
    int ret = 0;
    cJSON *rObj = NULL;
    cJSON *arr = NULL;
    cJSON *item = NULL;

    rObj = cJSON_CreateObject();
    if(!rObj)
    {
        log_error("create json obj failed!\n");
        return;
    }

    arr = cJSON_CreateArray();
    if(!arr)
    {
        cJSON_Delete(rObj);
        log_error("create json arr obj failed!\n");
        return;
    }

    for(i = 0; i < g_vpn_group.member_nums; i ++)
    {
        int cnt, rtt, loss;

        item = cJSON_CreateObject();
        if(!item)
        {
            log_error("create json obj failed!\n");
            continue;
        }

        /* 对每个组成员发送10个icmp包，超时4 sec */
        cnt = 10;
        rtt = loss = 0;
        
        ret = ping_rtt_avg(g_vpn_group.members[i].ip, cnt, 4, &rtt, &loss);
        if(ret < 0)
        {
            log_error("ping error!\n");
            continue;
        }
        
        cJSON_AddStringToObject(item, "sn", g_vpn_group.members[i].sn);
        cJSON_AddStringToObject(item, "ip", g_vpn_group.members[i].ip);
        cJSON_AddNumberToObject(item, "latency", (rtt / cnt));
        cJSON_AddNumberToObject(item, "loss", ((loss * 100) / cnt ));
        cJSON_AddItemToArray(arr, item);
    }

    cJSON_AddNumberToObject(rObj, "code", 0);
    cJSON_AddItemToObject(rObj, "data", arr);

    char *data = NULL;
    int datalen = 0;

    data = cJSON_PrintUnformatted(rObj);
    if(!data)
    {
        log_error("print unformatted json failed!\n");
        goto end_proc;
    }
    
    datalen = strlen(data);
    ret = send(sockfd, data, datalen, MSG_NOSIGNAL);
    if(ret < 0 || ret != datalen)
    {
        log_error("send error!\n");
    }

end_proc:
    if(data)
    {
        free(data);
    }
    
    if(rObj)
    {
        cJSON_Delete(rObj);
    }
}

void uds_packet_handle(int sockfd)
{
    int ret = 0;
    char rbuf[1024] = {0};
    cJSON *rObj = NULL;
    cJSON *data = NULL;
    char *cmd = NULL;

    ret = recv(sockfd, rbuf, sizeof(rbuf), 0);
    if(ret < 0)
    {
        log_error("recv: %s\n", strerror(errno));
        return;
    }
    else if(ret == 0)
    {
        log_debug("peer closed\n");
        return;
    }

    rObj = cJSON_Parse(rbuf);
    if(rObj == NULL)
    {
        log_error("parse json error\n");
        return;
    }

    cmd = cjson_get_string(rObj, "cmd");
    data = cJSON_GetObjectItem(rObj, "data");
    if(!cmd || !data)
    {
        cJSON_Delete(rObj);
        log_error("param error!\n");
        return;
    }

    group_member_reinit();
    parse_group_members(data);

    if(strcmp(cmd, "perf") == 0)
    {
        handle_cmd_perf(sockfd);
    }
    else if(strcmp(cmd, "ping") == 0)
    {
        handle_cmd_ping(sockfd);
    }
    else
    {
        log_error("unsupported cmd!\n");
    }

    if(rObj)
    {
        cJSON_Delete(rObj);
    }
}

/*
 * TODO:
 */
void handle_discovery_request(int sockfd, struct sockaddr_in *addr, socklen_t addrLen, uint8_t *buff, int len)
{
        
}

void handle_perf_request(int sockfd, struct sockaddr_in *addr, socklen_t addrLen, uint8_t *buff, int len)
{
    int ret = 0;
    int perfd_pid = 0;
    perf_proto_t resp;
    perf_proto_t *pkt = NULL;
    int bandwidth = 0;
    char ip[16];

    pkt = (perf_proto_t *)buff;

    if(len != sizeof(perf_proto_t))
    {
        return;
    }

    memset(&resp, 0x0, sizeof(resp));

    resp.type = MEMBER_PERF_RESP;
    resp.mode = pkt->mode;

    if(pkt->mode == 0)
    {    
        snprintf(ip,  sizeof(ip), "%s", inet_ntoa(addr->sin_addr));

        log_debug("ip = %s\n", ip);
        
        ret = do_perf_client(ip, &bandwidth);
        if(ret < 0)
        {
            log_debug("do perf client failed!\n");
            bandwidth = 0;
        }
        
        resp.running = 0;
        resp.bandwidth = htonl(bandwidth);

        log_debug("bandwidth = %d\n", bandwidth);
    }
    else if(pkt->mode == 1)
    {
        resp.running = pkt->running;
        if(pkt->running == 0)
        {
            if(g_iperfd_pid > 0)
            {
                kill(g_iperfd_pid, SIGKILL);
                g_iperfd_pid = -1;
            }
        }
        else
        {
            system("killall -KILL iperf >/dev/null 2>&1");
            g_iperfd_pid = do_perf_server();
        }
    }

    if(sendto(sockfd, &resp, sizeof(perf_proto_t), 0, (struct sockaddr *)addr, addrLen) < 0)
    { 
        log_error("send error!\n");
    }
}

/*
 * 目前主要作用：
 *     1. 组间成员发现(TODO)
 *     2. 组间消息控制
 */
void udp_packet_handle(int sockfd)
{
    int rlen = 0;
    uint8_t rbuff[1024];
    struct sockaddr_in addr;
    socklen_t addrLen;
    uint8_t type = 0;

    addrLen = sizeof(struct sockaddr_in);
    memset(&addr, 0x0, sizeof(addrLen));
    memset(rbuff, 0x0, sizeof(rbuff));

    rlen = recvfrom(sockfd, rbuff, sizeof(rbuff), 0, (struct sockaddr *)&addr, &addrLen);
    if(rlen < 0)
    {
        log_error("recvfrom: %s\n", strerror(errno));
        return;
    }
    else if(rlen == 0)
    {
        log_warn("error packet len!\n");
        return;
    }

    type = rbuff[0];

    log_debug("rlen = %d\n", rlen);
    log_debug("type = %hhu\n", type);

    switch(type)
    {
        case MEMBER_DISCOVERY:
            handle_discovery_request(sockfd, &addr, addrLen, rbuff, rlen);
            break;
        case MEMBER_PERF_REQ:
            handle_perf_request(sockfd, &addr, addrLen, rbuff, rlen);
            break;
        case MEMBER_PERF_RESP:
            break;
    }
}

/* 主要实现UDP组间成员通信，
 * 以及系统内进程间通信
 */
void rpcd_loop()
{
    int ret = 0;
    int max_fd;
    fd_set rfds;
    int uds_cfd = -1;
    int udpfd, udsfd;
    struct timeval tv;

    group_member_init();

    /* 
     * 先简化处理
     * 应该是绑定虚拟网卡，不能监听所有的ip
     */
    udpfd = udp_sock_server("0.0.0.0", UDP_SERVER_PORT);
    if(udpfd < 0)
    {
        log_error("create udp sock server failed!\n");
        return;
    }
    
    udsfd = unix_sock_server(UDS_SERVER_PATH);
    if(udsfd < 0)
    {
        close(udpfd);
        log_error("create unix sock server failed!\n");
        return;
    }

    max_fd = (udpfd > udsfd) ? udpfd : udsfd;

    while(1)
    {
        tv.tv_sec = 10;
        tv.tv_usec = 0;

        FD_ZERO(&rfds);        
        FD_SET(udpfd, &rfds);
        FD_SET(udsfd, &rfds);

        if(uds_cfd > 0)
        {
            FD_SET(uds_cfd, &rfds);
        }

        ret = select(max_fd + 1, &rfds, NULL, NULL, &tv);
        if(ret < 0)
        {
            if(errno == EINTR)
            {
                continue;
            }
            
            log_error("select: %s", strerror(errno));
            break;
        }
        else if(ret == 0)
        {
            continue;
        }
        
        /* udp消息处理 */
        if(FD_ISSET(udpfd, &rfds))
        {
            udp_packet_handle(udpfd);
        }
            
        if(FD_ISSET(udsfd, &rfds))
        {
            uds_cfd = accept(udsfd, NULL, NULL);
            if(uds_cfd < 0)
            {
                log_error("accept failed!\n");
                continue;
            }
                        
            if(uds_cfd > max_fd)
            {
                max_fd = uds_cfd;
            }
        }

        if(uds_cfd > 0)
        {
            if(FD_ISSET(uds_cfd, &rfds))
            {
                uds_packet_handle(uds_cfd);
                FD_CLR(uds_cfd, &rfds);
                close(uds_cfd);
                uds_cfd = -1;
            }
        }
    }
}
