
/*
 * 1.直接定期获取/proc/net/arp信息,有老化时间
 * 2.获取dhcpd信息，hostname相关，获取不到，通过nbns协议获取
 * 3.获取的同时发送arp_request,检查有没有在线，会阻塞一段时间,暂定1s吧
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>

#include "client.h"
#include "packet.h"
#include "utils.h"

int g_nbt_sock = -1;
int g_arp_sock = -1;
int g_sig_usr1 = 0;
int g_sig_usr2 = 0;
int g_sig_exit = 0;

int g_lan_num = 1;

ev_timer_t g_arp_timer;
ev_timer_t g_scan_timer;

#define MAX_LAN_NUM 4

enum {
    LAN1_UNIT = 1,
    LAN2_UNIT = 2,
    LAN3_UNIT = 3,
    LAN4_UNIT = 4,
    _LAN_UNIT_MAX
};

static client_list_t lan_client[_LAN_UNIT_MAX];

#define MAX(a, b) (((a) > (b)) ? (a) : (b))

struct if_desc {
    char *name;
    char *device;
};

struct if_desc lan_ifs[_LAN_UNIT_MAX] = {
    { "(error)", "(error)" },
    { "LAN1", "br-lan" },
    { "LAN2", "br-lan2" },
    { "LAN3", "br-lan3" },    
    { "LAN4", "br-lan4" },
};

struct arp_sock arp_socks[_LAN_UNIT_MAX] = {
    { .sockfd = -1 },
    { .sockfd = -1 },
    { .sockfd = -1 },
    { .sockfd = -1 },
    { .sockfd = -1 }
};

/* 接口别名 */
int get_lan_unit_by_name(char *name)
{
    int unit;
    
    for (unit = LAN1_UNIT; unit < _LAN_UNIT_MAX; unit ++ )
    {
        if (!strcmp(lan_ifs[unit].name, name))
        {
            return unit;
        }
    }

    return -1;
}

/* 接口名 */
int get_lan_unit_by_device(char *device)
{
    int unit;

    for (unit = LAN1_UNIT; unit < _LAN_UNIT_MAX; unit ++ )
    {
        if (!strcmp(lan_ifs[unit].device, device))
        {
            return unit;
        }
    }

    return -1;    
}

void client_list_init()
{
    int i = 0;
    int ret = 0;

    for (i = 1; i <= g_lan_num; i ++)
    {    
        ret = get_device_ifconf(lan_ifs[i].device, 
            lan_client[i].lan_ip, lan_client[i].lan_mask, lan_client[i].lan_mac);
        if(ret < 0)
        {
            continue;
        }

        lan_client[i].lan_unit = i;
        lan_client[i].total_num = 0;
        lan_client[i].active_num = 0;
        
        INIT_LIST_HEAD(&lan_client[i].head);
    }
}

/* 更新时间 */
void reset_client_status()
{
    int i;
    net_client_t *item;

    for(i = 1; i <= g_lan_num; i ++)
    {    
        list_for_each_entry(item, &lan_client[i].head, list)
        {
            item->status = 0;
            item->offtime = time(NULL);
        }
    }
}

net_client_t *find_client_by_mac(struct list_head *head, char *macaddr)
{
    net_client_t *item = NULL;

    list_for_each_entry(item, head, list)
    {
        if(strcmp(item->macaddr, macaddr) == 0)
        {
            return item;
        }
    }

    return NULL;
}

net_client_t *find_client_by_ip(struct list_head *head, char *ipaddr)
{
    net_client_t *item = NULL;

    list_for_each_entry(item, head, list)
    {
        if(strcmp(item->ipaddr, ipaddr) == 0)
        {
            return item;
        }
    }

    return NULL;
}

net_client_t *client_item_new()
{
    net_client_t *item = NULL;

    item = (net_client_t *)malloc(sizeof(net_client_t));
    if(!item)
    {
        return NULL;
    }

    memset(item, 0x0, sizeof(net_client_t));

    INIT_LIST_HEAD(&item->list);

    return item;
}

void client_item_free(net_client_t *item)
{
    free(item);
}

void client_list_destroy()
{
    int i = 0;
    net_client_t *item, *temp;
    
    for(i = 1; i <= g_lan_num; i ++)
    {
        list_for_each_entry_safe(item, temp, &lan_client[i].head, list)
        {
            list_del(&item->list);
            client_item_free(item);
        }
    }
}

void client_list_dump()
{
    int i = 0;
    int num = 0;
    FILE *fp = NULL;
    char out_file[64];
    net_client_t *client;
//    int lock;
    
//    lock = file_lock("networkmap")

    for (i = 1; i <= g_lan_num; i ++)
    {
        num = 0;

        snprintf(out_file, sizeof(out_file), "/tmp/networkmap_%s.json", lan_ifs[i].name);
        fp = fopen(out_file, "w");
        if (!fp)
        {
            continue;
        }

        fprintf(fp, "{\"lan\":\"%s\",\"num\":%d", lan_ifs[i].name, lan_client[i].active_num);
        fprintf(fp, ",\"devices\":[");
        
        list_for_each_entry(client, &lan_client[i].head, list)
        {
            if(client->status == 1)
            {  
                fprintf(fp, "%s{\"id\":%d,\"ip\":\"%s\",\"mac\":\"%s\",\"name\":\"%s\","
                    "\"vendor\":\"%s\",\"devtype\":\"%s\",\"conntype\":\"%s\"}", ((num > 0) ? "," : ""), num + 1, 
                    client->ipaddr, client->macaddr, 
                    ((client->hostname[0] == '\0') ? "-" : client->hostname), 
                    ((client->vendor[0] == '\0') ? "-" : client->vendor), 
                    ((client->devtype[0] == '\0') ? "-" : client->devtype), 
                    ((client->conntype[0] == '\0') ? "-" : client->conntype));
                num ++;
            }
        }
        
        fprintf(fp, "]}");
        fclose(fp);
    }

//    file_unlock(lock);
}

void dump_test()
{
    int i = 0;
    int num = 0;
    net_client_t *client;

    printf("%-8s %-18s %-16s %-20s %-10s %-8s\n", 
        "index", "macaddr", "ipaddr", "hostname", "lan", "status");

    for(i = 1; i <= g_lan_num; i ++)
    {
        num = 0;
        list_for_each_entry(client, &lan_client[i].head, list)
        {
            printf("%-8d %-18s %-16s %-20s %-10s %-1d\n", num + 1, client->macaddr, 
                client->ipaddr, ((client->hostname[0] == '\0') ? "unknown" : client->hostname), lan_ifs[i].name, client->status);
            num ++;
        }
    }
}

void get_hostname_by_dhcpd(net_client_t *item)
{
#if 0
    ret = find_udhcpd_host_name(item->device, item->ipaddr, item->hostname, sizeof(item->hostname));
    if(ret < 0)
    {
        return;
    }
#endif
}

void parse_proc_arp()
{
    int ret = 0;
    FILE *fp = NULL;
    char ipaddr[16];
    char macaddr[18];
    char device[20];
    unsigned int flags = 0;
    char line[128] = {0};
    net_client_t *item = NULL;
    int info_changed = 0;
    int lan_unit = 0;
    
    fp = fopen("/proc/net/arp", "r");
    if(!fp)
    {
        return;
    }
    
    reset_client_status();

    fgets(line, sizeof(line), fp);

    while(fgets(line, sizeof(line), fp))
    {
        ret = sscanf(line, "%s %*s 0x%8X %s %*s %s", ipaddr, &flags, macaddr, device);
        if(ret != 4)
        {
            continue;
        }
                
        if(strcmp(macaddr, "00:00:00:00:00:00") == 0 ||
                flags == 0)
        {
            continue;
        }

        lan_unit = get_lan_unit_by_device(device);        
        if (lan_unit < LAN1_UNIT)
        {
            continue;
        }
                
        item = find_client_by_mac(&lan_client[lan_unit].head, macaddr);
        if(!item)
        {
            item = client_item_new();
            if(!item)
            {
                continue;
            }

            strncpy(item->ipaddr, ipaddr, sizeof(item->ipaddr) - 1);
            strncpy(item->macaddr, macaddr, sizeof(item->macaddr) - 1);
            strncpy(item->device, device, sizeof(item->device) - 1);
            item->uptime = time(NULL);
            item->status = 1;

            /*
             * get oui vendor
             * get dhcp option hostname
             * get mdns info
             * nbt query
             */
            if(item->hostname[0] == '\0')
            {            
                nbt_query_send(g_nbt_sock, ipaddr);
            }

            lan_client[lan_unit].total_num ++;
            list_add(&item->list, &lan_client[lan_unit].head);
        }
        else
        {
            if(strcmp(item->ipaddr, ipaddr) != 0)
            {
                info_changed = 1;
                strncpy(item->ipaddr, ipaddr, sizeof(item->ipaddr) - 1);
            }
            
            if(strcmp(item->device, device) != 0)
            {
                info_changed = 1;
                strncpy(item->device, device, sizeof(item->device) - 1);  
            }

            if(info_changed)
            {
                item->uptime = time(NULL);
                item->status = 1;
            }
        }
    }

    fclose(fp);    
}

int get_lan_unit_by_mac(uint8_t *mac)
{
    int i = 0;

    for(i = 1; i <= g_lan_num; i ++)
    {
        if(memcmp(lan_client[i].lan_mac, mac, 6) == 0) 
        {
            return lan_client[i].lan_unit;
        }
    }

    return -1;
}

void ip_mask_net(uint8_t *ip, uint8_t *mask, uint8_t *net)
{
    int i = 0;

    for(i = 0; i < 4; i ++)
    {
        net[i] = ip[i] & mask[i];
    }
}

int get_lan_idx_by_ipmask(uint8_t *ip)
{
    int i = 0;
    uint8_t net1[4];
    uint8_t net2[4];

    memset(net1, 0x0, 4);
    memset(net2, 0x0, 4);

    for(i = 1; i <= g_lan_num; i ++)
    {
        ip_mask_net(ip, lan_client[i].lan_mask, net1);
        ip_mask_net(lan_client[i].lan_ip, lan_client[i].lan_mask, net2);
    
        if(memcmp(net1, net2, 4) == 0) 
        {
            return lan_client[i].lan_unit;
        }
    }

    return -1;
}

#define NETBIOS_UTILS

void name_mangle(char *p)
{
    int i;

    p[0] = 32;
    p[1] = (('*' >> 4) & 0x0F) + 'A';
    p[2] = ('*' & 0x0F) + 'A';
    for (i = 3; i < 33; i++)
        p[i] = 'A';
    p[i] = '\0';
}

int nbt_sock_init()
{
    int ret = 0;
	int sockfd = -1;
	struct sockaddr_in addr;
	
	sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if(sockfd < 0)
    {   
        perror("socket: ");
		return -1;
    }
    
	memset(&addr, 0, sizeof(addr));
    
	addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("0.0.0.0");
    addr.sin_port = htons(0);
    
	ret = bind(sockfd, (struct sockaddr *)&addr, sizeof(addr));
    if(ret < 0)
    {
        perror("bind: ");
        close(sockfd);
		return -1;
    }
    
    return sockfd;
}

int nbt_query_send(int sockfd, char *ipaddr)
{
    int ret = 0;
    ns_name_query req;
    static uint16_t xid = 0;
    
    struct sockaddr_in addr;

    bzero(&addr, sizeof(addr));
    addr.sin_family = PF_INET;
    addr.sin_port = htons(137);
    addr.sin_addr.s_addr = inet_addr(ipaddr);

    xid ++;

    memset(&req, 0x0, sizeof(ns_name_query));
    
	req.trans_id = htons(xid);
	req.flags = htons(0x0010);
	req.questions = htons(1);
	req.answers = 0;
	req.authority_RRs = 0;
	req.additional_RRs = 0;
    name_mangle((char *)req.name);
	req.query_type = htons(0x21);
	req.query_class = htons(0x01);

    ret = sendto(sockfd, (char *)&req, sizeof(ns_name_query), 0, 
        (struct sockaddr *)&addr, sizeof(addr));
    if(ret < 0)
    {
        perror("sendto:");
        return -1;
    }

    return 0;
}

static void get_nbtstat_name(net_client_t *item, char *buff, int len)
{
	uint16_t num;
	uint8_t *p, *e;
    char *tmp;
    ns_nbtstat_resp_hdr *resp;

    /* get nbtstat name */
    if(len <= sizeof(ns_nbtstat_resp_hdr))
    {
        return;
    }
    
    resp = (ns_nbtstat_resp_hdr *)buff;
    
    num = resp->name_num;
    p = (uint8_t *)&buff[NS_HDR_LEN];
    e = p + (num * 18);
    for (; p < e; p += 18)
    {
        if (p[15] == 0 && (p[16] & 0x80) == 0)
        {
            break;
        }
        if (p == e)
        {
            return;
        }
    }

    tmp = trim_str((char *)p);
    strncpy(item->hostname, tmp, sizeof(item->hostname) - 1);
    
}

int nbt_reply_parse(int sockfd)
{
    int ret = 0;
    socklen_t addrlen;
    struct sockaddr_in addr;
    net_client_t *item = NULL;
    char buff[512] = {0};
    char ipaddr[16] = {0};
    int lan_id = 0;

    addrlen = sizeof(struct sockaddr_in);
    memset(&addr, 0x0, addrlen);
    ret = recvfrom(sockfd, buff, sizeof(buff), 0, (struct sockaddr *)&addr, &addrlen);
    if(ret < 0)
    {
        perror("recvfrom:");
        return -1;
    }

    lan_id = get_lan_idx_by_ipmask(&addr.sin_addr);
    if(lan_id < 0)
    {
        return -1;
    }

    strncpy(ipaddr, inet_ntoa(addr.sin_addr), sizeof(ipaddr) - 1);
    
    item = find_client_by_ip(&lan_client[lan_id].head, ipaddr);
    if(!item)
    {
        printf("unknow error\n");
        return -1;
    }

    get_nbtstat_name(item, buff, ret);

    return 0;
}

#define ARP_UTILS

int lan_arp_sock_init()
{
    int i;

    for(i = 1; i <= g_lan_num; i ++)
    {        
        arp_socks[i].sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
        if(arp_socks[i].sockfd < 0)
        {
            perror("socket");
            continue;
        }

        memset(&arp_socks[i].eth_in, 0x0, sizeof(struct sockaddr_ll));
        memset(&arp_socks[i].arp, 0x0, sizeof(arp_packet_t));
        
        arp_socks[i].eth_in.sll_family = PF_PACKET;
        arp_socks[i].eth_in.sll_ifindex = if_nametoindex(lan_ifs[i].device);

        memset(arp_socks[i].arp.h_dest, 0xFF, 6);
        memcpy(arp_socks[i].arp.h_source, lan_client[i].lan_mac, 6);
        arp_socks[i].arp.h_proto = htons(0x0806);
        
        arp_socks[i].arp.ar_hrd = htons(0x0001);
        arp_socks[i].arp.ar_pro = htons(ETH_P_IP);
        arp_socks[i].arp.ar_hln  = 6;
        arp_socks[i].arp.ar_pln = 4;
        arp_socks[i].arp.ar_op = htons(0x0001);
        
        memcpy(arp_socks[i].arp.ar_sha, lan_client[i].lan_mac, 6);
        memcpy(arp_socks[i].arp.ar_sip, lan_client[i].lan_ip, 4);
    }

    return 0;
}

int arp_mon_sock_init()
{
    int sockfd = -1;

    sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if(sockfd < 0)
    {
        perror("socket");
        return -1;
    }

    return sockfd;
}

int arp_request_send(struct arp_sock *sock, char *macaddr, char *ipaddr)
{
    int ret = 0;
    unsigned int ip;

    if(sock->sockfd < 0)
    {
        return -1;
    }
    
    ip = inet_addr(ipaddr);

    memcpy(sock->arp.ar_tip, &ip, 4);
    ret = sendto(sock->sockfd, &sock->arp, sizeof(arp_packet_t), 0, (struct sockaddr *)(&sock->eth_in), sizeof(sock->eth_in));
    if(ret < 0)
    {
        printf("sendto failed!\n");
        return -1;
    }

    return 0;
}

int arp_reply_parse(int sockfd)
{   
    int ret = 0;
    arp_packet_t *arp;
    char buff[100] = {0};
    char ip[16] = {0};
    char mac[18] = {0};
    socklen_t len = 0;
    struct sockaddr_ll addr;
    net_client_t *item;
    int lan_idx = 0;

    len = sizeof(struct sockaddr_ll);

    ret = recvfrom(sockfd, buff, sizeof(buff), 0, (struct sockaddr *)&addr, &len);
    if(ret < 0)
    {
        perror("recvfrom");
        return -1;
    }

    arp = (arp_packet_t *)buff;

    if(ntohs(arp->ar_op) == 2)
    {    
        snprintf(ip, sizeof(ip), "%u.%u.%u.%u", arp->ar_sip[0], arp->ar_sip[1], 
            arp->ar_sip[2], arp->ar_sip[3]);
        snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x", arp->ar_sha[0],
            arp->ar_sha[1], arp->ar_sha[2], arp->ar_sha[3], arp->ar_sha[4], arp->ar_sha[5]);

        lan_idx = get_lan_unit_by_mac(arp->ar_tha);
        if(lan_idx < 0)
        {
            return 0;
        }

        item = find_client_by_mac(&lan_client[lan_idx].head, mac);
        if(item)
        {
            if(strcmp(ip, item->ipaddr) == 0)
            {
                item->status = 1;
                lan_client[lan_idx].active_num ++;
            }
        }
    }    

    return 0;
}

/* 发送ARP请求，检查是否在线 */
void arp_clients_request()
{
    int i = 0;
    net_client_t *client;

    for(i = 1; i <= g_lan_num; i ++)
    {
        lan_client[i].active_num = 0;
        list_for_each_entry(client, &lan_client[i].head, list)
        {
            client->status = 0;
            arp_request_send(&arp_socks[i], client->macaddr, client->ipaddr);
        }    
    }
}

#define MAIN_ROUTINE

void sig_handle(int signo)
{
    switch(signo)
    {
        case SIGUSR1:
            g_sig_usr1 = 1;
            break;
        case SIGUSR2:
            g_sig_usr2 = 1;
            break;
        case SIGTERM:
        case SIGKILL:
            g_sig_exit = 1;
            break;
    }
}

void main_loop()
{
    int ret = 0;
    fd_set rfds;
    int maxfd = 0;
    struct timeval timeo;

    g_arp_sock = arp_mon_sock_init();
    if(g_arp_sock < 0)
    {
        printf("create arp mon sock failed!\n");
        goto err;
    }

    ret = lan_arp_sock_init();
    if(ret < 0)
    {        
        printf("create lan arp sock failed!\n");
        goto err;
    }

    g_nbt_sock = nbt_sock_init();
    if(g_nbt_sock < 0)
    {
        printf("nbt_sock_init failed!\n");
        goto err;
    }

    ev_timer_init(&g_arp_timer);
    ev_timer_init(&g_scan_timer);

    maxfd = MAX(maxfd, g_arp_sock);
    maxfd = MAX(maxfd, g_nbt_sock);
    maxfd = MAX(maxfd, g_arp_timer.fd);
    maxfd = MAX(maxfd, g_scan_timer.fd);

    /*
     * 1s后开启扫描
     */
    ev_timer_mod(&g_scan_timer, NULL, NULL, 1);

    while(1)
    {
        FD_ZERO(&rfds);
        FD_SET(g_arp_sock, &rfds);
        FD_SET(g_nbt_sock, &rfds);
        FD_SET(g_arp_timer.fd, &rfds);
        FD_SET(g_scan_timer.fd, &rfds);

        timeo.tv_sec = 1;
        timeo.tv_usec = 0;
    
        ret = select(maxfd + 1, &rfds, NULL, NULL, &timeo);
        if(ret <= 0)
        {
            if(ret == 0)
            {
                continue;
            }
                    
            if(errno != EINTR || g_sig_exit)
            {
                printf("select : %s\n", strerror(errno));
                exit(1);
            }

            if(g_sig_usr1)
            {   
                /* 发送arp请求，等待回复，超时输出结果 */
                arp_clients_request();
                ev_timer_mod(&g_arp_timer, NULL, NULL, 1);
                g_sig_usr1 = 0;
            }

            if(g_sig_usr2)
            {
                /* 调试用 */
                dump_test();
                g_sig_usr2 = 0;
            }

            continue;
        }

        /* 
         * arp response
         */
        if(FD_ISSET(g_arp_sock, &rfds))
        {
            ret = arp_reply_parse(g_arp_sock);
            if(ret < 0)
            {
                continue;
            }
        }

        /*
         * nbns response
         */
        if(FD_ISSET(g_nbt_sock, &rfds))
        {        
            ret = nbt_reply_parse(g_nbt_sock);
            if(ret < 0)
            {
                continue;
            }
        }

        /* 
         * arp timerfd
         */
        if(FD_ISSET(g_arp_timer.fd, &rfds))
        {
            client_list_dump();
            ev_timer_stop(&g_arp_timer);
        }

        /* 
         * arp scan timerfd
         */
        if(FD_ISSET(g_scan_timer.fd, &rfds))
        {
            parse_proc_arp();
            ev_timer_mod(&g_scan_timer, NULL, NULL, 5);
        }
    }   

err:
    ev_timer_destroy(&g_arp_timer);
    ev_timer_destroy(&g_scan_timer);
}

int main(int argc, char *argv[])
{
    pid_t pid;
    FILE *fp = NULL;
    int no_daemon = 0;

    signal(SIGUSR1, sig_handle);
    signal(SIGUSR2, sig_handle);
    signal(SIGTERM, sig_handle);
    signal(SIGKILL, sig_handle);

    g_lan_num = 1;

    if(argc >= 2)
    {
        if(strcmp(argv[1], "-f") == 0)
        {
            no_daemon = 1;
        }
    }

    if(!no_daemon)
    {
        if(daemon(0, 0) < 0)
        {
            perror("daemon");
            exit(1);
        }
    }
    
    /* 写入PID，用于其他进程获取, 发信号等等... */
    pid = getpid();
    if((fp = fopen(PID_FILE, "w")) != NULL)
    {
        fprintf(fp, "%d", pid);
        fclose(fp);
    }

    client_list_init();

    main_loop();

    client_list_destroy();
    
    unlink(PID_FILE);

    return 0;
}
