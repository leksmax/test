
/*
 * 在同一个组下的设备，组网成功的话，会处于统一子网下，这样，
 * 组成员间可以自动发现现有设备
 *
 * UDP广播发现组间成员，
 * UDP消息，组间可以传递消息
 *
 * 注意：
 *   此服务在vpn建立完成时候再启动
 *   需指定vpn虚拟接口，udp服务监听在vpn成员子网内
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "log.h"
#include "rpcd.h"

int g_debug_level = LOG_ALL;

extern char vpn_ifname[20];

void sig_child(int signo)
{
    pid_t pid;
    int status;

    while((pid = waitpid(-1, &status, WNOHANG)) > 0);

    return;
} 

int main(int argc, char *argv[])
{
    int opt = 0;
    int nodaemon = 0;

    signal(SIGCHLD, sig_child);

    while((opt = getopt(argc, argv, "i:d:fh")) != -1)
    {
        switch(opt)
        {
            case 'i':
                strncpy(vpn_ifname, optarg, sizeof(vpn_ifname));
                break;
            case 'd':
                g_debug_level = atoi(optarg);
                break;
            case 'f':
                nodaemon = 1;
                break;
            case 'h':
                break; 
        }
    }

    if(!nodaemon)
    {
        daemon(0, 0);
    }

    /* 组间消息以及进程间消息处理 */
    rpcd_loop();  

    return 0;
}
