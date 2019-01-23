
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>

#include "ipfw.h"

static void ipset_do_command(const char *fmt, ...)
{
    va_list vargs;
    char *fmt_cmd = NULL;
    char *cmd = NULL;
    
    va_start(vargs, fmt);
    vasprintf(&fmt_cmd, fmt, vargs);
    va_end(vargs);
    
    asprintf(&cmd, "/usr/sbin/ipset %s", fmt_cmd);
    
    if (cmd)
    {
        system(cmd);        
    }

    if (fmt_cmd)
    {
        free(fmt_cmd);
    }

    if (cmd)
    {
        free(cmd);
    }
}

static void iptables_do_command(const char *fmt, ...)
{
    va_list vargs;
    char *fmt_cmd = NULL;
    char *cmd = NULL;
    
    va_start(vargs, fmt);
    vasprintf(&fmt_cmd, fmt, vargs);
    va_end(vargs);
    
    asprintf(&cmd, "/usr/sbin/iptables %s", fmt_cmd);
    
    if (cmd)
    {
        system(cmd);
    }

    if(fmt_cmd)
    {
        free(fmt_cmd);
    }

    if(cmd)
    {
        free(cmd);
    }
}

void ipfw_init(char *gw_address, int gw_port)
{
    ipset_do_command("create " IPSET_WHITEIP " hash:ip");

    iptables_do_command("-t nat -N " CHAIN_NAT);
    iptables_do_command("-t nat -I PREROUTING  -j " CHAIN_NAT); 
    iptables_do_command("-t nat -A " CHAIN_NAT " -d %s -j ACCEPT", gw_address);
    iptables_do_command("-t nat -A " CHAIN_NAT " -m set --match-set " IPSET_WHITEIP " src -p tcp -j ACCEPT");
    iptables_do_command("-t nat -A " CHAIN_NAT " -p tcp --dport 80 -j REDIRECT --to-ports %d", gw_port);
}

void ipfw_destroy()
{
    iptables_do_command("-t nat -D PREROUTING -j " CHAIN_NAT);
    iptables_do_command("-t nat -F " CHAIN_NAT);
    iptables_do_command("-t nat -X " CHAIN_NAT);
    
    ipset_do_command("flush " IPSET_WHITEIP);
    ipset_do_command("destroy " IPSET_WHITEIP);
}

void ipfw_allow_user(char *ip)
{
    ipset_do_command("add " IPSET_WHITEIP " %s", ip);
}

void ipfw_deny_user(char *ip)
{
    ipset_do_command("del " IPSET_WHITEIP " %s", ip);
}

