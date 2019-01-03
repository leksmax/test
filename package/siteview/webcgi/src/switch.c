
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "webcgi.h"
#include "switch.h"

#define GET_BIT(val, i) ((val & (1 << i)) >> i)

struct switch_vlan sw;

int portMap[] = {0, 1, 2, 3, 4, 5, 6};

int getCpuPort(int phyPort)
{
    if(phyPort == 0 || phyPort == 5)
        return 0;
    else
        return 6;
}

int phyPort_to_pannelPort(int phyPort)
{
    int i;

    for(i = 0; i < MAX_PHY_PORT; i ++)
    {
        if(portMap[i] == phyPort)
        {
            return i;
        }
    }

    return -1;
}

int pannelPort_to_phyPort(int port)
{
    if(port > MAX_PANNEL_PORT)
    {
        return -1;
    }
    
    return portMap[port];
}


int ports_to_pbmp(int vlan, char *ports)
{
    int cpuPort = 0;
    int phyPort = 0;  
    char *res = NULL;
    char *delims = " ";
    
    res = strtok(ports, delims);
    
    while (res != NULL)
    {
        int port = 0;
        char attr;

        sscanf(res, "%d%c", &port, &attr);

        /* 端口转换 */
        phyPort = pannelPort_to_phyPort(port);        
		cpuPort = getCpuPort(phyPort);

        /* CPU Port */
        sw.vlan_bmp[vlan] |= (1 << cpuPort);
        sw.t_vlan_bmp[vlan] |= (1 << cpuPort);

        /* PHY Port */
        sw.vlan_bmp[vlan] |= (1 << phyPort); /* vlan port */
        if (attr == 't') {
            sw.t_vlan_bmp[vlan] |= (1 << phyPort); /* vlan tagged port member */
        }
        else {
            sw.pvid[phyPort] = sw.vid[vlan]; /* untagged port vlan成员的PVID必须与该vlan的vid相等 */
        }
        
        res = strtok(NULL, delims);
    }

    return 0;
}

/*
 * 这里转换时不带cpu的，port需要转换成面板端口
 */
int pbmp_to_ports(int vlan, char *ports, int len)
{
    int i = 0;
    int n = 0;
    int cnt = 0;
    int port;

    pbmp_t v = 0;
    pbmp_t tv;

    v = sw.vlan_bmp[vlan];
    tv = sw.t_vlan_bmp[vlan];

    for (i = 0; i < MAX_PHY_PORT; i ++)
    {
        if (!GET_BIT(v, i))
            continue;
        
        if (getCpuPort(i) == i) /* 不计入cpu端口 */
            continue;

        port = phyPort_to_pannelPort(i);
        
        if (GET_BIT(tv, i))
            cnt += snprintf(ports + cnt, len - cnt, "%s%dt", (n > 0) ? " " : "", port);
        else
            cnt += snprintf(ports + cnt, len - cnt, "%s%d", (n > 0) ? " " : "", port);

        n ++;
    }

    return 0;
}

/*
 * 这里转换出来是带cpu的，port也是实际phy port序号
 */
int pbmp_to_phyPorts(int vlan, char *phyPorts, int len)
{
    int i = 0;
    int n = 0;
    int cnt = 0;

    pbmp_t v;
    pbmp_t tv;

    v = sw.vlan_bmp[vlan];
    tv = sw.t_vlan_bmp[vlan];

    for (i = 0; i < MAX_PHY_PORT; i ++)
    {
        if (!GET_BIT(v, i))
            continue;

        if (GET_BIT(tv, i))
            cnt += snprintf(phyPorts + cnt, len - cnt, "%s%dt", (n > 0) ? " " : "", i);
        else
            cnt += snprintf(phyPorts + cnt, len - cnt, "%s%d", (n > 0) ? " " : "", i);

        n ++;
    }

    return 0;
}

int switch_config_init()
{
    switch_vlan_t vlan;
    switch_port_t port;
    struct uci_context *ctx;
    struct uci_package *pkg = NULL;
    struct uci_element *e;

    ctx = uci_alloc_context();
    if (!ctx) {
        //log_error("");
        return -1;
    }

    uci_load(ctx, "switch", &pkg);
    if (!pkg) {
        //log_error("");
        goto out;
    }

    memset(&sw, 0x0, sizeof(struct switch_vlan));
    
    uci_foreach_element(&pkg->sections, e) 
    {  
        struct uci_element *n;
        struct uci_section *s = uci_to_section(e);

        if (!strcmp(s->type, "vlan"))
        {
            memset(&vlan, 0x0, sizeof(switch_vlan_t));
            
            uci_foreach_element(&s->options, n) 
            {
                struct uci_option *o = uci_to_option(n);
                
                if (o->type != UCI_TYPE_STRING)
                    continue;
                
                if (!strcmp(o->e.name, "name"))
                {
                    strncpy(vlan.name, o->v.string, sizeof(vlan.name) - 1);
                }
                else if (!strcmp(o->e.name, "vlan"))
                {
                    vlan.vlan = atoi(o->v.string);
                }
                else if (!strcmp(o->e.name, "vid"))
                {
                    vlan.vid = atoi(o->v.string);
                }
                else if (!strcmp(o->e.name, "ports"))
                {
                    strncpy(vlan.ports, o->v.string, sizeof(vlan.ports) - 1);
                }
            }

            sw.vid[sw.vlan_entry] = vlan.vid;           
            ports_to_pbmp(sw.vlan_entry, vlan.ports);
                        
            sw.vlan_entry ++;
        }
        else if (!strcmp(s->type, "port"))
        {
            int phyPort;
            memset(&port, 0x0, sizeof(switch_port_t));
            
            uci_foreach_element(&s->options, n) 
            {
                struct uci_option *o = uci_to_option(n);
                
                if (o->type != UCI_TYPE_STRING)
                    continue;
                
                if (!strcmp(o->e.name, "port"))
                {
                    port.port = atoi(o->v.string);
                }
                else if (!strcmp(o->e.name, "pvid"))
                {
                    port.pvid = atoi(o->v.string);
                }
            }

            phyPort = pannelPort_to_phyPort(port.port);
            sw.pvid[phyPort] = port.pvid;
        }
    } 

    uci_unload(ctx, pkg);
    out:
    uci_free_context(ctx);

    return 0;
}

void sw_conf_add_switch(FILE *fp, char *device)
{
    fprintf(fp, "\n");
    fprintf(fp, "config switch\n");
    fprintf(fp, "\toption name '%s'\n", device);
    fprintf(fp, "\toption reset '1'\n");
    fprintf(fp, "\toption enable_vlan '1'\n");
    fprintf(fp, "\n");
}

void sw_conf_add_vlan(FILE *fp, char *device, int vlan,
        int vid, char *ports)
{
    fprintf(fp, "config switch_vlan\n");
    fprintf(fp, "\toption device '%s'\n", device);
    fprintf(fp, "\toption vlan '%d'\n", vlan);
    fprintf(fp, "\toption vid '%d'\n", vid);
    fprintf(fp, "\toption ports '%s'\n", ports);
    fprintf(fp, "\n");
}

void sw_conf_add_port(FILE *fp, char *device, int port, int pvid)
{
    fprintf(fp, "config switch_port\n");
    fprintf(fp, "\toption device '%s'\n", device);
    fprintf(fp, "\toption port '%d'\n", port);
    fprintf(fp, "\toption pvid '%d'\n", pvid);
    fprintf(fp, "\n");
}

/*
 * swconfig配置pvid有些问题，
 * 这里直接调用ssdk去修改
 */
void ssdk_port_pvid_fix()
{
    int i;
//    int phyPort;

    for (i = 1; i <= MAX_PANNEL_PORT; i ++) {
//        phyPort = pannelPort_to_phyPort(i);
        //sys_exec("ssdk_sh portVlan defaultCvid set %d %d", phyPort, sw.pvid[phyPort]);
    }
}

/* VLAN初始化 */
void sw_config_vlan()
{
    int i = 0;
    int phyPort;
    char phyPorts[128];
    FILE *fp = NULL;
    char *device = "switch0";

    /* 读配置 */
    switch_config_init();

    fp = fopen("/tmp/sw.conf", "w");
    if (!fp) {
        //log_error("");
        return;
    }

    sw_conf_add_switch(fp, device);

    /* VLAN */
    for (i = 0; i < sw.vlan_entry; i ++) {
        pbmp_to_phyPorts(i, phyPorts, sizeof(phyPorts));
        sw_conf_add_vlan(fp, device, i + 1, sw.vid[i], phyPorts);
    }

    /* PVID */
    for (i = 1; i <= MAX_PANNEL_PORT; i ++) {
        phyPort = pannelPort_to_phyPort(i);
        sw_conf_add_port(fp, device, phyPort, sw.pvid[phyPort]);
    }
    
    fclose(fp);

    //sys_exec("swconfig dev %s load %s", device, "/tmp/sw.conf");

    //ssdk_port_pvid_fix();
}


