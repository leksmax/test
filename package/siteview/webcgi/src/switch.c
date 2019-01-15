
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "webcgi.h"
#include "switch.h"

#define GET_BIT(val, i) ((val & (1 << i)) >> i)

struct switch_vlan sw;

int portMap[] = {0, 5, 4, 3, 2, 1, 6};

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

/* [Status]:DISABLE/ENABLE */
static int ssdk_get_port_linkstatus(int port, int *link)
{
    int ret = 0;
    FILE *fp = NULL;
    size_t rlen = 0;
    char buf[256] = {0};
    char *pt = NULL;
    
    snprintf(buf, sizeof(buf), "ssdk_sh port linkstatus get %d", port);
    if ((fp = popen(buf, "r")) == NULL)
    {
        //log_error("%s: Run [%s] fail!\n", __func__, buf);
        return -1;
    }

    rlen = fread(buf, 1, sizeof(buf), fp);
    pclose(fp);
    
    if (rlen <= 1)
    {
        return -1;
    }
    
    buf[rlen - 1] = '\0';
    if ((pt = strstr(buf, "[Status]:")) == NULL)
    {
        return -1;
    }

    pt += 9; // strlen of "[Status]:"
    if (!strncmp(pt, "ENABLE", 6)) 
    {
        *link = LINK_UP;
    }
    
    return 0;
}

/* [speed]:10(Mbps) */
static int ssdk_get_port_speed(int port, int *speed)
{
    int ret = 0;
    FILE *fp = NULL;
    size_t rlen = 0;
    char buf[256] = {0};
    char *pt = NULL;
    
    snprintf(buf, sizeof(buf), "ssdk_sh port speed get %d | grep OK", port);
    if ((fp = popen(buf, "r")) == NULL)
    {
        //log_error("%s: Run [%s] fail!\n", __func__, buf);
        return -1;
    }

    rlen = fread(buf, 1, sizeof(buf), fp);
    
    pclose(fp);
    
    if (rlen <= 1)
    {
        return -1;
    }
    buf[rlen - 1] = '\0';
    
    if ((pt = strstr(buf, "[speed]:")) == NULL)
    {
        return -1;
    }

    pt += 8; // strlen of "[speed]:"
    if (!strncmp(pt, "1000", 4)) 
    {
        *speed = SPEED_1000;
    }
    else if (!strncmp(pt, "100", 3))
    {
       *speed = SPEED_100;
    }
    else
    {
        *speed = SPEED_10;
    }
    
    return 0;
}

/* [duplex]:HALF/FULL */
static int ssdk_get_port_duplex(int port, int *duplex)
{
    int ret = 0;
    FILE *fp = NULL;
    size_t rlen = 0;
    char buf[256] = {0};
    char *pt = NULL;
    
    snprintf(buf, sizeof(buf), "ssdk_sh port duplex get %d", port);
    if ((fp = popen(buf, "r")) == NULL)
    {
        //log_error("%s: Run [%s] fail!\n", __func__, buf);
        return -1;
    }

    rlen = fread(buf, 1, sizeof(buf), fp);
    
    pclose(fp);
    
    if (rlen <= 1)
    {
        return -1;
    }
    buf[rlen - 1] = '\0';
    
    if ((pt = strstr(buf, "[duplex]:")) == NULL)
    {
        return -1;
    }

    pt += 9; // strlen of "[duplex]:"
    if (!strncmp(pt, "FULL", 4)) 
    {
        *duplex = DUPLEX_FULL;
    }  
    
    return 0;
}


#define SYSDEPS_SWITCH_API

int libgw_get_port_status(int port, port_info_t *info)
{
    int ret = 0;
    int phyPort = 0;
    
    if (port < 1 || port > MAX_PANNEL_PORT)
    {
        return -1;
    }

    phyPort = pannelPort_to_phyPort(port);

    info->port = port;
    
    ret = ssdk_get_port_linkstatus(phyPort, &info->link);
    if (ret < 0)
    {
        return -1;
    }

    if (info->link == LINK_UP)
    {
        ret += ssdk_get_port_speed(phyPort, &info->speed);
        ret += ssdk_get_port_duplex(phyPort, &info->duplex);
    }
    
    return ret;
}

#define SWITCH_CGI

int get_port_status(cgi_request_t *req, cgi_response_t *resp)
{
    int i = 0;
    int ret = 0;
    port_info_t info;    

    webs_json_header(req->out);
    webs_write(req->out, "{\"code\":%d,\"data\":{", cgi_errno);
    webs_write(req->out, "\"num\":%d,\"ports\":[", MAX_PANNEL_PORT);

    for (i = 1; i <= MAX_PANNEL_PORT; i ++)
    {
        memset(&info, 0x0, sizeof(port_info_t));
        ret = libgw_get_port_status(i, &info);
        if (ret < 0)
        {
            //continue;
        }
        
        webs_write(req->out, "%s{\"port\":%d,\"link\":%d,\"duplex\":%d,\"speed\":%d}",
            (i == 1) ? "" : ",", info.port, info.link, info.duplex, info.speed);
    }
    
    webs_write(req->out, "]}}");

    return 0;
}


#define VLAN_CGI

int ports_to_pbmp(int vlan, char *ports)
{
    char *res = NULL;
    char *delims = " ";
    
    res = strtok(ports, delims);
    
    while (res != NULL)
    {
        int port = 0;
        char attr;

        sscanf(res, "%d%c", &port, &attr);

        sw.vlan_bmp[vlan] |= (1 << port);
        if (attr == 't')
        {
            sw.t_vlan_bmp[vlan] |= (1 << port);
        }
        
        res = strtok(NULL, delims);
    }

    return 0;
}

int pbmp_to_ports(int vlan, char *ports, int len)
{
    int i = 0;
    int n = 0;
    int cnt = 0;

    for (i = 1; i <= MAX_PANNEL_PORT; i ++)
    {
        if (!GET_BIT(sw.vlan_bmp[vlan], i))
        {
            continue;
        }
        
        if (GET_BIT(sw.t_vlan_bmp[vlan], i))
        {
            cnt += snprintf(ports + cnt, len - cnt, "%s\"%dt\"", (n > 0) ? "," : "", i);
        }
        else
        {
            cnt += snprintf(ports + cnt, len - cnt, "%s\"%d\"", (n > 0) ? "," : "", i);
        }
        
        n ++;
    }

    return 0;
}

#if 0
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
        if (attr == 't') 
        {
            sw.t_vlan_bmp[vlan] |= (1 << phyPort); /* vlan tagged port member */
        }
        else
        {
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
        {
            cnt += snprintf(ports + cnt, len - cnt, "%s\"%dt\"", (n > 0) ? "," : "", port);
        }
        else
        {
            cnt += snprintf(ports + cnt, len - cnt, "%s\"%d\"", (n > 0) ? "," : "", port);
        }
        
        n ++;
    }

    return 0;
}
#endif

int get_port_vlans(int phyPort, char *vlans, int len)
{
    int i = 0;
    int cnt = 0;
    char hit = 0;

    for (i = 0; i < sw.vlan_entry; i ++)
    {
        /* 判断port是否属于该vlan */
        if (GET_BIT(sw.vlan_bmp[i], phyPort))
        {
            /* 是否tagged */
            if (GET_BIT(sw.t_vlan_bmp[i], phyPort))
            {
                cnt += snprintf(vlans + cnt, len - cnt, "%s\"%dt\"", (hit > 0 ? "," : ""), i + 1);                
            }
            else
            {
                cnt += snprintf(vlans + cnt, len - cnt, "%s\"%d\"", (hit > 0 ? "," : ""), i + 1);
            }

            hit ++;
        }
    }

    return 0;
}

#if 0
/*  */
int ports_to_pbmp(char *ports, char *delims, vlan_cfg_t *vlan)
{
    char *res = NULL;
    
    res = strtok(ports, delims);
    while (res != NULL)
    {
        int port = 0;
        char attr;

        sscanf(res, "%d%c", &port, &attr);

        vlan->vlan_bmp |= (1 << port);
        if (attr == 't') {
            vlan->t_vlan_bmp |= (1 << port);
        }
        
        res = strtok(NULL, delims);
    }

    return 0;    
}
#endif

void _uci_switch_add_vlan(FILE *fp, vlan_cfg_t *cfg)
{
    fprintf(fp, "config vlan\n");
    fprintf(fp, "\toption name '%s'\n", cfg->name);
    fprintf(fp, "\toption vlan '%d'\n", cfg->vlan);
    fprintf(fp, "\toption vid '%d'\n", cfg->vid);
    fprintf(fp, "\toption ports '%s'\n", cfg->ports);
    fprintf(fp, "\toption desc '%s'\n", cfg->desc);
    fprintf(fp, "\n");
}

void _uci_switch_add_port(FILE *fp, port_cfg_t *cfg)
{
    fprintf(fp, "config switch_port\n");
    fprintf(fp, "\toption name '%s'\n", cfg->name);
    fprintf(fp, "\toption port '%d'\n", cfg->port);
    fprintf(fp, "\toption pvid '%d'\n", cfg->pvid);
    fprintf(fp, "\n");
}

void vlan_entry_commit()
{
    int i = 0;
    int ret = 0;
    FILE *fp = NULL;
    struct vlan_alias *v;
    vlan_cfg_t vlan;

    fp = fopen("/etc/config/switch", "w");
    if (!fp)
    {
        return ;
    }

    list_for_each_entry(v, &sw.vlans, list) 
    {
        memset(&vlan, 0x0, sizeof(vlan_cfg_t));
        
        vlan.vlan = v->vlan;
        vlan.vid = sw.vid[vlan.vlan];
        strncpy(vlan.name, v->name, sizeof(vlan.name) - 1);
        strncpy(vlan.desc, v->desc, sizeof(vlan.desc) - 1);
        pbmp_to_ports(vlan.vlan, vlan.ports, sizeof(vlan.ports));

        _uci_switch_add_vlan(fp, &vlan);
    }

}


int switch_config_init()
{
    int ret = 0;
    vlan_cfg_t vlan;
    port_cfg_t port;
    struct uci_context *ctx;
    struct uci_package *pkg = NULL;
    struct uci_element *e;

    ctx = uci_alloc_context();
    if (!ctx) 
    {
        return -1;
    }

    uci_load(ctx, "switch", &pkg);
    if (!pkg) 
    {
        ret = -1;
        goto out;
    }

    memset(&sw, 0x0, sizeof(struct switch_vlan));
    
    INIT_LIST_HEAD(&sw.vlans);
    INIT_LIST_HEAD(&sw.ports);
    
    uci_foreach_element(&pkg->sections, e) 
    {  
        struct uci_element *n;
        struct uci_section *s = uci_to_section(e);

        if (!strcmp(s->type, "vlan"))
        {
            memset(&vlan, 0x0, sizeof(vlan_cfg_t));
            
            uci_foreach_element(&s->options, n) 
            {
                struct uci_option *o = uci_to_option(n);
                
                if (o->type != UCI_TYPE_STRING)
                {
                    continue;
                }
                
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
                else if (!strcmp(o->e.name, "desc"))
                {
                    strncpy(vlan.desc, o->v.string, sizeof(vlan.desc) - 1);
                }
            }

            struct vlan_alias *p = NULL;

            p = (struct vlan_alias *)malloc(sizeof(struct vlan_alias));
            if (!p)
            {
                continue;
            }

            p->vlan = vlan.vid;
            strncpy(p->name, vlan.name, sizeof(p->name) - 1);
            strncpy(p->desc, vlan.desc, sizeof(p->desc) - 1);
            
            list_add_tail(&p->list, &sw.vlans);

            sw.vid[vlan.vid] = vlan.vid;           
            ports_to_pbmp(vlan.vid, vlan.ports);
            sw.vlan_entry ++;
        }

#if 0
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
            sw.pvid[phyPort] = port.pvid;
        }
#endif

    } 

    uci_unload(ctx, pkg);
out:
    uci_free_context(ctx);

    return ret;
}

#define SWITCH_VLAN_API

int get_vlan_entry(cgi_request_t *req, cgi_response_t *resp)
{
    int i = 0;
    int ret = 0;
    int vlan = 0;
    char ports[128];
    struct vlan_alias *v;

    /* 读配置 */
    ret = switch_config_init();
    if (ret < 0)
    {
        cgi_errno = CGI_ERR_CFG_PARAM;
        goto out;
    }

    webs_json_header(req->out);
    webs_write(req->out, "{\"code\":%d,\"data\":{", cgi_errno);
    webs_write(req->out, "\"num\":%d", sw.vlan_entry);
    webs_write(req->out, ",\"entry\":[");

    list_for_each_entry(v, &sw.vlans, list)
    {
        vlan = v->vlan;
    
        webs_write(req->out, "%s{\"id\":%d", (i > 0 ? "," : ""), i + 1);
        webs_write(req->out, ",\"vid\":%d", sw.vid[vlan]);
        
        pbmp_to_ports(vlan, ports, sizeof(ports));
        webs_write(req->out, ",\"ports\":[%s]", ports);

        webs_write(req->out, ",\"name\":\"%s\"", v->name);
        webs_write(req->out, ",\"desc\":\"%s\"}", v->desc);
        
        i ++;
    }

    webs_write(req->out, "]}}");

out:

    if (cgi_errno != CGI_ERR_OK)
    {
        webs_json_header(req->out);
        webs_write(req->out, "{\"code\":%d,\"data\":{}}", cgi_errno);
    }

    return 0;
}

int parse_json_vlan_cfg(cJSON *params, vlan_cfg_t *cfg)
{
    int ret = 0;
    int intval = 0;
    cJSON *val = NULL;
    char *strval = NULL;

    strval = cjson_get_string(params, "name");
    if (!strval)
    {
        return -1;
    }

    strncpy(cfg->name, strval, sizeof(cfg->name) - 1);

    ret = cjson_get_int(params, "vid", &intval);
    if (ret < 0)
    {
        return -1;
    }

    cfg->vid = intval;

    val = cJSON_GetObjectItem(params, "ports");
    if (!val || val->type != cJSON_Array)
    {
        return -1;
    }

    cJSON *c = val->child;
    while (c)
    {
        if (c->type != cJSON_String)
        {
            return -1;
        }
        
        c = c->next;
    }

    strval = cjson_get_string(params, "desc");
    if (!strval)
    {
        return -1;
    }

    strncpy(cfg->desc, strval, sizeof(cfg->desc) - 1);

    return 0;
}

int vlan_entry_add(cJSON *params)
{
    int ret = 0;
    vlan_cfg_t cfg;

    memset(&cfg, 0x0, sizeof(vlan_cfg_t));

    if (sw.vlan_entry >= MAX_VLAN_ENTRY)
    {
        return CGI_ERR_CFG_OVERMUCH;
    }

    ret = parse_json_vlan_cfg(params, &cfg);
    if (ret < 0)
    {
        return CGI_ERR_CFG_PARAM;
    }

    return 0;
}

int vlan_entry_edit(cJSON *params)
{
    return 0;
}

int vlan_entry_del(cJSON *params)
{
    return 0;
}

int vlan_entry_config(cgi_request_t *req, cgi_response_t *resp)
{
    int ret = 0;
    int method = 0;
    cJSON *params = NULL;

    ret = param_init(req->post_data, &method, &params);
    if (ret < 0)
    {
        cgi_errno = CGI_ERR_PARAM;
        goto out;
    }
    
    ret = switch_config_init();
    if (req < 0)
    {
        cgi_errno = CGI_ERR_CFG_FILE;
        goto out;
    }

    switch(method)
    {
        case CGI_ADD:
            cgi_errno = vlan_entry_add(params);
            break;
        case CGI_SET:
            cgi_errno = vlan_entry_edit(params);
            break;
        case CGI_DEL:
            cgi_errno = vlan_entry_del(params);
            break;
        default:
            cgi_errno = CGI_ERR_NOT_FOUND;
            break;
    }

    if (cgi_errno == CGI_ERR_OK)
    {
        vlan_entry_commit();
        /* 重新初始化VLAN配置 */
        //fork_exec(1, "/etc/init.d/switch restart");
    }
out:
    param_free();
    
    webs_json_header(req->out);
    webs_write(req->out, "{\"code\":%d,\"data\":{}}", cgi_errno);       

    return 0;
}

#define SWITCH_PORT_API

int port_vlan_list(cgi_request_t *req, cgi_response_t *resp)
{
    int i = 0;
    int ret = 0;
    int phyPort = 0;
    char vlans[128] = {0};

    /* 读配置 */
    ret = switch_config_init();
    if (ret < 0)
    {
        cgi_errno = CGI_ERR_CFG_FILE;
        goto out;
    }

    webs_json_header(req->out);
    webs_write(req->out, "{\"code\":%d,\"data\":{", cgi_errno);
    webs_write(req->out, "\"num\":%d", MAX_PANNEL_PORT);
    webs_write(req->out, ",\"port\":[");

    /* 遍历   switch port vlan 配置 */

    for (i = 1; i <= MAX_PANNEL_PORT; i ++)
    {
        webs_write(req->out, "%s{\"id\":%d", i > 1 ? "," : "", i);
        phyPort = pannelPort_to_phyPort(i);
        webs_write(req->out, ",\"pvid\":%d", sw.pvid[phyPort]);
        get_port_vlans(phyPort, vlans, sizeof(vlans));
        webs_write(req->out, ",\"vlans\":[%s]}", vlans);
    }

    webs_write(req->out, "]}}");

out:
    
    if (cgi_errno != CGI_ERR_OK)
    {
        webs_json_header(req->out);
        webs_write(req->out, "{\"code\":%d,\"data\":{}}", cgi_errno);
    }

    return 0;
}

int port_vlan_edit(cJSON *params)
{
    return 0;
}

int port_vlan_config(cgi_request_t *req, cgi_response_t *resp)
{
    int ret = 0;
    int method = 0;
    cJSON *params = NULL;
    char *strVal = NULL;
    
    ret = param_init(req->post_data, &method, &params);
    if (ret < 0)
    {
        cgi_errno = CGI_ERR_PARAM;
        goto out;
    }

    ret = port_vlan_edit(params);
    if (ret < 0)
    {
           
    }

    //port_vlan_commit();

    /* 重新初始化VLAN配置 */
out:    
    param_free();

    webs_json_header(req->out);
    webs_write(req->out, "{\"code\":%d,\"data\":{}}", cgi_errno);    

    return 0;
}
