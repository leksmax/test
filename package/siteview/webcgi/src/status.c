
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "webcgi.h"
#include "status.h"

#if 0
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
        return -2;
    }

    rlen = fread(buf, 1, sizeof(buf), fp);
    
    pclose(fp);
    
    if (rlen <= 1)
    {
        return -3;
    }
    buf[rlen - 1] = '\0';
    
    if ((pt = strstr(buf, "[Status]:")) == NULL)
    {
        //
    }

    pt += 9; // strlen of "[Status]:"
    if (!strncmp(pt, "ENABLE", 6)) 
    {
        return LINK_UP;
    }
    
    return 0;
}

/* [speed]:10(Mbps) */
static int ssdk_get_port_speed(int port)
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
        return -2;
    }

    rlen = fread(buf, 1, sizeof(buf), fp);
    
    pclose(fp);
    
    if (rlen <= 1)
    {
        return -3;
    }
    buf[rlen - 1] = '\0';
    
    if ((pt = strstr(buf, "[speed]:")) == NULL)
    {
        //
    }

    pt += 8; // strlen of "[speed]:"
    if (!strncmp(pt, "1000", 4)) 
    {
        return SPEED_1000;
    }
    else if (!strncmp(pt, "100", 3))
    {
        return SPEED_100;
    }
    else
    {
        return SPEED_10;
    }
    
    return 0;
}

/* [duplex]:HALF/FULL */
static int ssdk_get_port_duplex(int port)
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
        return -2;
    }

    rlen = fread(buf, 1, sizeof(buf), fp);
    
    pclose(fp);
    
    if (rlen <= 1)
    {
        return -3;
    }
    buf[rlen - 1] = '\0';
    
    if ((pt = strstr(buf, "[duplex]:")) == NULL)
    {
        //
    }

    pt += 9; // strlen of "[duplex]:"
    if (!strncmp(pt, "FULL", 4)) 
    {
        return DUPLEX_FULL;
    }  
    
    return 0;
}

int libgw_get_port_mib(int port)
{
    return 0;
}

int libgw_get_port_status(int port, port_info_t *info)
{
    int phyPort = 0;
    
    if (port < 1 || port > MAX_PANNEL_PORT)
    {
        return -1;
    }

    phyPort = pannelPort_to_phyPort(port);

    info->port = port;
    info->link = ssdk_get_port_linkstatus(phyPort);
    info->speed = ssdk_get_port_speed(phyPort);
    info->duplex = ssdk_get_port_duplex(phyPort);
    
    return 0;
}

#endif

int dump_lanx_devices(FILE *out, char *suffix)
{
    int try = 0;
    int rlen = 0;
    int line_buf[100];
    char dump_file[64] = {0};
    FILE *fp = NULL;

    snprintf(dump_file, sizeof(dump_file), "/tmp/networkmap_%s.json", suffix);

    while (try < 6)
    {   
        fp = fopen(dump_file, "r");
        if(!fp)
        {   
            usleep(200000);
        }
        else
        {
            break;
        }

        try ++;
    }
    
    while (fp)
    {   
        rlen = fread(line_buf, 1, sizeof(line_buf), fp);
        if(rlen <= 0)
        {   
            break;
        }   
        else
        {   
            fwrite(line_buf, 1, rlen, out);
        }   
    }  

    if (fp)
    {
        fclose(fp);
        unlink(dump_file);
    }
    
    return 0;
}

int get_attached_devices(cgi_request_t *req, cgi_response_t *resp)
{
    int ret = 0;
    int method = 0;    
    cJSON *params = NULL;
    char *lan_name = NULL;

    ret = param_init(req->post_data, &method, &params);
    if (ret < 0)
    {
        cgi_errno = CGI_ERR_PARAM;
        goto out;
    }

    lan_name = cjson_get_string(params, "lan");
    if (!lan_name)
    {
        cgi_errno = CGI_ERR_CFG_PARAM;
        goto out;
    }

    /* 发送信号，等待文件生成 */
    system("killall -USR1 networkmap");
    sleep(1);
    
    webs_json_header(req->out);
    webs_write(req->out, "{\"code\":%d,\"data\":{", cgi_errno);
    webs_write(req->out, "\"interface\":[");
        
//    if (lan_name[0] != '\0')
//    {
        dump_lanx_devices(req->out, "LAN1");
//    }
//    else
//    {
#if 0
        /* 遍历整个LAN */
        list_for_each_entry(, h, list) {
            dump_lanx_devices(req->out, xx->name)
        }
#endif
//    }
    
    webs_write(req->out, "]}}");
    
out:
    param_free();

    if (cgi_errno != CGI_ERR_OK)
    {
        webs_json_header(req->out);
        webs_write(req->out, "{\"code\":%d,\"data\":{}}", cgi_errno);
    }
    
    return 0;
}

