
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "webcgi.h"
#include "status.h"

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

