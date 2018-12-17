
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <sys/sysinfo.h>

#include "session.h"
#include "servlet.h"
#include "utils.h"

extern int cgi_errno;

void cgi_request_free(cgi_request_t *req)
{
    if (!req)
    {
        return ;
    }

    if (req->url)
    {
        free(req->url);
    }

    if (req->post_data)
    {
        free(req->post_data);
    }

    if (req->sess)
    {
        free(req->sess);
    }

    free(req);
}

void cgi_reponse_free(cgi_response_t *resp)
{
    if (!resp)
    {
        return ;
    }
    
    free(resp);
}

int do_handler(cgi_handler_t *map[], cgi_request_t *req, cgi_response_t *resp)
{
    int ret = 0;
    struct sysinfo s_info;
	cgi_handler_t *current = NULL;

	if (req->url == NULL)
    {
        return ret;
	}

	for (current = map; current->url != NULL; current ++) 
    {    
		if (strcmp(req->url, current->url) == 0)
        {      
            break;
        }
	}

    if (!current->url)
    {
        cgi_errno = 501;
    }

    /*
     * 检查session信息
     */  
    sysinfo(&s_info);
    
    if ((current->auth & PRIV_GUEST) || (current->auth & PRIV_ADMIN))
    {    
        if (strcmp(req->ipaddr, req->sess->ipaddr) != 0)
        {
            cgi_errno = CGI_ERR_AUTH_REQUIRED;
        }
        else if ((s_info.uptime - req->sess->last_active) > SESSION_TIMEOUT)
        {
            cgi_errno = CGI_ERR_AUTH_TIMEOUT;
        }
        else
        {   
            req->sess->last_active = s_info.uptime;
            update_cgi_session(req->sess);
        }
    }

    if (cgi_errno != CGI_ERR_OK)
    {
        webs_json_header(req->out);
        webs_write(req->out, "{\"code\":%d,\"data\":{}}", cgi_errno);
    }
    else
    {
	    ret = current->handler(req, resp);
    }
    
	return ret;
}

int process_request(cgi_request_t *req)
{
    char *envStr = NULL;
    char *content_len = NULL;
    char *content_type = NULL;
    
    envStr = getenv("REQUEST_METHOD");    
    if (envStr != NULL)
    {
        strncpy(req->method, envStr, sizeof(req->method) - 1);
    }

    envStr = getenv("REMOTE_ADDR");
    if (envStr != NULL)
    {
        strncpy(req->ipaddr, envStr, sizeof(req->ipaddr) - 1);
    }

    envStr = getenv("PATH_INFO");
    if (envStr != NULL)
    {
        req->url = strdup(envStr);
    }

    envStr = getenv("QUERY_STRING");
    if (envStr != NULL)
    {
        
    }

    req->out = stdout;
    
    content_len = getenv("CONTENT_LENGTH");
    content_type = getenv("CONTENT_TYPE");

    /* 主要对POST请求处理，文件上传，form表单... */
    if (strcmp(req->method, "POST") == 0) 
    {
        int inlen = 0;
        int nread = 0;

        inlen = strtol(content_len, NULL, 10);
        if (inlen <= 0)
        {
            return -1;
        }
    
        if (!content_type)
        {
            return -1;
        }

        req->post_len = inlen;

        /* 
         * 文件上传, 这里不建议直接接收文件
         */
        if (strncmp(content_type, MULTIPART_CONTENT_TYPE, strlen(MULTIPART_CONTENT_TYPE)) == 0) 
        {
            req->file_upload = 1;
        }
        else
        {
            /*
             * 这里可以对CGI POST最大数据长度做限制 
             */
            req->post_data = (char *)malloc(inlen + 1);
            if (!req->post_data)
            {
                return -1;
            }
            
            fread(req->post_data, inlen, 1, stdin);
            req->post_data[inlen] = '\0';
        }
    }
        
    return 0;
}

int cgi_servlet_init(cgi_handler_t *map[])
{
    int ret = 0;
    cgi_request_t *req = NULL;
    cgi_response_t *resp = NULL;    

	req = malloc(sizeof(cgi_request_t));
	resp = malloc(sizeof(cgi_response_t));
    if (!req || !resp)
    {
        /* 这里可以返回500错误 */
        goto out;
    }

    memset(req, 0x0, sizeof(cgi_request_t));
    memset(resp, 0x0, sizeof(cgi_response_t));

    req->sess = session_init();
    if (!req->sess)
    {
        /* 这里可以返回500错误 */
        goto out;        
    }

    get_cgi_session(req->sess);

    ret = process_request(req);
    if (ret < 0)
    {
        
    }

    ret = do_handler(map, req, resp);
    if (ret < 0)
    {
        
    }

out:
    cgi_request_free(req);
    cgi_reponse_free(resp);

    return ret;
}

