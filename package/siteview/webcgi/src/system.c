
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "webcgi.h"
#include "system.h"

#define SYSTEM_API

int do_reboot(cgi_request_t *req, cgi_response_t *resp)
{
    webs_json_header(req->out);
    webs_write(req->out, "{\"code\":0,\"data\":{}}");
    fork_exec(1, "reboot");

    return 0;
}

int do_factory_reset(cgi_request_t *req, cgi_response_t *resp)
{
    webs_json_header(req->out);
    webs_write(req->out, "{\"code\":0,\"data\":{}}");
    fork_exec(1, "jffs2reset -y && reboot");
    return 0;
}

int do_backup_config(cgi_request_t *req, cgi_response_t *resp)
{
    int ret = 0;
    FILE *fp = NULL;
    char rbuff[128];
    struct stat st;

    /* 生成备份配置文件 */
    //sys_exec("");
    
    ret = stat(BACKUP_FILE_PATH, &st);
    if (ret < 0)
    {   
        /* 创建配置文件出错 */
        cgi_errno = CGI_ERR_CREATE_BACKUP;
        goto out;
    }

#if 0
    webs_file_header(req->out);

    if(fp = fopen(cmd, "r+b")) {  
        do {
            int rs = fread(filebuf, 1, sizeof(filebuf), fp);
            fwrite(filebuf, rs, 1, stdout);
        } while(!feof(fp));
        
        fclose(fp);
    }
#endif
 
out:
    if (cgi_errno != CGI_ERR_OK)
    {
        webs_json_header(req->out);
        webs_write(req->out, "{\"code\":%d,\"data\":{}}", cgi_errno);
    }
    
    unlink(BACKUP_FILE_PATH);
    
    return 0;
}

int do_restore_config(cgi_request_t *req, cgi_response_t *resp)
{
    int ret = 0;

    if (!req->file_upload)
    {
        cgi_errno = CGI_ERR_UPLOAD;
        goto out;
    }

    ret = upload_file(stdin, req->post_len, RESTORE_FILE_PATH);
    if (ret < 0)
    {
        cgi_errno = CGI_ERR_UPLOAD;
        goto out;
    }

    /* 在此之前检查下配置是否完整 */
    //fork_exec("");

out:
    webs_json_header(req->out);
    webs_write(req->out, "{\"code\":%d,\"data\":{}}", cgi_errno);

    unlink(RESTORE_FILE_PATH);

    return 0;
}

#define FIRMWARE_API

int image_check(char *filepath)
{
    int ret = 0;
    FILE *fp = NULL;
    char result[128] = {0};
    char cmdbuff[128] = {0};

    snprintf(cmdbuff, sizeof(cmdbuff), "/sbin/dniimage check %s", filepath);

    fp = popen(cmdbuff, "r");
    if(!fp)
    {
        return -1;
    }

    fgets(result, sizeof(result), fp);

    pclose(fp);

    char tmp1[32] = {0};
    char tmp2[32] = {0};

    ret = sscanf(result, "%[^:]:%s", tmp1, tmp2);
    if(ret != 2)
    {
        return -1;
    }

    if(strcmp(tmp1, "success") == 0)
    {
        return 0;
    }
    else
    {
        return -1;
    }

    return 0;
}

int upgrade_check(cgi_request_t *req, cgi_response_t *resp)
{
    int ret = 0;
    int check_ok = 0;
    char upg_fw_ver[64] = {0}; /* 升级固件版本 */
    char curr_fw_ver[64] = {0}; /* 当前固件版本 */
    
    if (!req->file_upload)
    {
        cgi_errno = CGI_ERR_UPLOAD;
        goto out;
    }

    if (req->post_len > MAX_IMAGE_SIZE)
    {
        cgi_errno = CGI_ERR_FW_OVERSIZE;
        goto out;
    }

    strncpy(curr_fw_ver, cat_file("/firmware_version"), sizeof(curr_fw_ver) - 1);

    ret = upload_file(stdin, req->post_len, FIRMWARE_PATH);
    if (ret < 0)
    {
        cgi_errno = CGI_ERR_UPLOAD;
        goto out;
    }

    check_ok = image_check(FIRMWARE_PATH);
    if(check_ok < 0)
    {  
        cgi_errno = CGI_ERR_FW_CHECK;
    }

out:

    webs_json_header(req->out);
    if (cgi_errno == CGI_ERR_OK)
    {
        webs_write(req->out, "{\"code\":%d,\"data\":{\"firmware_ver\":\"%s\","
            "\"current_ver\":\"%s\"}}", cgi_errno, upg_fw_ver, curr_fw_ver);
    }
    else
    {
        webs_write(req->out, "{\"code\":%d,\"data\":{}}", cgi_errno);
        unlink(FIRMWARE_PATH);
    }

    return 0;
}

int firmware_upgrade(cgi_request_t *req, cgi_response_t *resp)
{
    int ret = 0;
    int method = 0;
    int upgrade = 0;
    char *strVal = NULL;
    int check_ok = 0;
    cJSON *params = NULL;

    ret = param_init(req->post_data, &method, &params);
    if (ret < 0)
    {
        cgi_errno = CGI_ERR_PARAM;
        goto out;
    }

    strVal = cjson_get_string(params, "upgrade_yes_no");
    if (ret < 0)
    {
        cgi_errno = CGI_ERR_CFG_PARAM;
        goto out;
    }

    if (strcmp(strVal, "yes") == 0)
    {
        upgrade = 1;
    }

    if (access(FIRMWARE_PATH, F_OK) == 0)
    {
        check_ok = 1;
    }
    else
    {
        cgi_errno = CGI_ERR_FW_NOT_FOUND;
    }
        
    if (upgrade && check_ok)
    {
        fork_exec(1, "/sbin/sysupgrade %s", FIRMWARE_PATH);
    }

out:

    webs_json_header(req->out);
    webs_write(req->out, "{\"code\":%d,\"data\":{}}", cgi_errno);

    if (cgi_errno != CGI_ERR_OK)
    {
        unlink(FIRMWARE_PATH);
    }
        
    return ret;
}

#define SYSTIME_API

int get_ntp_config(cgi_request_t *req, cgi_response_t *resp)
{
    int ret = 0;
    ntp_cfg_t ntp;
    time_t cur_time;

    cur_time = time(NULL);

    memset(&ntp, 0x0, sizeof(ntp_cfg_t));

#if 0
    ret = libgw_get_ntp_config(&ntp);
    if (ret < 0)
    {
        
    }
#endif

    webs_json_header(req->out);
    webs_write(req->out, "{\"code\":%d,\"data\":{", cgi_errno);
    webs_write(req->out, "\"enabled\":%d,\"server1\":\"%s\",\"server2\":\"%s\",\"timezone\":%d,"
            "\"current_time\":\"%d\"", ntp.enabled, ntp.server1, ntp.server2, 
            ntp.timezone, cur_time);
    webs_write(req->out, "}}");
    
    return 0;
}

int set_ntp_config(cgi_request_t *req, cgi_response_t *resp)
{
    int ret = 0;
    int method = 0;    
    cJSON *params = NULL;
    ntp_cfg_t ntp;

    ret = param_init(req->post_data, &method, &params);
    if (ret < 0)
    {
        cgi_errno = CGI_ERR_PARAM;
        goto out;
    }

    memset(&ntp, 0x0, sizeof(ntp_cfg_t));

#if 0
    ret = libg
#endif

out:
    webs_json_header(req->out);
    webs_write(req->out, "{\"code\":%d,\"data\":{}}", cgi_errno);  

    return 0;
}

int sync_current_time(cgi_request_t *req, cgi_response_t *resp)
{
    int ret = 0;
    int method = 0;
    cJSON *params = NULL;
    char *strVal = NULL;
    struct timeval tv;

    ret = param_init(req->post_data, &method, &params);
    if (ret < 0)
    {
        cgi_errno = CGI_ERR_PARAM;
        goto out;
    }

    strVal = cjson_get_string(params, "current_time");
    if (ret < 0)
    {
        cgi_errno = CGI_ERR_CFG_PARAM;
        goto out;
    }

    memset(&tv, 0x0, sizeof(struct timeval));
    tv.tv_sec = atoi(strVal);

    settimeofday(&tv, NULL);

out:
    webs_json_header(req->out);
    webs_write(req->out, "{\"code\":%d,\"data\":{}}", cgi_errno);
    
    return 0;
}

#define SYSLOG_API

int get_syslog_config(cgi_request_t *req, cgi_response_t *resp)
{
    webs_json_header(req->out);
    webs_write(req->out, "{\"code\":%d,\"data\":{}}", cgi_errno);
    return 0;
}

int set_syslog_config(cgi_request_t *req, cgi_response_t *resp)
{
    webs_json_header(req->out);
    webs_write(req->out, "{\"code\":%d,\"data\":{}}", cgi_errno);
    return 0;
}

int get_syslog_info(cgi_request_t *req, cgi_response_t *resp)
{
    webs_json_header(req->out);
    webs_write(req->out, "{\"code\":%d,\"data\":{}}", cgi_errno);
    return 0;
}

int clear_syslog_info(cgi_request_t *req, cgi_response_t *resp)
{
    webs_json_header(req->out);
    webs_write(req->out, "{\"code\":%d,\"data\":{}}", cgi_errno);
    return 0;
}