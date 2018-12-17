
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include "servlet.h"
#include "system.h"
#include "utils.h"

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
    webs_json_header(req->out);
    webs_write(req->out, "{\"code\":0,\"data\":{}}");
    return 0;
}

int do_restore_config(cgi_request_t *req, cgi_response_t *resp)
{
    webs_json_header(req->out);
    webs_write(req->out, "{\"code\":0,\"data\":{}}");
    return 0;
}

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
        /* 没有上传文件 */
    }

    if (req->post_len > MAX_IMAGE_SIZE)
    {
        cgi_errno = 190;
        goto out;
    }

    strncpy(curr_fw_ver, cat_file("/firmware_version"), sizeof(curr_fw_ver) - 1);

    ret = upload_file(stdin, req->post_len, FIRMWARE_PATH);
    if (ret < 0)
    {
        cgi_errno = 191;
        goto out;
    }

    check_ok = image_check(FIRMWARE_PATH);
    if(check_ok < 0)
    {  
        cgi_errno = 191;
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
        cgi_errno = 101;
        goto out;
    }

    strVal = cjson_get_string(params, "upgrade_yes_no");
    if (ret < 0)
    {
        cgi_errno = 102;
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
        cgi_errno = 192;
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
