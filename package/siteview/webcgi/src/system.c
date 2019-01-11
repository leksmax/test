
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>

#include "webcgi.h"
#include "system.h"

#define SYSTEM_API

#define _MONTH_MAX 13
#define _WEEK_MAX 8

const char *months[_MONTH_MAX] = {
    "(error)",
    "Jan",
    "Feb",
    "Mar",
    "Apr",	
    "May",
    "Jun",
    "Jul",
    "Aug",
    "Sep",
    "Oct",
    "Nov",
    "Dec",
};

const char *weeks[_WEEK_MAX] = {
    "(error)",
    "Mon",
    "Tue",
    "Wed",
    "Thu",
    "Fri",
    "Sat",
    "Sun",
};

int libgw_get_ntp_cfg(ntp_cfg_t *cfg)
{
    cfg->enabled = config_get_int(NTP_ENABLED);
    cfg->timezone = config_get_int(NTP_TIMEZONE);
    strncpy(cfg->server1, config_get(NTP_SERVER1), sizeof(cfg->server1) - 1);
    strncpy(cfg->server2, config_get(NTP_SERVER2), sizeof(cfg->server2) - 1);

    return 0;
}

int libgw_set_ntp_cfg(ntp_cfg_t *cfg)
{
    config_set_int(NTP_ENABLED, cfg->enabled);
    config_set_int(NTP_TIMEZONE, cfg->timezone);
    config_set(NTP_SERVER1, cfg->server1);
    config_set(NTP_SERVER2, cfg->server2);

    return 0;
}

int libgw_get_syslog_cfg(syslog_cfg_t *cfg)
{
    cfg->enabled = config_get_int(SYSLOG_ENABLE);
    cfg->log_remote = config_get_int(SYSLOG_REMOTE);
    strncpy(cfg->server_ip, config_get(SYSLOG_IP), sizeof(cfg->server_ip) - 1);
    cfg->log_level = config_get_int(SYSLOG_LEVEL);

    return 0;
}

int libgw_set_syslog_cfg(syslog_cfg_t *cfg)
{
    config_set_int(SYSLOG_ENABLE, cfg->enabled);
    config_set_int(SYSLOG_REMOTE, cfg->log_remote);
    config_set(SYSLOG_IP, cfg->server_ip);
    config_set_int(SYSLOG_LEVEL, cfg->log_level);

    return 0;
}

int parse_json_ntp_cfg(cJSON *params, ntp_cfg_t *cfg)
{
    int ret = 0;
    int intVal;
    char *strVal;

    ret = cjson_get_int(params, "enabled", &intVal);
    if (ret < 0)
    {
        return -1;
    }
    cfg->enabled = intVal;

    ret = cjson_get_int(params, "timezone", &intVal);
    if (ret < 0)
    {
        return -1;
    }    
    cfg->timezone = intVal;

    strVal = cjson_get_string(params, "server1");
    if (!strVal)
    {
        return -1;
    }
    strncpy(cfg->server1, strVal, sizeof(cfg->server1) - 1);

    strVal = cjson_get_string(params, "server2");
    if (!strVal)
    {
        return -1;
    }
    strncpy(cfg->server1, strVal, sizeof(cfg->server2) - 1);

    return 0;
}

int parse_json_syslog_cfg(cJSON *params, syslog_cfg_t *cfg)
{
    int ret = 0;
    int intVal;
    char *strVal;

    ret = cjson_get_int(params, "log_level", &intVal);
    if (ret < 0)
    {
        return -1;
    }
    cfg->log_level = intVal;

    ret = cjson_get_int(params, "remote_log", &intVal);
    if (ret < 0)
    {
        return -1;
    }    
    cfg->log_remote = intVal;

    strVal = cjson_get_string(params, "server_ip");
    if (!strVal)
    {
        return -1;
    }
    strncpy(cfg->server_ip, strVal, sizeof(cfg->server_ip) - 1);

    return 0;
}

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
    struct stat st;
    FILE *fp = NULL;
    char filebuf[100];
    int nread = 0;
    int nwrite = 0;

    /* 
     * 生成备份配置文件, 注意这里避免脚本输出任何数据导致cgi异常
     */
    sys_exec("/sbin/backup.sh create %s >/dev/null", BACKUP_FILE_PATH);

    fp = fopen(BACKUP_FILE_PATH, "rb");
    if (!fp)
    {
        /* 创建配置文件出错 */
        cgi_errno = CGI_ERR_CREATE_BACKUP;
        goto out;        
    }    

    webs_file_header(req->out, "NETGEAR_BR500.cfg");

    do {
        memset(filebuf, 0x0, sizeof(filebuf));
        nread = fread(filebuf, 1, sizeof(filebuf), fp);
        nwrite = fwrite(filebuf, 1, nread, stdout);
    } while(!feof(fp));

    fclose(fp);

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

    /*
     * 在此之前检查下配置是否完整
     */
    fork_exec(1, "/sbin/backup.sh restore \"%s\" >/dev/null", RESTORE_FILE_PATH);

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
    ntp_cfg_t cfg;
    time_t cur_time;

    cur_time = time(NULL);

    memset(&cfg, 0x0, sizeof(ntp_cfg_t));

    ret = libgw_get_ntp_cfg(&cfg);
    if (ret < 0)
    {
        cgi_errno = CGI_ERR_CFG_PARAM;
        goto out;    
    }

    webs_json_header(req->out);
    webs_write(req->out, "{\"code\":%d,\"data\":{", cgi_errno);
    webs_write(req->out, "\"enabled\":%d,\"server1\":\"%s\",\"server2\":\"%s\",\"timezone\":%d,"
            "\"current_time\":\"%d\"", cfg.enabled, cfg.server1, cfg.server2, 
            cfg.timezone, cur_time);
    webs_write(req->out, "}}");
    
out:
    if (cgi_errno != CGI_ERR_OK)
    {
        webs_json_header(req->out);
        webs_write(req->out, "{\"code\":%d,\"data\":{}}", cgi_errno);   
    }
    
    return 0;
}

int set_ntp_config(cgi_request_t *req, cgi_response_t *resp)
{
    int ret = 0;
    int method = 0;    
    cJSON *params = NULL;
    ntp_cfg_t cfg;

    ret = param_init(req->post_data, &method, &params);
    if (ret < 0)
    {
        cgi_errno = CGI_ERR_PARAM;
        goto out;
    }

    memset(&cfg, 0x0, sizeof(ntp_cfg_t));

    ret = parse_json_ntp_cfg(params, &cfg);
    if (ret < 0)
    {   
        cgi_errno = CGI_ERR_CFG_PARAM;
        goto out;
    }

    ret = libgw_set_ntp_cfg(&cfg);
    if (ret < 0)
    {
        cgi_errno = CGI_ERR_CFG_FILE;
        goto out;
    }

    fork_exec(1, "/etc/init.d/ntpclient restart");

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
    int ret = 0;
    syslog_cfg_t cfg;

    memset(&cfg, 0x0, sizeof(syslog_cfg_t));

    ret = libgw_get_syslog_cfg(&cfg);
    if (ret < 0)
    {
        cgi_errno = CGI_ERR_CFG_PARAM;
        goto out;    
    }

    webs_json_header(req->out);
    webs_write(req->out, "{\"code\":%d,\"data\":{", cgi_errno);
    webs_write(req->out, "\"enabled\":%d,\"log_level\":%d,\"remote_log\":%d,\"server_ip\":\"%s\"",
        cfg.enabled, cfg.log_level, cfg.log_remote, cfg.server_ip);
    webs_write(req->out, "}}");
    
out:
    if (cgi_errno != CGI_ERR_OK)
    {
        webs_json_header(req->out);
        webs_write(req->out, "{\"code\":%d,\"data\":{}}", cgi_errno);   
    }
    
    return 0;
}

int set_syslog_config(cgi_request_t *req, cgi_response_t *resp)
{
    int ret = 0;
    int method = 0;    
    cJSON *params = NULL;
    ntp_cfg_t cfg;

    ret = param_init(req->post_data, &method, &params);
    if (ret < 0)
    {
        cgi_errno = CGI_ERR_PARAM;
        goto out;
    }

    memset(&cfg, 0x0, sizeof(ntp_cfg_t));

    ret = parse_json_syslog_cfg(params, &cfg);
    if (ret < 0)
    {   
        cgi_errno = CGI_ERR_CFG_PARAM;
        goto out;
    }

    ret = libgw_set_syslog_cfg(&cfg);
    if (ret < 0)
    {
        cgi_errno = CGI_ERR_CFG_FILE;
        goto out;
    }

    fork_exec(1, "/etc/init.d/log restart");

out:
    webs_json_header(req->out);
    webs_write(req->out, "{\"code\":%d,\"data\":{}}", cgi_errno);  

    return 0;
}

typedef struct {
    time_t time;
    char module[20];
    char level[10];
    char info[128];    
} loginfo_t;

static void json_string_encode(char *str, int len)
{
    int i = 0;
    char val;
    
    for (i = 0; i < len; i ++)
    {
        val = str[i];
        switch(val)
        {
            case '"':
                str[i] = '\'';
                break;
            default:
                break;
        }
    }
}

static int syslog_format(char *logbuf, loginfo_t *log)
{
    int i = 0;
	int ret = 0;
	struct tm t;
    int week_int, month_int;
    char week_str[10], month_str[10];
    
	memset(&t, 0x0, sizeof(struct tm));
    
	ret = sscanf(logbuf, "%s %s %d %d:%d:%d %d %[^.].%[^. ] %[^\n]",
		week_str, month_str, &t.tm_mday, &t.tm_hour, &t.tm_min, &t.tm_sec, &t.tm_year, log->module, log->level, log->info);
	if(ret != 10)
    {   
		return -1;
    }

    for (i = 1; i < _MONTH_MAX; i ++)
    {
        if (!strcmp(month_str, months[i]))
        {
            month_int = i;
            break;
        }
    }

    for (i = 1; i < _WEEK_MAX; i ++)
    {
        if (!strcmp(week_str, weeks[i]))
        {
            week_int = i;
            break;
        }
    }    
    
	t.tm_mon = month_int - 1;
	t.tm_wday = week_int - 1;
	t.tm_year = t.tm_year - 1900;
	t.tm_isdst = -1;

	log->time = mktime(&t);

    /* json数据处理 */
    json_string_encode(log->info, strlen(log->info));

    return 0;
}

/*
 * 大致格式为
 *
 * Wed Jan  2 14:43:41 2019 daemon.notice watchquagga[6187]: Terminating on signal
 */
int get_syslog_info(cgi_request_t *req, cgi_response_t *resp)
{
    int i = 0;
    int ret = 0;
    FILE *fp = NULL;    
    char logbuf[1024];
    char syslog_file[128] = {0};
    loginfo_t log;

    strncpy(syslog_file, config_get(SYSLOG_FILE), sizeof(syslog_file));
    
    fp = fopen(syslog_file, "r");
    if (!fp)
    {
        cgi_errno = CGI_ERR_PARAM;
        goto out;
    }

    webs_json_header(req->out);
    webs_write(req->out, "{\"code\":%d,\"data\":{", cgi_errno);
    webs_write(req->out, "\"syslog\":[");

    while (fgets(logbuf, sizeof(logbuf), fp))
    {        
        /* 格式化 */
        memset(&log, 0x0, sizeof(loginfo_t));
        
        ret = syslog_format(logbuf, &log);
        if (ret < 0)
        {
            continue;
        }

        webs_write(req->out, "%s{\"id\":%d,\"time\":\"%d\",\"module\":\"%s\",\"level\":\"%s\","
            "\"info\":\"%s\"}", (i > 0 ? "," : ""), i + 1, log.time, log.module, log.level, log.info);
        
        i ++;
    }

    webs_write(req->out, "]}}");

    fclose(fp);
    
out:
    if (cgi_errno != CGI_ERR_OK)
    {
        webs_json_header(req->out);
        webs_write(req->out, "{\"code\":%d,\"data\":{}}", cgi_errno);   
    }

    return 0;
}

int clear_syslog_info(cgi_request_t *req, cgi_response_t *resp)
{
    char syslog_file[128] = {0};

    strncpy(syslog_file, config_get(SYSLOG_FILE), sizeof(syslog_file));
    
    webs_json_header(req->out);
    webs_write(req->out, "{\"code\":%d,\"data\":{}}", cgi_errno);

    if (syslog_file[0] != '\0')
    {
        fork_exec(1, "echo \"\" >  %s", SYSLOG_FILE);
    }
    
    return 0;
}
