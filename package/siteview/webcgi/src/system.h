
#ifndef __SYSTEM_H_
#define __SYSTEM_H_

#include "utils.h"
#include "servlet.h"

/* 最大升级文件的大小32MB */
#define MAX_IMAGE_SIZE (0x2000000)

#define BACKUP_FILE_PATH "/tmp/backup.tar.gz"
#define RESTORE_FILE_PATH "/tmp/restore.tar.gz"

/* 升级文件路径 */
#define FIRMWARE_PATH "/tmp/firmware.bin"

/* ntp配置 */
typedef struct ntp_cfg {
    int enabled;
    char server1[16];
    char server2[16];
    int timezone;
} ntp_cfg_t;

/* 重启与复位 */
int do_reboot(cgi_request_t * req, cgi_response_t * resp);
int do_factory_reset(cgi_request_t * req, cgi_response_t * resp);

/* 备份与恢复配置 */
int do_backup_config(cgi_request_t * req, cgi_response_t * resp);
int do_restore_config(cgi_request_t * req, cgi_response_t * resp);

/* 升级 */
int upgrade_check(cgi_request_t * req, cgi_response_t * resp);
int firmware_upgrade(cgi_request_t * req, cgi_response_t * resp);

int get_ntp_config(cgi_request_t * req, cgi_response_t * resp);
int set_ntp_config(cgi_request_t * req, cgi_response_t * resp);
int sync_current_time(cgi_request_t * req, cgi_response_t * resp);

/* syslog */
int get_syslog_config(cgi_request_t * req, cgi_response_t * resp);
int set_syslog_config(cgi_request_t * req, cgi_response_t * resp);
int get_syslog_info(cgi_request_t * req, cgi_response_t * resp);
int clear_syslog_info(cgi_request_t * req, cgi_response_t * resp);

#endif
