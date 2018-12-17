
#ifndef __SYSTEM_H_
#define __SYSTEM_H_

/* 最大升级文件的大小32MB */
#define MAX_IMAGE_SIZE (0x2000000)
/* 升级文件路径 */
#define FIRMWARE_PATH "/tmp/firmware.bin"

/* 重启与复位 */
int do_reboot(cgi_request_t * req, cgi_response_t * resp);
int do_factory_reset(cgi_request_t * req, cgi_response_t * resp);

/* 备份与恢复配置 */
int do_backup_config(cgi_request_t * req, cgi_response_t * resp);
int do_restore_config(cgi_request_t * req, cgi_response_t * resp);

/* 升级 */
int upgrade_check(cgi_request_t * req, cgi_response_t * resp);
int firmware_upgrade(cgi_request_t * req, cgi_response_t * resp);

#endif
