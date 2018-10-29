#ifndef __NVRAM_COMMON_H__
#define __NVRAM_COMMON_H__

#define NVRAM_BIN			"config"

#define BIRD_INFO_FILE	"/etc/site/bird_info.txt"
#define SITE_FILE "/etc/site/site%d.conf"

#define NVRAM_INTERFACE "site_interface"
#define NVRAM_REMOTEPEER "site_remote_peer%d"
#define NVRAM_LOCALVIP "site_local_vip%d"
#define NVRAM_LOCALVSUBNET "site_localsubnet"

#define NVRAM_SITE_ON "site%d_on"
#define NVRAM_SITE_SERVER "site%d_server"

#define CLOUD_HOST "cloud_host"
#define CLOUD_PORT "cloud_port"

#define NVRAM_SITE_MANAGER_HOST "site_cloud_host"
#define NVRAM_SITE_MANAGER_PORT "site_cloud_port"

#define NVRAM_VPPN_WHITELIST_FMT "site_whitelist%d"

#define FILE_SITE_MANAGER "/etc/site/manager"

#endif
