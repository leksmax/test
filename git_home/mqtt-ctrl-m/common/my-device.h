#ifndef _SRC_MY_DEVICE_H_
#define _SRC_MY_DEVICE_H_

#include "cJSON.h"

#ifdef __cplusplus
extern "C"
{
#endif

cJSON* get_my_device_baseinfo();
void set_lan_subnets(cJSON* new_subnets);
cJSON* get_all_lan_subnets();

void vpn_tunnel_gen_key(char* dir);
int vpn_upload_key_once(char* user);
void get_my_id(char *id);
void get_my_teamid(char* teamid);
void set_my_teamid(char* teamid);
void unset_my_teamid();
int get_vppn_status();
void set_vppn_status(int status);
void get_my_wanmac(char* wan_mac);
void get_my_wanip(char* wan_ip);
void get_my_lansubnet(char* lan_subnet);
void get_my_wansubnet(char* wan_subnet);
void get_my_virtualip(char* virtual_ip);

int get_mqtt_manager_server_from_cloud(char* ret_server, char* host, int port, int* http_saved);
int get_mqtt_manager_server_from_cloud_old(char* ret_server, char* host, int port);
int get_mqtt_manager_server_from_local(char *server);
void set_mqtt_manager_server_to_local(char *server);
void set_http_manager_server_to_local(char* server, char* port);

cJSON* get_my_device_info();
cJSON *GetCPUJSON2(double* avg_load);
double Get_Mem_Info(unsigned int* total_val, unsigned int* free_val);
cJSON* get_attach_devices();
void random_id_init(char* out_buf, int save_config);
#ifdef __cplusplus
}
#endif

#endif
