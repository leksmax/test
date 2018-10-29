/*
 * ctrl-interface.h
 *
 *  Created on: Jun 5, 2017
 *      Author: pp
 */

#ifndef CTRL_INTERFACE_H_
#define CTRL_INTERFACE_H_

#include <stdio.h>
#include <pthread.h>
#include "cJSON.h"
#include "file_tool.h"
#include "vpn_config.h"

#define MAX_IP_BUF_LEN (40)

enum CONFIG_TYPE_E
{
	TYPE_VPN = 0,
	TYPE_VPPN
};

struct ctrl_manager_status_s
{
	char manager_host[MAX_IP_BUF_LEN];
	int  manager_port;
	double manager_latency;
};

struct ctrl_proxy_status_s
{
	char proxy_host[MAX_IP_BUF_LEN];
	int  proxy_port;
	double proxy_latency;
};

struct ctrl_local_status_s
{
	char local_vip[MAX_IP_BUF_LEN];
	double  local2gw_latency;
};

cJSON *ctrl_get_tunnel_neighbors(int channel);
int ctrl_find_neighbor(int channel, char *neighbor_ip);
int ctrl_get_localsubnet(char *lan_if, char *gw_buf, char *netmask_buf);
struct vpn_config_s* ctrl_get_tunnel_config();

void ctrl_reload_vpn(int conf_type, int channel, char* team_id);
void ctrl_reload_firewall(int channel, char* virtual_subnet);
void ctrl_reload_dnsmasq(int conf_type, int channel, char* team_id);
void ctrl_reload_bird(int conf_type, int channel, char* team_id);
void ctrl_disable_vpn(int conf_type, int channel);
void ctrl_enable_vpn(int conf_type, int channel, char* team_id);
cJSON *ctrl_get_tunnel_log_conf(int tunnel_id);
void ctrl_set_tunnel_log_conf(int tunnel_id, cJSON *item);
void ctrl_enable_log(int tunnel_id, int log_level);
void ctrl_disable_log(int tunnel_id);
void ctrl_disable_dnsmasq_conf(int conf_type, int channel);
void ctrl_refresh_vpn();
cJSON* ctrl_get_manager(int conf_type, int channel);
void ctrl_set_manager(int conf_type, int channel, char *manager_host, int manager_port);
cJSON *ctrl_get_public_whitelist_switch(int conf_type, int tunnel_id);

cJSON *get_public_whitelist(char *cloud_host, int cloud_port, int vpn_type, int tunnel_id);
void generate_public_vpath_conf(cJSON *whitelist, int conf_type, int tunnel_id, char *gw);
void remove_public_vpath_conf(int conf_type, int tunnel_id);
void ctrl_load_public_vpath(char *cloud_host, int cloud_port, int conf_type, int tunnel_id);

#endif /* CTRL_INTERFACE_H_ */
