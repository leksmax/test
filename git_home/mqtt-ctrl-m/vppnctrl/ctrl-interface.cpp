/*
 * ctrl-interface.c
 *
 *  Created on: Jun 5, 2017
 *      Author: pp
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "file_tool.h"
#include "net_tool.h"
#include "cJSON.h"
#include "process_tool.h"
#include "ctrl-interface.h"
#include "vpn_cloud.h"
#include "net_tool.h"

extern int refresh_flag;

#ifndef FREE_PTR
#define FREE_PTR(ptr) do{if (ptr) {free((ptr)); (ptr)=NULL;}}while(0);
#endif

cJSON *get_public_whitelist_from_cloud(char *cloud_host, int cloud_port, int vpn_type, int tunnel_id)
{
	cJSON *ret = NULL;
	cJSON *client_info = cJSON_CreateObject();
	cJSON_AddNumberToObject(client_info, "tunnel_id", tunnel_id);
	if (vpn_type == 0)
	{
		cJSON_AddStringToObject(client_info, "tunnel_type", "vpn");
	}
	else
	{
		cJSON_AddStringToObject(client_info, "tunnel_type", "vppn");
	}
	ret = vpn_cloud_tool3((char*)"/GetWhiteList", client_info);
	//ret = vpn_cloud_tool(client_info, cloud_host, cloud_port, "/GetWhiteList");
	cJSON_Delete(client_info);
	return ret;
}

cJSON *get_public_whitelist_from_local(int vpn_type, int tunnel_id)
{
	cJSON *ret = NULL;
	char public_whitelist_file[100];
	if (vpn_type == 0)
	{
		sprintf(public_whitelist_file, "/etc/vpn/public_vpath%d.conf", tunnel_id);
	}
	else
	{
		sprintf(public_whitelist_file, "/etc/site/public_vpath%d.conf", tunnel_id);
	}
	ret = read_json_from_file(public_whitelist_file);
	return ret;
}

cJSON *get_public_whitelist(char *cloud_host, int cloud_port, int vpn_type, int tunnel_id)
{
	cJSON *ret = NULL;
	char public_whitelist_file[100];
	if (vpn_type == 0)
	{
		sprintf(public_whitelist_file, "/etc/vpn/public_vpath%d.conf", tunnel_id);
	}
	else
	{
		sprintf(public_whitelist_file, "/etc/site/public_vpath%d.conf", tunnel_id);
	}

	cJSON *cloud_ret = get_public_whitelist_from_cloud(cloud_host, cloud_port, vpn_type, tunnel_id);
	if (cloud_ret)
	{
		int array_count = cJSON_GetArraySize(cloud_ret);
		int i;
		for(i = 0; i < array_count; i++)
		{
			cJSON *wl_array = cJSON_GetArrayItem(cloud_ret, i);
			cJSON *wl = cJSON_GetObjectItem(wl_array, "List");
			if (wl)
			{
				ret = cJSON_Duplicate(wl, 1);
				write_json_to_file(public_whitelist_file, ret);
				break;
			}
		}
		cJSON_Delete(cloud_ret);
	}
	else
	{
		ret = get_public_whitelist_from_local(vpn_type, tunnel_id);
	}
	return ret;
}

void generate_public_vpath_conf(cJSON *whitelist, int conf_type, int tunnel_id, char *gw)
{
	char public_vpath_conf[100];
	char public_whitelist_file[100];
	cJSON *dest_json = NULL;

	if (conf_type == 0)
	{
		sprintf(public_vpath_conf, "/etc/vpn/public_tunnel_vpath%d.conf", tunnel_id);
		sprintf(public_whitelist_file, "/etc/vpn/public_vpath%d.conf", tunnel_id);
		gw = NULL;
	}
	else
	{
		sprintf(public_vpath_conf, "/etc/site/public_tunnel_vpath%d.conf", tunnel_id);
		sprintf(public_whitelist_file, "/etc/site/public_vpath%d.conf", tunnel_id);
	}

	dest_json = cJSON_CreateArray();
	int item_cnt = cJSON_GetArraySize(whitelist);
	int i;
	for(i = 0; i < item_cnt; i++)
	{
		cJSON *uri_item = cJSON_GetArrayItem(whitelist, i);
		cJSON *new_obj = NULL;
		if (conf_type != 0)
		{
			if (gw)
			{
				new_obj = cJSON_CreateObject();
				cJSON_AddStringToObject(new_obj, "vproxy", gw);
				cJSON_AddStringToObject(new_obj, "uri", uri_item->valuestring);
			}
		}
		else
		{
			new_obj = cJSON_CreateObject();
			cJSON_AddStringToObject(new_obj, "uri", uri_item->valuestring);
		}
		if (new_obj)
		{
			cJSON_AddItemToArray(dest_json, new_obj);
		}
	}
	write_json_to_file(public_vpath_conf, dest_json);
	cJSON_Delete(dest_json);
	return;
}

void remove_public_vpath_conf(int conf_type, int tunnel_id)
{
	char public_vpath_conf[100];
	if (conf_type == 0)
	{
		sprintf(public_vpath_conf, "/etc/vpn/public_tunnel_vpath%d.conf", tunnel_id);
	}
	else
	{
		sprintf(public_vpath_conf, "/etc/site/public_tunnel_vpath%d.conf", tunnel_id);
	}
	remove(public_vpath_conf);
	return;
}

void ctrl_load_public_vpath(char *cloud_host, int cloud_port, int conf_type, int tunnel_id)
{
	char public_vpath_switch_file[100];

	int on = 0;
	char *gw = NULL;

	if (conf_type == TYPE_VPN)
	{
		sprintf(public_vpath_switch_file, "/etc/vpn/public_vpath%d_switch.conf", tunnel_id);
	}
	else
	{
		sprintf(public_vpath_switch_file, "/etc/site/public_vpath%d_switch.conf", tunnel_id);
	}
	cJSON *switch_json = read_json_from_file(public_vpath_switch_file);
	if (switch_json)
	{
		cJSON *on_item = cJSON_GetObjectItem(switch_json, "on");
		cJSON *gw_item = cJSON_GetObjectItem(switch_json, "vpath_tunnel");
		if (on_item)
		{
			on = on_item->valueint;
		}
		if (gw_item)
		{
			gw = strdup(gw_item->valuestring);
		}
		cJSON_Delete(switch_json);
	}

	if (on)
	{
		if ((conf_type == TYPE_VPPN && gw)
				||
				(conf_type == TYPE_VPN))
		{
			cJSON *public_wl_json = get_public_whitelist(cloud_host, cloud_port, conf_type, tunnel_id);
			if (public_wl_json)
			{
				generate_public_vpath_conf(public_wl_json, conf_type, tunnel_id, gw);
				cJSON_Delete(public_wl_json);
			}
		}
	}
	else
	{
		remove_public_vpath_conf(conf_type, tunnel_id);
	}
	FREE_PTR(gw);
	return;
}

cJSON *ctrl_get_public_whitelist_switch(int conf_type, int tunnel_id)
{
	cJSON *ret = NULL;
	char public_vpath_switch_file[100];
	if (conf_type == TYPE_VPN)
	{
		sprintf(public_vpath_switch_file, "/etc/vpn/public_vpath%d_switch.conf", tunnel_id);
	}
	else
	{
		sprintf(public_vpath_switch_file, "/etc/site/public_vpath%d_switch.conf", tunnel_id);
	}
	ret = read_json_from_file(public_vpath_switch_file);
	return ret;
}

cJSON *ctrl_get_tunnel_neighbors(int channel)
{
	char peers_file[100];
	sprintf(peers_file, "/etc/site/vppn%d_peers.conf", channel);
	cJSON *ret = read_json_from_file(peers_file);
	return ret;
}

int ctrl_find_neighbor(int channel, char *neighbor_ip)
{
	int ret = 0;
	if (neighbor_ip)
	{
		cJSON *neighbors = ctrl_get_tunnel_neighbors(channel);
		if (neighbors)
		{
			int items_cnt = cJSON_GetArraySize(neighbors);
			int i;
			for(i = 0; i < items_cnt; i++)
			{
				cJSON* one_neighbor = cJSON_GetArrayItem(neighbors, i);
				cJSON* ip_item = cJSON_GetObjectItem(one_neighbor, "peer_vip");
				if (ip_item)
				{
					if (strcmp(ip_item->valuestring, neighbor_ip) == 0)
					{
						ret = 1;
						break;
					}
				}
			}
			cJSON_Delete(neighbors);
		}
	}
	return ret;
}

int ctrl_get_localsubnet(char *lan_if, char *gw_buf, char *netmask_buf)
{
	int ret = -1;
	ret = net_tool_get_if_ip(lan_if, gw_buf) || net_tool_get_if_netmask(lan_if, netmask_buf);
	return ret;
}

extern struct vpn_config_s *dump_global_config();
struct vpn_config_s* ctrl_get_tunnel_config()
{
	struct vpn_config_s* ret = dump_global_config();
	return ret;
}

cJSON *ctrl_get_tunnel_conf(int conf_type, int channel)
{
	cJSON *ret = NULL;
	char conf_file[100];
	/* if vppn */
	if (conf_type == 1)
	{
		sprintf(conf_file, "/etc/site/site%d.conf", channel);
	}
	/* if vpn */
	else
	{
		sprintf(conf_file, "/etc/vpn/vpn%d.conf", channel);
	}
	ret = read_json_from_file(conf_file);
	return ret;
}

void ctrl_set_tunnel_conf(int conf_type, int channel, cJSON *tunnel_conf)
{
	char conf_file[100];
	/* if vppn */
	if (conf_type == 1)
	{
		sprintf(conf_file, "/etc/site/site%d.conf", channel);
	}
	/* if vpn */
	else
	{
		sprintf(conf_file, "/etc/vpn/vpn%d.conf", channel);
	}
	write_json_to_file(conf_file, tunnel_conf);
	return;
}

void ctrl_enable_vpn(int conf_type, int channel, char* team_id)
//void ctrl_enable_vpn(int conf_type, int channel, char *server, int port, char* teamid, char *self_vip)
{
	cJSON *tunnel_conf = ctrl_get_tunnel_conf(conf_type, channel);
	if (!tunnel_conf)
	{
		tunnel_conf = cJSON_CreateObject();
		cJSON_AddNumberToObject(tunnel_conf, "on", 0);
		cJSON_AddStringToObject(tunnel_conf, "team_id", "");
		//cJSON_AddStringToObject(tunnel_conf, "team_id", "");
		//cJSON_AddStringToObject(tunnel_conf, "myself_addr", "");
		//cJSON_AddNumberToObject(tunnel_conf, "server_port", 0);
	}

	cJSON_ReplaceItemInObject(tunnel_conf, "on", cJSON_CreateNumber(1));
	cJSON_ReplaceItemInObject(tunnel_conf, "team_id", cJSON_CreateString(team_id));
#if 0
	if (server)
	{
		cJSON_ReplaceItemInObject(tunnel_conf, "server_addr", cJSON_CreateString(server));
	}
	if (self_vip)
	{
		cJSON_ReplaceItemInObject(tunnel_conf, "myself_addr", cJSON_CreateString(self_vip));
	}
	if (port)
	{
		cJSON_ReplaceItemInObject(tunnel_conf, "server_port", cJSON_CreateNumber(port));
	}
	if (teamid)
	{
		cJSON_ReplaceItemInObject(tunnel_conf, "team_id", cJSON_CreateString(teamid));
	}
#endif
	ctrl_set_tunnel_conf(conf_type, channel, tunnel_conf);
	refresh_flag = 1;
	cJSON_Delete(tunnel_conf);
	return;
}

cJSON *ctrl_get_tunnel_log_conf(int tunnel_id)
{
	char log_file[100];
	sprintf(log_file, "/tmp/vppn_log_site%d.conf", tunnel_id);
	cJSON *res = read_json_from_file(log_file);
	return res;
}

void ctrl_set_tunnel_log_conf(int tunnel_id, cJSON *item)
{
	char log_file[100];
	sprintf(log_file, "/tmp/vppn_log_site%d.conf", tunnel_id);
	write_json_to_file(log_file, item);
	return;
}

void ctrl_enable_log(int tunnel_id, int log_level)
{
	cJSON *item = cJSON_CreateObject();
	if (item)
	{
		cJSON_AddNumberToObject(item, "log_on", 1);
		cJSON_AddNumberToObject(item, "log_level", log_level);
		ctrl_set_tunnel_log_conf(tunnel_id, item);
		cJSON_Delete(item);
	}
	return;
}

void ctrl_disable_log(int tunnel_id)
{
	cJSON *item = cJSON_CreateObject();
	if (item)
	{
		cJSON_AddNumberToObject(item, "log_on", 0);
		ctrl_set_tunnel_log_conf(tunnel_id, item);
		cJSON_Delete(item);
	}
	return;
}

void ctrl_refresh_vpn()
{
	refresh_flag = 1;
}

void ctrl_set_manager(int conf_type, int channel, char *manager_host, int manager_port)
{
	char manager_file[100];
	if (conf_type)
	{
		sprintf(manager_file, "/etc/site/manager");
	}
	else
	{
		sprintf(manager_file, "/etc/vpn/manager");
	}
	cJSON *manager_json = read_json_from_file(manager_file);
	if (!manager_json)
	{
		manager_json =	cJSON_CreateObject();
		cJSON_AddStringToObject(manager_json, "cloud_host", manager_host);
		cJSON_AddNumberToObject(manager_json, "cloud_port", manager_port);
	}
	else
	{
		cJSON_ReplaceItemInObject(manager_json, "cloud_host", cJSON_CreateString(manager_host));
		cJSON_ReplaceItemInObject(manager_json, "cloud_port", cJSON_CreateNumber(manager_port));
	}
	write_json_to_file(manager_file, manager_json);
	cJSON_Delete(manager_json);
	refresh_flag = 1;
	return;
}

cJSON* ctrl_get_manager(int conf_type, int channel)
{
	char manager_file[100];
	if (conf_type)
	{
		sprintf(manager_file, "/etc/site/manager");
	}
	else
	{
		sprintf(manager_file, "/etc/vpn/manager");
	}
	cJSON *manager_json = read_json_from_file(manager_file);
	return manager_json;
}

void ctrl_disable_vpn(int conf_type, int channel)
{
	cJSON *tunnel_conf = ctrl_get_tunnel_conf(conf_type, channel);
	if (!tunnel_conf)
	{
		tunnel_conf = cJSON_CreateObject();
		cJSON_AddNumberToObject(tunnel_conf, "on", 0);
		cJSON_AddStringToObject(tunnel_conf, "team_id", "");
		//cJSON_AddStringToObject(tunnel_conf, "server_addr", "");
		//cJSON_AddStringToObject(tunnel_conf, "myself_addr", "");
		//cJSON_AddNumberToObject(tunnel_conf, "server_port", 0);
		//cJSON_AddStringToObject(tunnel_conf, "team_id", "");
	}

	cJSON_ReplaceItemInObject(tunnel_conf, "on", cJSON_CreateNumber(0));
	cJSON_ReplaceItemInObject(tunnel_conf, "team_id", cJSON_CreateString(""));
	ctrl_set_tunnel_conf(conf_type, channel, tunnel_conf);
	refresh_flag = 1;
	cJSON_Delete(tunnel_conf);
	return;
}

void ctrl_restart_bird()
{
	system("bird.sh stop");
	usleep(50000);
	system("bird.sh start");
}

void ctrl_reload_bird(int conf_type, int tunnel_id, char* team_id)
{
	/* if vppn, need reload bird. else need not */
	if (conf_type == 1)
	{
		extern void reload_bird_conf(int tunnel_id, char* team_id);
		reload_bird_conf(tunnel_id, team_id);
		ctrl_restart_bird();
	}
	return;
}

void ctrl_start_swap_routed()
{
	system("swap-routed");
}

void ctrl_stop_swap_routed()
{
	system("killall swap-routed");
}

void ctrl_restart_swap_routed()
{
	ctrl_stop_swap_routed();
	sleep(1);
	ctrl_start_swap_routed();
}

void load_vpath_into_dnsmasq_conf(cJSON *vpath, char *dnsmasq_conf_file, int conf_type, int channel, char* team_id)
{
	int vpath_cnt = cJSON_GetArraySize(vpath);
	int i;
	for(i = 0; i < vpath_cnt; i++)
	{
		cJSON *one_path = cJSON_GetArrayItem(vpath, i);
		char line_buf[100];
		cJSON *uri_item = cJSON_GetObjectItem(one_path, "uri");
		cJSON *proxy_item = cJSON_GetObjectItem(one_path, "vproxy");
		cJSON *team_id_item = cJSON_GetObjectItem(one_path, "team_id");
		/* if vppn */
		if (conf_type)
		{
			if (proxy_item && uri_item && team_id_item)
			{
				if (strcmp(team_id_item->valuestring, team_id) == 0)
				{
					sprintf(line_buf, "server=/%s/%s#53\n", uri_item->valuestring, proxy_item->valuestring);
					append_line(dnsmasq_conf_file, line_buf);
				}
			}
		}
		/* if vpn */
		else
		{
			char gw_buf[30];
			sprintf(gw_buf, "10.100.%d.1", channel + 10);
			sprintf(line_buf, "server=/%s/%s#53\n", uri_item->valuestring, gw_buf);
			append_line(dnsmasq_conf_file, line_buf);
		}
	}
	return;
}

void reload_dnsmasq_conf(int conf_type, int channel, char* team_id)
{
	char dnsmasq_conf_file[100];
	char vpath_conf_file[100];
	char public_vpath_conf_file[100];
	if (conf_type == 0)
	{
		sprintf(dnsmasq_conf_file, "/etc/dnsmasq.d/vpn%d_vpath.conf", channel);
		sprintf(vpath_conf_file, "/etc/vpn/vpn%d_vpath.conf", channel);
		sprintf(public_vpath_conf_file, "/etc/vpn/public_tunnel_vpath%d.conf", channel);
	}
	else
	{
		sprintf(dnsmasq_conf_file, "/etc/dnsmasq.d/vppn%d_vpath.conf", channel);
		sprintf(vpath_conf_file, "/etc/site/vppn%d_vpath.conf", channel);
		sprintf(public_vpath_conf_file, "/etc/site/public_tunnel_vpath%d.conf", channel);
	}
	remove(dnsmasq_conf_file);
	cJSON *vpath = read_json_from_file(vpath_conf_file);
	if (vpath)
	{
		load_vpath_into_dnsmasq_conf(vpath, dnsmasq_conf_file, conf_type, channel, team_id);
		cJSON_Delete(vpath);
	}

	cJSON *public_vpath = read_json_from_file(public_vpath_conf_file);
	if (public_vpath)
	{
		load_vpath_into_dnsmasq_conf(public_vpath, dnsmasq_conf_file, conf_type, channel, team_id);
		cJSON_Delete(public_vpath);
	}
	return;
}

void ctrl_restart_dnsmasq()
{
	process_tool_system("/etc/init.d/dnsmasq stop");
	process_tool_system("/etc/init.d/dnsmasq start");
}

void ctrl_disable_dnsmasq_conf(int conf_type, int channel)
{
	char dnsmasq_conf_file[100];
	char vpath_conf_file[100];
	if (conf_type == 0)
	{
		sprintf(dnsmasq_conf_file, "/etc/dnsmasq.d/vpn%d_vpath.conf", channel);
		sprintf(vpath_conf_file, "/etc/vpn/vpn%d_vpath.conf", channel);
	}
	else
	{
		sprintf(dnsmasq_conf_file, "/etc/dnsmasq.d/vppn%d_vpath.conf", channel);
		sprintf(vpath_conf_file, "/etc/site/vppn%d_vpath.conf", channel);
	}
	remove(dnsmasq_conf_file);
	ctrl_restart_dnsmasq();
	return;
}

void ctrl_reset_route_table(int conf_type, int channel)
{
	char dev[100];
	if (conf_type == 0)
	{
		sprintf(dev, "tun%d", channel);
	}
	else
	{
		sprintf(dev, "site%d", channel);
	}
	net_tool_reset_routes(dev);
}

void ctrl_reload_route(int conf_type, int channel)
{
	char peer_file[100];
	sprintf(peer_file, "/etc/site/vppn%d_peers.conf", channel);
	char dev[100];

	if (conf_type == 0)
	{
		sprintf(dev, "tun%d", channel);
	}
	else
	{
		sprintf(dev, "site%d", channel);
	}
	cJSON* peers = read_json_from_file(peer_file);
	if (peers)
	{
		int peers_cnt = cJSON_GetArraySize(peers);
		int i;
		for(i = 0; i < peers_cnt; i++)
		{
			cJSON* peer_item = cJSON_GetArrayItem(peers, i);
			cJSON* peer_vip_item = cJSON_GetObjectItem(peer_item, "peer_vip");
			if (peer_vip_item)
			{
				add_route_by_cmd(peer_vip_item->valuestring, (char*)"255.255.255.255", dev);
			}
		}
		cJSON_Delete(peers);
	}
	return;
}

void ctrl_reload_dnsmasq(int conf_type, int channel, char* team_id)
{
	reload_dnsmasq_conf(conf_type, channel, team_id);
	ctrl_reset_route_table(conf_type, channel);
	ctrl_restart_dnsmasq();
}

void ctrl_reload_vpn(int conf_type, int channel, char* team_id)
{
	//ctrl_reload_bird(conf_type, channel, team_id);
	ctrl_restart_swap_routed();
	ctrl_reload_dnsmasq(conf_type, channel, team_id);
	return;
}

#if 1
void ctrl_write_firewall_script(char *peers_file)
{
	char buf[4096];
	char fw_file[100] = "/etc/scripts/firewall/vppn.rule";
	cJSON* peers = NULL;
	sprintf(buf,
			"#! /bin/sh\n"
			"if [ \"$1\" == \"start\" ]; then\n"
			"\t/usr/sbin/iptables -I INPUT -i site0 -j ACCEPT\n"
			"\t/usr/sbin/iptables -I OUTPUT -o site0 -j ACCEPT\n"
			"\t/usr/sbin/iptables -I INPUT -i brwan -p udp --dport 3277 -j ACCEPT\n"
			"\t/usr/sbin/iptables -I INPUT -i ppp0 -p udp --dport 3277 -j ACCEPT\n"
			"\t/usr/sbin/iptables -I INPUT -i brwan -p tcp --dport 3277 -j ACCEPT\n"
			"\t/usr/sbin/iptables -I INPUT -i ppp0 -p tcp --dport 3277 -j ACCEPT\n"
			"\t/usr/sbin/iptables -I FORWARD -i site0 -j ACCEPT\n"
			"\t/usr/sbin/iptables -I FORWARD -o site0 -j ACCEPT\n"
			"\t/usr/sbin/iptables -t nat -I POSTROUTING -o site0 -j MASQUERADE\n");
	write_shell(fw_file, buf);

	peers = read_json_from_file(peers_file);
	if (peers)
	{
		int cnt = cJSON_GetArraySize(peers);
		int i;
		for(i = 0; i < cnt; i++)
		{
			cJSON* peer_item = cJSON_GetArrayItem(peers, i);
			cJSON* peer_vip_item = cJSON_GetObjectItem(peer_item, "peer_vip");
			if (peer_vip_item)
			{
				sprintf(buf,
						"\t/usr/sbin/iptables -t nat -I br0_masq -s %s/32 -j MASQUERADE\n"
						"\t/usr/sbin/iptables -t nat -I POSTROUTING -o br1 -s %s/32 -j MASQUERADE\n"
						"\t/usr/sbin/iptables -t nat -I POSTROUTING -o br2 -s %s/32 -j MASQUERADE\n"
						"\t/usr/sbin/iptables -t nat -I POSTROUTING -o br3 -s %s/32 -j MASQUERADE\n"
						"\t/usr/sbin/iptables -t nat -I brwan_masq -s %s/32 -j MASQUERADE\n"
						"\t/usr/sbin/iptables -t nat -I ppp0_masq -s %s/32 -j MASQUERADE\n",
						peer_vip_item->valuestring,
						peer_vip_item->valuestring,
						peer_vip_item->valuestring,
						peer_vip_item->valuestring,
						peer_vip_item->valuestring,
						peer_vip_item->valuestring
						);
				append_line(fw_file, buf);
			}
		}
		cJSON_Delete(peers);
	}
	sprintf(buf, "fi\n");
	append_line(fw_file, buf);

	sprintf(buf,
			"#! /bin/sh\n"
			"if [ \"$1\" == \"stop\" ]; then\n"
			"\t/usr/sbin/iptables -D INPUT -i site0 -j ACCEPT\n"
			"\t/usr/sbin/iptables -D OUTPUT -o site0 -j ACCEPT\n"
			"\t/usr/sbin/iptables -D INPUT -i brwan -p udp --dport 3277 -j ACCEPT\n"
			"\t/usr/sbin/iptables -D INPUT -i ppp0 -p udp --dport 3277 -j ACCEPT\n"
			"\t/usr/sbin/iptables -D INPUT -i brwan -p tcp --dport 3277 -j ACCEPT\n"
			"\t/usr/sbin/iptables -D INPUT -i ppp0 -p tcp --dport 3277 -j ACCEPT\n"
			"\t/usr/sbin/iptables -D FORWARD -i site0 -j ACCEPT\n"
			"\t/usr/sbin/iptables -D FORWARD -o site0 -j ACCEPT\n"
			"\t/usr/sbin/iptables -t nat -D POSTROUTING -o site0 -j MASQUERADE\n");
	append_line(fw_file, buf);

	peers = read_json_from_file(peers_file);
	if (peers)
	{
		int cnt = cJSON_GetArraySize(peers);
		int i;
		for(i = 0; i < cnt; i++)
		{
			cJSON* peer_item = cJSON_GetArrayItem(peers, i);
			cJSON* peer_vip_item = cJSON_GetObjectItem(peer_item, "peer_vip");
			if (peer_vip_item)
			{
				sprintf(buf,
						"\t/usr/sbin/iptables -t nat -D br0_masq -s %s/32 -j MASQUERADE\n"
						"\t/usr/sbin/iptables -t nat -D POSTROUTING -o br1 -s %s/32 -j MASQUERADE\n"
						"\t/usr/sbin/iptables -t nat -D POSTROUTING -o br2 -s %s/32 -j MASQUERADE\n"
						"\t/usr/sbin/iptables -t nat -D POSTROUTING -o br3 -s %s/32 -j MASQUERADE\n"
						"\t/usr/sbin/iptables -t nat -D brwan_masq -s %s/32 -j MASQUERADE\n"
						"\t/usr/sbin/iptables -t nat -D ppp0_masq -s %s/32 -j MASQUERADE\n",
						peer_vip_item->valuestring,
						peer_vip_item->valuestring,
						peer_vip_item->valuestring,
						peer_vip_item->valuestring,
						peer_vip_item->valuestring,
						peer_vip_item->valuestring
						);
				append_line(fw_file, buf);
			}
		}
		cJSON_Delete(peers);
	}
	sprintf(buf, "fi\n");
	append_line(fw_file, buf);
}
#else
void ctrl_write_firewall_script(char *virtual_subnet)
{
	char buf[4096];
	sprintf(buf,
			"#! /bin/sh\n"
			"if [ \"$1\" == \"start\" ]; then\n"
			"\t/usr/sbin/iptables -I INPUT -i site0 -j ACCEPT\n"
			"\t/usr/sbin/iptables -I OUTPUT -o site0 -j ACCEPT\n"
			//"\t/usr/sbin/iptables -I INPUT -i brwan -p udp --dport 3277 -j ACCEPT\n"
			//"\t/usr/sbin/iptables -I INPUT -i ppp0 -p udp --dport 3277 -j ACCEPT\n"
			"\t/usr/sbin/iptables -I FORWARD -i site0 -j ACCEPT\n"
			"\t/usr/sbin/iptables -I FORWARD -o site0 -j ACCEPT\n"
			"\t/usr/sbin/iptables -t nat -I POSTROUTING -o site0 -j MASQUERADE\n"
			"\t/usr/sbin/iptables -t nat -I br0_masq -s %s -j MASQUERADE\n"
			"\t/usr/sbin/iptables -t nat -I brwan_masq -s %s -j MASQUERADE\n"
			"\t/usr/sbin/iptables -t nat -I ppp0_masq -s %s -j MASQUERADE\n"
			"fi\n"
			"if [ \"$1\" == \"stop\" ]; then\n"
			"\t/usr/sbin/iptables -D INPUT -i site0 -j ACCEPT\n"
			"\t/usr/sbin/iptables -D OUTPUT -o site0 -j ACCEPT\n"
			//"\t/usr/sbin/iptables -D INPUT -i brwan -p udp --dport 3277 -j ACCEPT\n"
			//"\t/usr/sbin/iptables -D INPUT -i ppp0 -p udp --dport 3277 -j ACCEPT\n"
			"\t/usr/sbin/iptables -D FORWARD -i site0 -j ACCEPT\n"
			"\t/usr/sbin/iptables -D FORWARD -o site0 -j ACCEPT\n"
			"\t/usr/sbin/iptables -t nat -D POSTROUTING -o site0 -j MASQUERADE\n"
			"\t/usr/sbin/iptables -t nat -D br0_masq -s %s -j MASQUERADE\n"
			"\t/usr/sbin/iptables -t nat -D brwan_masq -s %s -j MASQUERADE\n"
			"\t/usr/sbin/iptables -t nat -D ppp0_masq -s %s -j MASQUERADE\n"
			"fi\n"
			,
		virtual_subnet,
		virtual_subnet,
		virtual_subnet,
		virtual_subnet,
		virtual_subnet,
		virtual_subnet
		);
	write_shell((char*)"/etc/scripts/firewall/vppn.rule", buf);
}
#endif

void ctrl_stop_firewall()
{
	system("/etc/scripts/firewall/vppn.rule stop");
}

void ctrl_start_firewall()
{
	system("/etc/scripts/firewall/vppn.rule start");
}

void ctrl_reload_firewall(int channel, char* virtual_subnet)
{
	char peers_file[100];
	ctrl_stop_firewall();
	sprintf(peers_file, "/etc/site/vppn%d_peers.conf", channel);
	ctrl_write_firewall_script(peers_file);
	ctrl_start_firewall();
}
