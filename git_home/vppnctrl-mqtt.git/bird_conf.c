#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "bird_conf.h"
#include "cJSON.h"
#include "net_tool.h"
#include "file_tool.h"
#include "ctrl-interface.h"

void bird_config_common(char *buf)
{
	char *common_format = "router id %s; \n\n"
						"log \"/var/log/bird.log\" all; \n"
						"debug protocols { states, routes, filters, interfaces } \n\n"
						"protocol kernel { \n"
						"\timport none; \n"
						"\texport all; \n"
						"} \n\n"
						"protocol device { \n"
						"\t# default \n"
						"} \n\n";

	char local_ip[20] = {0};
	char common_buf[400] = {0};
	struct vpn_config_s *dump_config = ctrl_get_tunnel_config();
	net_tool_get_if_ip(dump_config->custom_lan_if, local_ip);

	sprintf(common_buf, common_format, local_ip);
	strcat(buf, common_buf);
	free(dump_config);
	
	return;
}

void bird_config_ospf(char *buf)
{
	int i=0;
	char intf_first[] =  "protocol ospf { \n"
						"\tarea 0 { \n"
						"\t\tinterface \"lo\" { \n"
						"\t\t\tstub; \n"
						"\t\t}; \n";
						/*"\t\tinterface \"br0\" { \n"
						"\t\t}; \n";*/
	
	char *intf_format = "\t\tinterface \"%s\" { \n"
						"\t\t\tstub; \n"
						"\t\t}; \n";
	
	char intf_last[] =	"\t}; \n"
						"}\n\n";

	strcat(buf, intf_first);
	
	for (i = 0; i < 5; i++)
	{
		char interface_buf[100];
		sprintf(interface_buf, "site%d", i);
		char content[400] = {0};
		sprintf(content, intf_format, interface_buf);
		strcat(buf, content);
	}
	
	strcat(buf, intf_last);

	return;
}

void bird_config_ebgp(char *buf, cJSON *peers)
{
	int i=0;
	int n=0;

	//char obj_str[20] = {0};
	char table_name[30] = {0};
	
	struct in_addr local_vip;
	struct in_addr peer_vip;

	char *ebgp_format = "table %s \n"	// table name
						"protocol static originate_to_%s { \n"	// table name
						"\ttable %s; \n"	// table name
						"\timport all; \n"
						"\troute %s blackhole; \n"	// subnet
						"} \n\n"
						"protocol bgp ebgp_%s { \n" // table name
						"\ttable %s; \n"	// table name
						"\tlocal %s as %d; \n"	// local vip, AS number
						"\tneighbor %s as %d; \n"	// peer vip, AS number
						"\timport filter { \n"
						"\t\taccept; \n"
						"\t}; \n"
						"\timport keep filtered on; \n"
						"\texport where source = RTS_STATIC; \n"
						"} \n\n"
						"protocol pipe p_master_to_%s { \n" // table name
						"\ttable master; \n"
						"\tpeer table %s; \n"	// table name
						"\timport where source = RTS_BGP; \n"
						"\texport none; \n"
						"} \n\n";
	
	char local_sub[100] = "";
	struct vpn_config_s *dump_config = ctrl_get_tunnel_config();
	net_tool_get_if_subnet(dump_config->custom_lan_if, local_sub);
	free(dump_config);

	n = cJSON_GetArraySize(peers);
	for (i=0; i<n; i++)
	{
		cJSON *obj = cJSON_GetArrayItem(peers, i);
		cJSON *peer_item = cJSON_GetObjectItem(obj, "peer_vip");
		cJSON *local_item = cJSON_GetObjectItem(obj, "local_vip");
		cJSON *tun_item = cJSON_GetObjectItem(obj, "tunnel_id");

		inet_aton(peer_item->valuestring, &peer_vip);
		peer_vip.s_addr = htonl(peer_vip.s_addr);

		inet_aton(local_item->valuestring, &local_vip);
		local_vip.s_addr = htonl(local_vip.s_addr);
		
		int local_as = local_vip.s_addr%1022 + 64512;
		int peer_as = peer_vip.s_addr%1022 + 64512;

		sprintf(table_name, "tun%d_%d", tun_item->valueint, peer_vip.s_addr & 0xffff);
		char content[1024] = {0};
		sprintf(content, ebgp_format, 
				table_name, table_name, table_name, local_sub,
				table_name, table_name, local_item->valuestring, local_as, peer_item->valuestring, peer_as,
				table_name, table_name);
				
		strcat(buf, content);
	}
}

void new_temp_peers_conf(cJSON *peers, int tunnel_id)
{
	char temp_bird_peers_file[100];
	sprintf(temp_bird_peers_file, "/etc/site/vppn%d_temp_peers.txt", tunnel_id);
	remove(temp_bird_peers_file);
	write_json_to_file(temp_bird_peers_file, peers);
	return;
}

cJSON* merge_temp_peers_conf()
{
	cJSON *peers = cJSON_CreateArray();
	int i;
	char temp_bird_peers_file[100];
	for(i = 0; i < 5; i++)
	{
		sprintf(temp_bird_peers_file, "/etc/site/vppn%d_temp_peers.txt", i);
		cJSON *tunnel_peers = read_json_from_file(temp_bird_peers_file);
		if (tunnel_peers)
		{
			int j;
			int tunnel_peers_cnt = cJSON_GetArraySize(tunnel_peers);
			for(j = 0; j < tunnel_peers_cnt; j++)
			{
				cJSON *item = cJSON_GetArrayItem(tunnel_peers, j);
				cJSON_AddItemToArray(peers, cJSON_Duplicate(item, 1));
			}
			cJSON_Delete(tunnel_peers);
		}
	}
	return peers;
}

void write_bird_conf(cJSON *peers)
{
	char *buf = malloc(256 * 1024);
	if (buf)
	{
		buf[0] = 0;
		bird_config_common(buf);
		bird_config_ospf(buf);
		bird_config_ebgp(buf, peers);
		write_text("/etc/bird.conf", buf);
		free(buf);
	}
	return;
}

void load_peer(cJSON *total_peers, int id, char* teamid)
{
	char conf_peer_file[100];
	char local_vip[100] = "";
	char v_interface[100];
	sprintf(v_interface, "site%d", id);

	int ip_err = net_tool_get_if_ip(v_interface, local_vip);
	if (ip_err == 0 && local_vip[0])
	{
		sprintf(conf_peer_file, "/etc/site/vppn%d_peers.conf", id);
		cJSON *peers = read_json_from_file(conf_peer_file);
		if (peers)
		{
			int i;
			int item_cnt = cJSON_GetArraySize(peers);
			for(i = 0; i < item_cnt; i++)
			{
				cJSON *peer = cJSON_GetArrayItem(peers, i);
				cJSON *peer_vip_item = cJSON_GetObjectItem(peer, "peer_vip");
				cJSON *peer_teamid_item = cJSON_GetObjectItem(peer, "peer_teamid");
				if (strcmp(peer_teamid_item->valuestring, teamid) == 0)
				{
					cJSON *new_obj = cJSON_CreateObject();
					cJSON_AddStringToObject(new_obj, "peer_vip", peer_vip_item->valuestring);
					cJSON_AddStringToObject(new_obj, "local_vip", local_vip);
					cJSON_AddNumberToObject(new_obj, "tunnel_id", id);
					cJSON_AddItemToArray(total_peers, new_obj);
				}
			}
			cJSON_Delete(peers);
		}
	}
	return;
}

void reload_bird_conf(int tunnel_id, char* teamid)
{
	cJSON *peers = cJSON_CreateArray();
	if (peers)
	{
		load_peer(peers, tunnel_id, teamid);
		new_temp_peers_conf(peers, tunnel_id);
		cJSON *bird_peers = merge_temp_peers_conf();
		if (bird_peers)
		{
			write_bird_conf(bird_peers);
			cJSON_Delete(bird_peers);
		}
		cJSON_Delete(peers);
	}
	return;
}


