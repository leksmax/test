#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <pthread.h>
#include <strings.h>
#include <string.h>
#include <arpa/inet.h>

/* add tinctool.h and tinctool.a */
#include <tinctool.h>
#include "ctrl_server.h"
#include "ctrl_server_json.h"
#include "ctrl-interface.h"
#include "vpn_config.h"
#include "cJSON.h"
#include "net_tool.h"
#include "my_debug.h"
#include "process_tool.h"
#include "str_tool.h"
#include "vpn_cloud.h"

#ifndef FREE_PTR
#define FREE_PTR(ptr) do{if (ptr) {free((ptr)); (ptr)=NULL;}}while(0);
#endif

extern void cJSON_Dump(cJSON *);

void update_member_traffic(cJSON* member, cJSON* nodes)
{
	cJSON* member_name_item = cJSON_GetObjectItem(member, "name");
	int found = 0;
	int i;
	int nodes_cnt = cJSON_GetArraySize(nodes);
	for(i = 0; i < nodes_cnt; i++)
	{
		cJSON* node_item = cJSON_GetArrayItem(nodes, i);
		cJSON* node_name_item = cJSON_GetObjectItem(node_item, "name");
		if (strcmp(member_name_item->valuestring, node_name_item->valuestring) == 0)
		{
			cJSON* node_direct_item = cJSON_GetObjectItem(node_item, "direct");
			cJSON* node_in_bps_item = cJSON_GetObjectItem(node_item, "in_bps");
			cJSON* node_out_bps_item = cJSON_GetObjectItem(node_item, "out_bps");
			cJSON* node_in_pps_item = cJSON_GetObjectItem(node_item, "in_pps");
			cJSON* node_out_pps_item = cJSON_GetObjectItem(node_item, "out_pps");
			cJSON* node_in_KB_item = cJSON_GetObjectItem(node_item, "in_KB");
			cJSON* node_out_KB_item = cJSON_GetObjectItem(node_item, "out_KB");

			cJSON_AddItemToObject(member, "direct", cJSON_Duplicate(node_direct_item, 1));
			cJSON_AddItemToObject(member, "in_bps", cJSON_Duplicate(node_in_bps_item, 1));
			cJSON_AddItemToObject(member, "out_bps", cJSON_Duplicate(node_out_bps_item, 1));
			cJSON_AddItemToObject(member, "in_pps", cJSON_Duplicate(node_in_pps_item, 1));
			cJSON_AddItemToObject(member, "out_pps", cJSON_Duplicate(node_out_pps_item, 1));
			cJSON_AddItemToObject(member, "in_KB", cJSON_Duplicate(node_in_KB_item, 1));
			cJSON_AddItemToObject(member, "out_KB", cJSON_Duplicate(node_out_KB_item, 1));
			found = 1;
			break;
		}
	}
	if (!found)
	{
		cJSON_AddItemToObject(member, "direct", cJSON_CreateNumber(0));
		cJSON_AddItemToObject(member, "in_bps", cJSON_CreateNumber(0));
		cJSON_AddItemToObject(member, "out_bps", cJSON_CreateNumber(0));
		cJSON_AddItemToObject(member, "in_pps", cJSON_CreateNumber(0));
		cJSON_AddItemToObject(member, "out_pps", cJSON_CreateNumber(0));
		cJSON_AddItemToObject(member, "in_KB", cJSON_CreateNumber(0));
		cJSON_AddItemToObject(member, "out_KB", cJSON_CreateNumber(0));
	}
	return;
}

void update_members_traffic(cJSON* members, cJSON* nodes)
{
	int i;
	int members_cnt = cJSON_GetArraySize(members);
	for(i = 0; i < members_cnt; i++)
	{
		cJSON* member = cJSON_GetArrayItem(members, i);
		update_member_traffic(member, nodes);
	}
	return;
}

static int uri_check_illegal(char *uri)
{
	int illegal = 0;
	int len = strlen(uri);
	if (len == 0)
	{
		illegal = 1;
		return illegal;
	}
	int i;
	for(i = 0; i < len; i++)
	{
		if (
			(uri[i] >= 'a' && uri[i] <= 'z')
				||
			(uri[i] >= 'A' && uri[i] <= 'Z')
				||
			(uri[i] >= '0' && uri[i] <= '9')
				||
			(uri[i] == '.')
				)
		{
			continue;
		}
		else
		{
			illegal = 1;
			break;
		}
	}
	return illegal;
}

static int find_vpath(cJSON *vpaths, char *gw, char *uri, char *teamid)
{
	int ret = -1;;
	int i;
	int cnt = cJSON_GetArraySize(vpaths);
	for(i = 0; i < cnt; i++)
	{
		cJSON *item = cJSON_GetArrayItem(vpaths, i);
		cJSON *gw_item = cJSON_GetObjectItem(item, "vproxy");
		cJSON *uri_item = cJSON_GetObjectItem(item, "uri");
		cJSON *teamid_item = cJSON_GetObjectItem(item, "team_id");

		if (gw)
		{
			if (gw_item && uri_item
					&&
					strcmp(gw_item->valuestring, gw) == 0
					&&
					strcmp(uri_item->valuestring, uri) == 0
					&&
					strcmp(teamid_item->valuestring, teamid) == 0
				)
			{
				ret = i;
				break;
			}
		}
		else
		{
			if (uri_item
					&&
					strcmp(uri_item->valuestring, uri) == 0
				)
			{
				ret = i;
				break;
			}
		}
	}
	return ret;
}

static void save_public_vpath_switch_conf(int on, int tunnel_id, int conf_type, char *gw)
{
	char vpath_switch_conf[100];
	cJSON *json_conf = cJSON_CreateObject();
	if (conf_type == 0)
	{
		sprintf(vpath_switch_conf, "/etc/vpn/public_vpath%d_switch.conf", tunnel_id);
	}
	else
	{
		sprintf(vpath_switch_conf, "/etc/site/public_vpath%d_switch.conf", tunnel_id);
		if (gw)
		{
			cJSON_AddStringToObject(json_conf, "vpath_tunnel", gw);
		}
	}
	cJSON_AddNumberToObject(json_conf, "on", on);
	write_json_to_file(vpath_switch_conf, json_conf);
	cJSON_Delete(json_conf);
	return;
}

static cJSON *get_route_list()
{
	cJSON *ret = cJSON_CreateArray();
	char line_buf[4096];
	FILE *route_fp = popen("route -n", "r");
	if (route_fp)
	{
		/* skip first two lines */
		fgets(line_buf, sizeof(line_buf),route_fp);
		fgets(line_buf, sizeof(line_buf),route_fp);
		memset(line_buf, 0, sizeof(line_buf));
		while(fgets(line_buf, sizeof(line_buf),route_fp))
		{
			char *save_ptr1 = NULL;
			char *str;
			char *token;
			char *dest = NULL;
			char *gw = NULL;
			char *mask = NULL;
			int i;
			int error = 0;
			for(str = line_buf, i = 0; i < 4 ;str = NULL, i++)
			{
				token = strtok_r(str, " ", &save_ptr1);
				if (!token)
				{
					error = 1;
					break;
				}
				if (i == 0)
				{
					dest = token;
				}
				else if(i == 1)
				{
					gw = token;
				}
				else if(i == 2)
				{
					mask = token;
				}
			}
			if (!error)
			{
				cJSON *new_obj = cJSON_CreateObject();
				MY_DEBUG_INFO("dest:%s\tgw:%s\t:mask:%s\n",dest, gw, mask);
				cJSON_AddStringToObject(new_obj, "dest", dest);
				cJSON_AddStringToObject(new_obj, "gw", gw);
				cJSON_AddStringToObject(new_obj, "mask", mask);
				cJSON_AddItemToArray(ret, new_obj);
			}
			memset(line_buf, 0, sizeof(line_buf));
		}
		pclose(route_fp);
	}
	return ret;
}

static int find_peer(cJSON *peers, char *peer, char *server)
{
	int ret = -1;
	int cnt = cJSON_GetArraySize(peers);
	int i;
	for(i = 0; i < cnt; i++)
	{
		cJSON *item = cJSON_GetArrayItem(peers, i);
		cJSON *peer_item = cJSON_GetObjectItem(item, "peer_vip");
		//cJSON *server_item = cJSON_GetObjectItem(item, "peer_server");
		if (peer_item 
				&&
				strcmp(peer_item->valuestring, peer) == 0
				)
		{
			ret = i;
			break;
		}
	}
	return  ret;
}

void json_response(cJSON *res, ctrl_request_t *request)
{
	char *data = cJSON_Print(res);
	if (data)
	{
		MY_DEBUG_INFO("#### response ####\n%s\n", data);
		send(request->client_fd, data, strlen(data) + 1, 0);
		free(data);
	}
	return;
}

void json_handle_ask_neighbor(cJSON *jsonreq, ctrl_request_t *request)
{
	cJSON *channel_item = cJSON_GetObjectItem(jsonreq, "channel");
	cJSON *vip_item = cJSON_GetObjectItem(jsonreq, "vip");
	int known = ctrl_find_neighbor(channel_item->valueint, vip_item->valuestring);
	char local_lan_ip[100];
	char local_lan_netmask[100];
	struct vpn_config_s *dump_config = ctrl_get_tunnel_config();
	if (dump_config)
	{
		ctrl_get_localsubnet(dump_config->custom_lan_if, local_lan_ip, local_lan_netmask);
	}
	cJSON *res = cJSON_CreateObject();
	cJSON_AddNumberToObject(res, "known", known);
	cJSON_AddStringToObject(res, "lan_ip", local_lan_ip);
	cJSON_AddStringToObject(res, "lan_netmask", local_lan_netmask);
	json_response(res, request);
	cJSON_Delete(res);
	FREE_PTR(dump_config);
	return;
}

void json_handle_start_vpn(cJSON *jsonreq, ctrl_request_t *request)
{
	//cJSON *server_port_item = cJSON_GetObjectItem(jsonreq, "server_addr");
	//cJSON *server_addr_item = cJSON_GetObjectItem(jsonreq, "server_port");
	cJSON *team_id_item = cJSON_GetObjectItem(jsonreq, "team_id");
	//cJSON *myself_addr_item = cJSON_GetObjectItem(jsonreq, "myself_addr");
	cJSON *channel_item = cJSON_GetObjectItem(jsonreq, "channel");
	int channel = channel_item->valueint;
	int err_code = 0;
	struct vpn_config_s *dump_config = ctrl_get_tunnel_config();
	if (dump_config)
	{
		ctrl_enable_vpn(dump_config->tunnel_type, channel, team_id_item->valuestring);
		err_code = 0;
	}
	else
	{
		err_code = 1;
	}
	cJSON *res = cJSON_CreateObject();
	cJSON_AddNumberToObject(res, "err_code", err_code);
	json_response(res, request);
	cJSON_Delete(res);
	FREE_PTR(dump_config);
	return;
}

void json_handle_stop_vpn(cJSON *jsonreq, ctrl_request_t *request)
{
	cJSON *channel_item = cJSON_GetObjectItem(jsonreq, "channel");
	int channel = channel_item->valueint;
	struct vpn_config_s *dump_config = ctrl_get_tunnel_config();
	int err_code = 0;
	if (dump_config)
	{
		ctrl_disable_vpn(dump_config->tunnel_type, channel);
		err_code = 0;
	}
	else
	{
		err_code = 1;
	}
	cJSON *res = cJSON_CreateObject();
	cJSON_AddNumberToObject(res, "err_code", err_code);
	json_response(res, request);
	cJSON_Delete(res);
	FREE_PTR(dump_config);
	return;
}

void json_handle_add_vpath_list(cJSON *jsonreq, ctrl_request_t *request)
{
	cJSON *channel_item = cJSON_GetObjectItem(jsonreq, "channel");
	cJSON *list_item = cJSON_GetObjectItem(jsonreq, "list");
	cJSON *teamid_item = cJSON_GetObjectItem(jsonreq, "team_id");

	int vpath_cnt = cJSON_GetArraySize(list_item);
	int err_code = 0;
	int conf_type = 0;
	struct vpn_config_s *dump_config = ctrl_get_tunnel_config();
	char vpath_file[100];
	/* server is NULL for vpn, non-NULL for vppn  */
	if (dump_config->tunnel_type != 0)
	{
		conf_type = TYPE_VPPN;
		sprintf(vpath_file, "/etc/site/vppn%d_vpath.conf", channel_item->valueint);
	}
	else
	{
		conf_type = TYPE_VPN;
		sprintf(vpath_file, "/etc/vpn/vpn%d_vpath.conf", channel_item->valueint);
	}
	cJSON *vpath_json = read_json_from_file(vpath_file);
	if (!vpath_json)
	{
		vpath_json = cJSON_CreateArray();
	}
	int i;
	for(i = 0; i < vpath_cnt; i++)
	{
		cJSON *item = cJSON_GetArrayItem(list_item, i);
		cJSON *gw_item = cJSON_GetObjectItem(item, "gw");
		cJSON *uri_item = cJSON_GetObjectItem(item, "uri");
		char *gw = gw_item->valuestring;
		char *uri = uri_item->valuestring;

		MY_DEBUG_INFO("ADD 1\n");
		if (uri && gw && uri[0] && !uri_check_illegal(uri))
		{
			int pos = find_vpath(vpath_json, gw, uri, teamid_item->valuestring);
			MY_DEBUG_INFO("ADD 2\n");
			if (pos >= 0)
			{
				MY_DEBUG_INFO("ADD 2.1\n");
				MY_DEBUG_INFO("ADD error\n");
			}
			else
			{
				MY_DEBUG_INFO("ADD ok\n");
				MY_DEBUG_INFO("ADD 2.2\n");
				cJSON *new_vpath = cJSON_CreateObject();
				if (gw)
				{
					cJSON_AddStringToObject(new_vpath, "vproxy", gw);
				}
				MY_DEBUG_INFO("ADD 2.3\n");
				cJSON_AddStringToObject(new_vpath, "uri", uri);
				cJSON_AddStringToObject(new_vpath, "team_id", teamid_item->valuestring);
				cJSON_AddItemToArray(vpath_json, new_vpath);
				MY_DEBUG_INFO("ADD 2.4\n");
			}
		}
	}
	err_code = 0;
	MY_DEBUG_INFO("ADD 3\n");
	write_json_to_file(vpath_file, vpath_json);
	MY_DEBUG_INFO("ADD 4\n");
	if (dump_config)
	{
		ctrl_reload_dnsmasq(conf_type, channel_item->valueint, dump_config->team_id);
	}
	MY_DEBUG_INFO("ADD 5\n");
	cJSON_Delete(vpath_json);

	MY_DEBUG_INFO("ADD 6\n");
	cJSON *res = cJSON_CreateObject();
	cJSON_AddNumberToObject(res, "err_code", err_code);
	json_response(res, request);
	MY_DEBUG_INFO("ADD 7\n");
	cJSON_Delete(res);
	MY_DEBUG_INFO("ADD 8\n");
	FREE_PTR(dump_config);
	MY_DEBUG_INFO("ADD 9\n");
	return;
}

void json_handle_del_vpath_list(cJSON *jsonreq, ctrl_request_t *request)
{
	cJSON *channel_item = cJSON_GetObjectItem(jsonreq, "channel");
	cJSON *list_item = cJSON_GetObjectItem(jsonreq, "list");
	cJSON *teamid_item = cJSON_GetObjectItem(jsonreq, "team_id");

	int vpath_cnt = cJSON_GetArraySize(list_item);
	int err_code = 0;
	int conf_type = 0;

	struct vpn_config_s *dump_config = ctrl_get_tunnel_config();
	char vpath_file[100];
	/* server is NULL for vpn, non-NULL for vppn  */
	if (dump_config->tunnel_type != 0)
	{
		conf_type = TYPE_VPPN;
		sprintf(vpath_file, "/etc/site/vppn%d_vpath.conf", channel_item->valueint);
	}
	else
	{
		conf_type = TYPE_VPN;
		sprintf(vpath_file, "/etc/vpn/vpn%d_vpath.conf", channel_item->valueint);
	}
	cJSON *vpath_json = read_json_from_file(vpath_file);
	if (!vpath_json)
	{
		vpath_json = cJSON_CreateArray();
	}
	int i;
	for(i = 0; i < vpath_cnt; i++)
	{
		cJSON *item = cJSON_GetArrayItem(list_item, i);
		cJSON *gw_item = cJSON_GetObjectItem(item, "gw");
		cJSON *uri_item = cJSON_GetObjectItem(item, "uri");
		char *gw = gw_item->valuestring;
		char *uri = uri_item->valuestring;

		int pos = find_vpath(vpath_json, gw, uri, teamid_item->valuestring);
		if (pos < 0)
		{

		}
		else
		{
			cJSON_DeleteItemFromArray(vpath_json, pos);
		}
	}
	err_code = 0;
	write_json_to_file(vpath_file, vpath_json);
	if (dump_config)
	{
		ctrl_reload_dnsmasq(conf_type, channel_item->valueint, dump_config->team_id);
	}
	cJSON_Delete(vpath_json);
	cJSON *res = cJSON_CreateObject();
	cJSON_AddNumberToObject(res, "err_code", err_code);
	json_response(res, request);
	cJSON_Delete(res);
	FREE_PTR(dump_config);
	return;
}

void json_handle_get_vpath_list(cJSON *jsonreq, ctrl_request_t *request)
{
	cJSON *channel_item = cJSON_GetObjectItem(jsonreq, "channel");
	cJSON *teamid_item = cJSON_GetObjectItem(jsonreq, "team_id");
	cJSON *list_item = cJSON_CreateArray();

	int err_code = 0;
	//int conf_type = 0;

	struct vpn_config_s *dump_config = ctrl_get_tunnel_config();
	char vpath_file[100];
	/* server is NULL for vpn, non-NULL for vppn  */
	if (dump_config->tunnel_type != 0)
	{
		//conf_type = TYPE_VPPN;
		sprintf(vpath_file, "/etc/site/vppn%d_vpath.conf", channel_item->valueint);
	}
	else
	{
		//conf_type = TYPE_VPN;
		sprintf(vpath_file, "/etc/vpn/vpn%d_vpath.conf", channel_item->valueint);
	}
	cJSON *vpath_json = read_json_from_file(vpath_file);
	if (!vpath_json)
	{
		vpath_json = cJSON_CreateArray();
	}
	int vpath_cnt = cJSON_GetArraySize(vpath_json);
	int i;
	for(i = 0; i < vpath_cnt; i++)
	{
		cJSON *item = cJSON_GetArrayItem(vpath_json, i);
		cJSON *gw_item = cJSON_GetObjectItem(item, "vproxy");
		cJSON *uri_item = cJSON_GetObjectItem(item, "uri");
		cJSON *teamid_file_item = cJSON_GetObjectItem(item, "team_id");
		//char *gw = gw_item->valuestring;
		//char *uri = uri_item->valuestring;
		if (strcmp(teamid_item->valuestring, teamid_file_item->valuestring) == 0)
		{
			cJSON* new_obj = cJSON_CreateObject();
			cJSON_AddStringToObject(new_obj, "uri", uri_item->valuestring);
			cJSON_AddStringToObject(new_obj, "gw", gw_item->valuestring);
			cJSON_AddItemToArray(list_item, new_obj);
		}
	}
	err_code = 0;
	//write_json_to_file(vpath_file, vpath_json);
	cJSON_Delete(vpath_json);
	cJSON *res = cJSON_CreateObject();
	cJSON_AddNumberToObject(res, "err_code", err_code);
	cJSON_AddItemToObject(res, "list", list_item);
	json_response(res, request);
	cJSON_Delete(res);
	FREE_PTR(dump_config);
	return;
}

void int_to_bitfield(void *bitfield, size_t size, unsigned int value)
{
    if(size > sizeof value)
        size = sizeof value;
    memcpy(bitfield, &value, size);
	return;
}

typedef struct node_status_t {
    unsigned int unused_active:1;           /* 1 if active (not used for nodes) */
    unsigned int validkey:1;                /* 1 if we currently have a valid key for him */
    unsigned int waitingforkey:1;           /* 1 if we already sent out a request */
    unsigned int visited:1;                 /* 1 if this node has been visited by one of the graph algorithms */
    unsigned int reachable:1;               /* 1 if this node is reachable in the graph */
    unsigned int indirect:1;                /* 1 if this node is not directly reachable by us */
    unsigned int sptps:1;                   /* 1 if this node supports SPTPS */
    unsigned int udp_confirmed:1;           /* 1 if the address is one that we received UDP traffic on */
    unsigned int send_locally:1;        /* 1 if the next UDP packet should be sent on the local network */
    unsigned int udppacket:1;       /* 1 if the most recently received packet was UDP */
    unsigned int validkey_in:1;     /* 1 if we have sent a valid key to him */
    unsigned int has_address:1;     /* 1 if we know an external address for this node */
    unsigned int unused:20;
} node_status_t;

static void name_to_ip(char* name, char *ip_out)
{
	int temp1;
	int temp2;
	sscanf(name, "%d_%d", &temp1, &temp2);
	sprintf(ip_out, "10.1.%d.%d", temp1, temp2);
	return;
}

#if 0
static cJSON* parse_reachable_nodes(char *str)
{
	cJSON* ret = cJSON_CreateArray();
	if (str)
	{
		int str_len = strlen(str);
		char *line_start = str;
		char *line_end = NULL;
		while((line_end = strchr(line_start, '\n')) != NULL)
		{
			char line_buf[200] = "";
			strncpy(line_buf, line_start, line_end - line_start);
			*line_end = 0;
			MY_DEBUG_INFO("line: %s\n", line_buf);
			char* name_ptr = line_start;
			char* status_ptr = strchr(line_start, ' ');
			*(status_ptr++) = 0;
			unsigned int status = 0;
			sscanf(status_ptr, "%x", &status);
			node_status_t node_state;
			int_to_bitfield(&node_state, sizeof(node_state), status);
			if (node_state.udp_confirmed)
			{
				cJSON* node_item = NULL;
				if (strcmp(name_ptr, "vpnserver") == 0)
				{
					node_item = cJSON_CreateString("10.1.255.1");
				}
				else
				{
					char vip[100] = "";
					name_to_ip(name_ptr, vip);
					node_item = cJSON_CreateString(vip);
				}
				cJSON_AddItemToArray(ret, node_item);
			}
			line_start = line_end + 1;
			if (line_start - str >= str_len)
			{
				break;
			}
		}
	}
	return ret;
}
#endif

static cJSON* parse_direct_nodes(char *str)
{
	cJSON* ret = cJSON_CreateArray();
	if (str)
	{
		int str_len = strlen(str);
		char *line_start = str;
		char *line_end = NULL;
		while((line_end = strchr(line_start, '\n')) != NULL)
		{
			char line_buf[200] = "";
			strncpy(line_buf, line_start, line_end - line_start);
			*line_end = 0;
			MY_DEBUG_INFO("line: %s\n", line_buf);
			char* name_ptr = line_start;
			char* status_ptr = strchr(line_start, ' ');
			*(status_ptr++) = 0;
			unsigned int status = 0;
			sscanf(status_ptr, "%x", &status);
			node_status_t node_state;
			int_to_bitfield(&node_state, sizeof(node_state), status);
			if (node_state.udp_confirmed)
			{
				cJSON* node_item = NULL;
				if (strcmp(name_ptr, "vpnserver") == 0)
				{
					node_item = cJSON_CreateString("10.255.255.254");
				}
				else
				{
					char vip[100] = "";
					name_to_ip(name_ptr, vip);
					node_item = cJSON_CreateString(vip);
				}
				cJSON_AddItemToArray(ret, node_item);
			}
			line_start = line_end + 1;
			if (line_start - str >= str_len)
			{
				break;
			}
		}
	}
	return ret;
}

void get_name_from_ip(char* name, char* ip)
{
	int seg1 = 0;
	int seg2 = 0;
	int seg3 = 0;
	int seg4 = 0;
	sscanf(ip, "%d.%d.%d.%d", &seg1, &seg2, &seg3, &seg4);
	sprintf(name, "%d_%d_%d", seg2, seg3, seg4);
	return;
}

/*member_type: 0 for router
 * 1 for phone
 * -1 for all
 * */
cJSON* get_members(char* cloud_host, int cloud_port, char* self_id, char* team_id, int member_type)
{
	cJSON* ret = cJSON_CreateArray();
	/* at least we have vpnserver node */
	cJSON* server_item = cJSON_CreateObject();
	cJSON_AddStringToObject(server_item, "ip", "10.255.255.254");
	cJSON_AddStringToObject(server_item, "sn", "");
	cJSON_AddNumberToObject(server_item, "status", 1);
	cJSON_AddStringToObject(server_item, "name", "vpnserver");
	cJSON_AddNumberToObject(server_item, "self", 0);

	cJSON_AddItemToArray(ret, server_item);

	struct vpn_config_s *dump_config = ctrl_get_tunnel_config();

	if (cloud_host && cloud_port && self_id && team_id
			&& cloud_host[0]
			&& self_id[0]
			&& team_id[0]
			)
	{
		cJSON* req = cJSON_CreateObject();
		if (req)
		{
			cJSON_AddStringToObject(req, "teamId", team_id);
			cJSON* response = vpn_cloud_tool3((char*)"/vppn/api/v1/client/searchTeamById", req);
			//cJSON* response = net_tool_https_json_client(1, dump_config->cloud_host, 443, "/vppn/api/v1/client/searchTeamById", req, headers_ptr, 2, NULL);

			//cJSON* response = net_tool_http_json_client2(1, cloud_host, cloud_port, "/vppn/api/v1/client/searchTeamById", req, "Authorization: Basic YWRtaW46cHVibGlj\r\n");
			if (response)
			{
				cJSON_Dump(response);
				cJSON* code_item = cJSON_GetObjectItem(response, "code");
				if (code_item)
				{
					cJSON* members_item = cJSON_GetObjectItem(response, "members");
					cJSON_Dump(members_item);
					int members_cnt = cJSON_GetArraySize(members_item);
					int i;
					for(i = 0; i < members_cnt; i++)
					{
						cJSON* member_item = cJSON_GetArrayItem(members_item, i);
						cJSON* ip_item = cJSON_GetObjectItem(member_item, "ip");
						cJSON* mac_item = cJSON_GetObjectItem(member_item, "mac");
						cJSON* status_item = cJSON_GetObjectItem(member_item, "status");
						cJSON* memberType_item = cJSON_GetObjectItem(member_item, "memberType");

						if (member_type < 0 ||
								memberType_item->valueint == member_type)
						{
							cJSON* new_member = cJSON_CreateObject();
							cJSON_AddItemToArray(ret, new_member);
							char name[100] = "";
							get_name_from_ip(name, ip_item->valuestring);
							cJSON_AddStringToObject(new_member, "ip", ip_item->valuestring);
							cJSON_AddStringToObject(new_member, "sn", mac_item->valuestring);
							cJSON_AddNumberToObject(new_member, "status", status_item->valueint);
							cJSON_AddStringToObject(new_member, "name", name);
							if (strcmp(mac_item->valuestring, self_id) == 0)
							{
								cJSON_AddNumberToObject(new_member, "self", 1);
							}
							else
							{
								cJSON_AddNumberToObject(new_member, "self", 0);
							}
						}
					}
				}
				cJSON_Delete(response);
			}
			cJSON_Delete(req);
		}
	}
	cJSON_Dump(ret);
	FREE_PTR(dump_config);
	return ret;
}

void json_handle_ping_members(cJSON* jsonreq, ctrl_request_t* request)
{
	//cJSON *channel_item = cJSON_GetObjectItem(jsonreq, "channel");
	//cJSON *teamid_item = cJSON_GetObjectItem(jsonreq, "team_id");
	struct vpn_config_s *dump_config = ctrl_get_tunnel_config();
	cJSON *res = cJSON_CreateObject();
	
	cJSON* members = get_members(dump_config->cloud_host,
				dump_config->cloud_port,
				dump_config->self_id,
				dump_config->team_id, 0
			);
	//cJSON_Dump(members);
	net_tool_ping_hosts3(members, (char*)"ip", (char*)"latency", (char*)"latency_list", (char*)"loss", 2, 10);
	int tunnel_id = dump_config->tunnel.tunnel_id;
	char tinc_pidfile[100] = "";
	char tinc_base[100] = "";
	sprintf(tinc_base, "/etc/tinc/site%d", tunnel_id);
	sprintf(tinc_pidfile, "/var/run/site%d.pid", tunnel_id);
	cJSON* nodes = tinctool_dump_traffic(tinc_base, tinc_pidfile);
	if (nodes)
	{
		//cJSON_Dump(nodes);
		update_members_traffic(members, nodes);
		cJSON_Delete(nodes);
	}
	cJSON_AddNumberToObject(res, "err_code", 0);
	cJSON_AddItemToObject(res, "members", members);
	json_response(res, request);
	cJSON_Delete(res);
	FREE_PTR(dump_config);
}

void json_handle_set_debuglevel(cJSON* jsonreq, ctrl_request_t* request)
{
	cJSON *level_item = cJSON_GetObjectItem(jsonreq, "level");
	cJSON *res = cJSON_CreateObject();
	if (level_item)
	{
		my_debug_set_level(level_item->valueint);
		cJSON_AddStringToObject(res, "err_code", "200");
	}
	else
	{
		cJSON_AddStringToObject(res, "err_code", "201");
	}
	json_response(res, request);
	cJSON_Delete(res);
}

void json_handle_get_connectInfo(cJSON* jsonreq, ctrl_request_t* request)
{
	cJSON *res = cJSON_CreateObject();
	struct vpn_config_s *dump_config = ctrl_get_tunnel_config();
	cJSON_AddStringToObject(res, "err_code", "200");
	cJSON_AddStringToObject(res, "host", dump_config->tunnel.info.resource.vpn_server_host);
	json_response(res, request);
	cJSON_Delete(res);
	FREE_PTR(dump_config);
}

void json_handle_dump_nodes(cJSON* jsonreq, ctrl_request_t* request)
{
	//cJSON *channel_item = cJSON_GetObjectItem(jsonreq, "channel");
	//cJSON *teamid_item = cJSON_GetObjectItem(jsonreq, "team_id");
	//cJSON *list_item = cJSON_CreateArray();
	struct vpn_config_s *dump_config = ctrl_get_tunnel_config();
	char cmdbuf[200];
	sprintf(cmdbuf, "tinc --config=/etc/tinc/site%d --pidfile=/var/run/site%d.pid dump reachable nodes | awk '{print $1,$19}'", dump_config->tunnel.tunnel_id, dump_config->tunnel.tunnel_id);
	char *result = process_tool_run_cmd(cmdbuf);
	cJSON* nodes = NULL;
	cJSON *res = cJSON_CreateObject();
	if (result)
	{
		nodes = parse_direct_nodes(result);
		free(result);
	}
	if (!nodes)
	{
		nodes = cJSON_CreateArray();
	}

	cJSON_AddNumberToObject(res, "err_code", 0);
	cJSON_AddItemToObject(res, "direct_list", nodes);
	json_response(res, request);
	cJSON_Delete(res);
	FREE_PTR(dump_config);
}

extern void set_members_conf(cJSON* members, char* teamid, char* self_id, int tunnel_id, struct vpn_tunnel_s *tunnel);

void json_handle_reload_member(cJSON *jsonreq, ctrl_request_t *request)
{
	//cJSON *channel_item = cJSON_GetObjectItem(jsonreq, "channel");
	//cJSON *teamid_item = cJSON_GetObjectItem(jsonreq, "team_id");
	//cJSON *list_item = cJSON_CreateArray();

	//int err_code = 0;
	//int conf_type = 0;

	struct vpn_config_s *dump_config = ctrl_get_tunnel_config();
	cJSON* req = cJSON_CreateObject();
	if (req)
	{
		cJSON* reconnectItem = cJSON_GetObjectItem(jsonreq, "reconnect_flag");
		cJSON* req_proxyIpItem = cJSON_GetObjectItem(jsonreq, "proxyIp");
		cJSON_AddStringToObject(req, "teamId", dump_config->team_id);
		cJSON* response = vpn_cloud_tool3((char*)"/vppn/api/v1/client/searchTeamById", req);
		//cJSON* response = net_tool_https_json_client(1, dump_config->cloud_host, 443, "/vppn/api/v1/client/searchTeamById", req, headers_ptr, 2, NULL);
		//cJSON* response = net_tool_http_json_client2(1, dump_config->cloud_host, dump_config->cloud_port, "/vppn/api/v1/client/searchTeamById", req, "Authorization: Basic YWRtaW46cHVibGlj\r\n");
		if (response)
		{
			cJSON* code_item = cJSON_GetObjectItem(response, "code");
			if (code_item)
			{
				if (code_item->valueint == 200)
				{
					cJSON* proxyKey_item = cJSON_GetObjectItem(response, "pubKey");
					if (proxyKey_item)
					{
						write_text((char*)"/tmp/rsa_key.pub", proxyKey_item->valuestring);
					}
					cJSON* res_proxyIpItem = cJSON_GetObjectItem(response, "proxyIp");
					if (dump_config->tunnel.tunnel_on)
					{
						if (reconnectItem)
						{
							if (reconnectItem->valueint == 1)
							{
								if (req_proxyIpItem 
										&& res_proxyIpItem
										&& (strcmp(req_proxyIpItem->valuestring, res_proxyIpItem->valuestring) == 0)
										)
								{
									MY_DEBUG_INFO("-----start refresh----\n");
									ctrl_refresh_vpn();
								}
							}
							else if (reconnectItem->valueint == 2)
							{
								ctrl_refresh_vpn();
							}
						}
					}
					cJSON* members_item = cJSON_GetObjectItem(response, "members");
					if (members_item)
					{
						set_members_conf(members_item, dump_config->team_id, dump_config->self_id, dump_config->tunnel.tunnel_id, &dump_config->tunnel);
					}
				}
			}
			cJSON_Delete(response);
		}
		cJSON_Delete(req);
	}
	FREE_PTR(dump_config);
	return;
}

void json_handle_add_vpath(cJSON *jsonreq, ctrl_request_t *request)
{
	/* res info */
	cJSON *channel_item = cJSON_GetObjectItem(jsonreq, "channel");
	cJSON *gw_item = cJSON_GetObjectItem(jsonreq, "vproxy");
	//cJSON *server_item = cJSON_GetObjectItem(jsonreq, "server");
	cJSON *uri_item = cJSON_GetObjectItem(jsonreq, "uri");
	cJSON *teamid_item = cJSON_GetObjectItem(jsonreq, "team_id");

	int conf_type = 0;
	char *gw = gw_item->valuestring;
	//char *server = server_item->valuestring;
	char *uri = uri_item->valuestring;
	int err_code = 1;
	if (uri && uri[0] && !uri_check_illegal(uri))
	{
		MY_DEBUG_INFO("ADD vproxy = %s,  uri = %s\n", gw, uri);
		struct vpn_config_s *dump_config = ctrl_get_tunnel_config();
		char vpath_file[100];
		/* server is NULL for vpn, non-NULL for vppn  */
		if (dump_config->tunnel_type != 0)
		{
			conf_type = TYPE_VPPN;
			sprintf(vpath_file, "/etc/site/vppn%d_vpath.conf", channel_item->valueint);
		}
		else
		{
			conf_type = TYPE_VPN;
			sprintf(vpath_file, "/etc/vpn/vpn%d_vpath.conf", channel_item->valueint);
		}

		cJSON *vpath_json = read_json_from_file(vpath_file);
		if (!vpath_json)
		{
			vpath_json = cJSON_CreateArray();
		}
		int pos = find_vpath(vpath_json, gw, uri, teamid_item->valuestring);
		if (pos >= 0)
		{
			MY_DEBUG_INFO("ADD error\n");
		}
		else
		{
			MY_DEBUG_INFO("ADD ok\n");
			cJSON *new_vpath = cJSON_CreateObject();
			if (gw)
			{
				cJSON_AddStringToObject(new_vpath, "vproxy", gw);
			}
			cJSON_AddStringToObject(new_vpath, "uri", uri);
			cJSON_AddItemToArray(vpath_json, new_vpath);
			err_code = 0;
		}
		write_json_to_file(vpath_file, vpath_json);
		cJSON_Delete(vpath_json);
		if (dump_config)
		{
			ctrl_reload_dnsmasq(conf_type, channel_item->valueint, dump_config->team_id);
		}
		FREE_PTR(dump_config);
	}
	cJSON *res = cJSON_CreateObject();
	cJSON_AddNumberToObject(res, "err_code", err_code);
	json_response(res, request);
	cJSON_Delete(res);
	return;
}

void json_handle_del_vpath(cJSON *jsonreq, ctrl_request_t *request)
{
	cJSON *channel_item = cJSON_GetObjectItem(jsonreq, "channel");
	cJSON *gw_item = cJSON_GetObjectItem(jsonreq, "vproxy");
	cJSON *uri_item = cJSON_GetObjectItem(jsonreq, "uri");
	cJSON *teamid_item = cJSON_GetObjectItem(jsonreq, "team_id");

	int conf_type = 0;
	char *gw = gw_item->valuestring;
	char *uri = uri_item->valuestring;
	int err_code = 1;
	if (uri && uri[0])
	{
		struct vpn_config_s *dump_config = ctrl_get_tunnel_config();
		char vpath_file[100];
		/* server is NULL for vpn, non-NULL for vppn  */
		if (dump_config->tunnel_type != 0)
		{
			conf_type = TYPE_VPPN;
			sprintf(vpath_file, "/etc/site/vppn%d_vpath.conf", channel_item->valueint);
		}
		else
		{
			conf_type = TYPE_VPN;
			sprintf(vpath_file, "/etc/vpn/vpn%d_vpath.conf", channel_item->valueint);
		}
		cJSON *vpath_json = read_json_from_file(vpath_file);
		if (!vpath_json)
		{
			vpath_json = cJSON_CreateArray();
		}

		int pos = find_vpath(vpath_json, gw, uri, teamid_item->valuestring);
		if (pos < 0)
		{

		}
		else
		{
			cJSON_DeleteItemFromArray(vpath_json, pos);
			err_code = 0;
		}
		write_json_to_file(vpath_file, vpath_json);
		if (dump_config)
		{
			ctrl_reload_dnsmasq(conf_type, channel_item->valueint, dump_config->team_id);
		}
		cJSON_Delete(vpath_json);
		FREE_PTR(dump_config);
	}
	cJSON *res = cJSON_CreateObject();
	cJSON_AddNumberToObject(res, "err_code", err_code);
	json_response(res, request);
	cJSON_Delete(res);
	return;
}

void json_handle_add_public_vpath(cJSON *jsonreq, ctrl_request_t *request)
{
	//cJSON *channel_item = cJSON_GetObjectItem(jsonreq, "channel");
	cJSON *gw_item = cJSON_GetObjectItem(jsonreq, "vproxy");
	char *gw = gw_item->valuestring;
	int err_code = 1;

	struct vpn_config_s *dump_config = ctrl_get_tunnel_config();
	cJSON *whitelist = get_public_whitelist(dump_config->cloud_host, dump_config->cloud_port, dump_config->tunnel_type, dump_config->tunnel.tunnel_id);
	if (whitelist)
	{
		err_code = 0;
		generate_public_vpath_conf(whitelist, dump_config->tunnel_type, dump_config->tunnel.tunnel_id, gw);
		save_public_vpath_switch_conf(1, dump_config->tunnel.tunnel_id, dump_config->tunnel_type, gw);
		ctrl_reload_dnsmasq(dump_config->tunnel_type, dump_config->tunnel.tunnel_id, dump_config->team_id);
		cJSON_Delete(whitelist);
	}
	cJSON *res = cJSON_CreateObject();
	cJSON_AddNumberToObject(res, "err_code", err_code);
	json_response(res, request);
	cJSON_Delete(res);
	FREE_PTR(dump_config);
	return;
}

void json_handle_del_public_vpath(cJSON *jsonreq, ctrl_request_t *request)
{
	//cJSON *channel_item = cJSON_GetObjectItem(jsonreq, "channel");
	int err_code = 0;
	struct vpn_config_s *dump_config = ctrl_get_tunnel_config();

	remove_public_vpath_conf(dump_config->tunnel_type, dump_config->tunnel.tunnel_id);
	save_public_vpath_switch_conf(0, dump_config->tunnel.tunnel_id, dump_config->tunnel_type, NULL);
	ctrl_reload_dnsmasq(dump_config->tunnel_type, dump_config->tunnel.tunnel_id, dump_config->team_id);
	//ctrl_reload_dnsmasq(dump_config->tunnel_type, dump_config->tunnel.tunnel_id);

	cJSON *res = cJSON_CreateObject();
	cJSON_AddNumberToObject(res, "err_code", err_code);
	json_response(res, request);
	cJSON_Delete(res);
	FREE_PTR(dump_config);
	return;
}

void json_handle_get_serverlist(cJSON *jsonreq, ctrl_request_t *request)
{
	int err_code = 1;
	cJSON *res = cJSON_CreateObject();
	struct vpn_config_s *dump_config = ctrl_get_tunnel_config();
	cJSON *req = cJSON_CreateObject();
	cJSON *serverlist = vpn_cloud_tool3((char*)"/GetServerList", req);
	//cJSON *serverlist = net_tool_http_json_client(dump_config->cloud_host, dump_config->cloud_port, "/GetServerList", req);
	if (serverlist)
	{
		MY_DEBUG_INFO("serverlist1\n");
		err_code = 0;
		cJSON_AddItemToObject(res, "server_list", serverlist);
	}
	MY_DEBUG_INFO("serverlist2\n");
	cJSON_AddNumberToObject(res, "err_code", err_code);
	MY_DEBUG_INFO("serverlist3\n");
	json_response(res, request);
	MY_DEBUG_INFO("serverlist4\n");
	cJSON_Delete(res);
	MY_DEBUG_INFO("serverlist5\n");
	cJSON_Delete(req);
	MY_DEBUG_INFO("serverlist6\n");
	FREE_PTR(dump_config);
	return;
}

void json_handle_get_route(cJSON *jsonreq, ctrl_request_t *request)
{
	int err_code = 0;
	cJSON *route_list = get_route_list();
	if (!route_list)
	{
		err_code = 1;
		route_list = cJSON_CreateArray();
	}

	cJSON *res = cJSON_CreateObject();
	cJSON_AddNumberToObject(res, "err_code", err_code);
	cJSON_AddItemToObject(res, "route_list", route_list);
	json_response(res, request);
	cJSON_Delete(res);
	return;
}

void json_handle_add_peer(cJSON *jsonreq, ctrl_request_t *request)
{
	int err_code = 0;
	cJSON *channel_item = cJSON_GetObjectItem(jsonreq, "channel");
	cJSON *peer_item = cJSON_GetObjectItem(jsonreq, "peer");
	cJSON *server_item = cJSON_GetObjectItem(jsonreq, "server");

	char *peer = peer_item->valuestring;
	char *server = server_item->valuestring;
	char peers_conf_file[100];

	sprintf(peers_conf_file, "/etc/site/vppn%d_peers.conf", channel_item->valueint);
	cJSON *peers_json = read_json_from_file(peers_conf_file);
	if (peers_json)
	{
	}
	else
	{
		peers_json = cJSON_CreateArray();
	}
	if (find_peer(peers_json, peer, server) < 0)
	{
		cJSON *new_peer = cJSON_CreateObject();
		cJSON_AddStringToObject(new_peer, "peer_vip", peer);
		//cJSON_AddStringToObject(new_peer, "peer_server", server);
		cJSON_AddItemToArray(peers_json, new_peer);
		err_code = 0;
	}
	else
	{
		err_code = 1;
	}
	write_json_to_file(peers_conf_file, peers_json);
	cJSON_Delete(peers_json);
	struct vpn_config_s *dump_config = ctrl_get_tunnel_config();
	if (dump_config)
	{
		//ctrl_reload_bird(TYPE_VPPN, dump_config->tunnel.tunnel_id, dump_config->team_id);
		ctrl_restart_swap_routed();
	}
	cJSON *res = cJSON_CreateObject();
	cJSON_AddNumberToObject(res, "err_code", err_code);
	json_response(res, request);
	cJSON_Delete(res);
	FREE_PTR(dump_config);
	return;
}

void json_handle_del_peer(cJSON *jsonreq, ctrl_request_t *request)
{
	int err_code = 0;
	cJSON *channel_item = cJSON_GetObjectItem(jsonreq, "channel");
	cJSON *peer_item = cJSON_GetObjectItem(jsonreq, "peer");
	cJSON *server_item = cJSON_GetObjectItem(jsonreq, "server");

	char *peer = peer_item->valuestring;
	char *server = server_item->valuestring;
	char peers_conf_file[100];

	sprintf(peers_conf_file, "/etc/site/vppn%d_peers.conf", channel_item->valueint);
	cJSON *peers_json = read_json_from_file(peers_conf_file);
	if (peers_json)
	{
	}
	else
	{
		peers_json = cJSON_CreateArray();
	}

	int pos = find_peer(peers_json, peer, server);
	if (pos >= 0)
	{
		cJSON_DeleteItemFromArray(peers_json, pos);
		err_code = 0;
	}
	else
	{
		err_code = 1;
	}
	write_json_to_file(peers_conf_file, peers_json);
	cJSON_Delete(peers_json);
	struct vpn_config_s *dump_config = ctrl_get_tunnel_config();
	if (dump_config)
	{
		//ctrl_reload_bird(TYPE_VPPN, dump_config->tunnel.tunnel_id, dump_config->team_id);
		ctrl_restart_swap_routed();
	}
	cJSON *res = cJSON_CreateObject();
	cJSON_AddNumberToObject(res, "err_code", err_code);
	json_response(res, request);
	cJSON_Delete(res);
	FREE_PTR(dump_config);
	return;
}

void json_handle_add_manager(cJSON *jsonreq, ctrl_request_t *request)
{
	int err_code = 1;
	cJSON *host_item = cJSON_GetObjectItem(jsonreq, "cloud_host");
	cJSON *port_item = cJSON_GetObjectItem(jsonreq, "cloud_port");
	cJSON *channel_item = cJSON_GetObjectItem(jsonreq, "channel");
	struct vpn_config_s *dump_config = ctrl_get_tunnel_config();
	if (dump_config)
	{
		err_code = 0;
		ctrl_set_manager(dump_config->tunnel_type, channel_item->valueint, host_item->valuestring, port_item->valueint);
	}
	cJSON *res = cJSON_CreateObject();
	cJSON_AddNumberToObject(res, "err_code", err_code);
	json_response(res, request);
	cJSON_Delete(res);
	FREE_PTR(dump_config);
	return;
}

void json_handle_del_manager(cJSON *jsonreq, ctrl_request_t *request)
{
	cJSON *res = cJSON_CreateObject();
	cJSON_AddNumberToObject(res, "err_code", 0);
	json_response(res, request);
	cJSON_Delete(res);
	return;
}

cJSON *json_get_manager(int tunnel_type, int tunnel_id)
{
	cJSON *ret = ctrl_get_manager(tunnel_type, tunnel_id);
	if (!ret)
	{
		ret = cJSON_CreateObject();
	}
	return ret;
}

cJSON *json_get_peers(int tunnel_id, char *server)
{
	char peers_conf_file[100];
	sprintf(peers_conf_file, "/etc/site/vppn%d_peers.conf", tunnel_id);
	cJSON *ret = cJSON_CreateArray();
	cJSON *peers_json = read_json_from_file(peers_conf_file);
	if (peers_json)
	{
		int peers_cnt = cJSON_GetArraySize(peers_json);
		int i;

		if (peers_cnt)
		{
			//res_param.channel_peers = &res_peers;

			for (i = 0; i < peers_cnt; i++)
			{
				cJSON *item = cJSON_GetArrayItem(peers_json, i);
				cJSON *peer_vip_item = cJSON_GetObjectItem(item, "peer_vip");
				//cJSON *peer_server_item = cJSON_GetObjectItem(item, "peer_server");
				cJSON *item_to_ping = cJSON_CreateObject();
				cJSON_AddItemToObject(item_to_ping, "peer_vip", cJSON_Duplicate(peer_vip_item, 1));
				//cJSON_AddItemToObject(item_to_ping, "peer_server", cJSON_Duplicate(peer_server_item, 1));
				cJSON_AddItemToArray(ret, item_to_ping);
			}
			net_tool_ping_hosts2(ret, (char*)"peer_vip", (char*)"peer_latency", 2);
		}
		cJSON_Delete(peers_json);
	}
	return ret;
}

cJSON *json_get_routes()
{
	cJSON *ret = get_route_list();
	if (!ret)
	{
		ret = cJSON_CreateArray();
	}
	return ret;
}

cJSON *json_get_vpathlist(int tunnel_type, int tunnel_id)
{
	//int conf_type;
	char vpath_file[100];
	if (tunnel_type != 0)
	{
		sprintf(vpath_file, "/etc/site/vppn%d_vpath.conf", tunnel_id);
	}
	else
	{
		sprintf(vpath_file, "/etc/vpn/vpn%d_vpath.conf", tunnel_id);
	}
	cJSON *ret = read_json_from_file(vpath_file);
	if (!ret)
	{
		ret = cJSON_CreateArray();
	}
	return ret;
}

cJSON *json_get_public_vpath(int tunnel_type, int tunnel_id)
{
	cJSON *ret = ctrl_get_public_whitelist_switch(tunnel_type, tunnel_id);
	if (!ret)
	{
		ret = cJSON_CreateObject();
	}
	return ret;
}

cJSON *json_get_package(struct vpn_tunnel_s *tunnel)
{
	cJSON *ret = cJSON_CreateObject();
	cJSON_AddStringToObject(ret, "endtime", tunnel->info.package.endtime);
	cJSON_AddStringToObject(ret, "flow", tunnel->info.package.flow);
	cJSON_AddStringToObject(ret, "mac", tunnel->info.package.mac);
	cJSON_AddStringToObject(ret, "type", tunnel->info.package.type);
	return ret;
}

cJSON *json_get_vpn_peers()
{
	cJSON *res = NULL;
	struct vpn_config_s *dump_config = ctrl_get_tunnel_config();
	res = json_get_peers(dump_config->tunnel.tunnel_id, dump_config->tunnel.info.resource.vpn_server_host);
	FREE_PTR(dump_config);
	return res;
}

cJSON *json_get_vpn_status()
{
	cJSON *res = cJSON_CreateObject();

	cJSON *route_list_item = json_get_routes();
	cJSON *status_item = cJSON_CreateObject();
	struct vpn_config_s *dump_config = ctrl_get_tunnel_config();

	cJSON *manager_item = json_get_manager(dump_config->tunnel_type, dump_config->tunnel.tunnel_id);
	cJSON_AddItemToObject(res, "manager", manager_item);
	cJSON_AddItemToObject(res, "route_list", route_list_item);
	cJSON_AddItemToObject(res, "tunnel_status", status_item);

	cJSON_AddNumberToObject(status_item, "err_code", 0);
	cJSON_AddStringToObject(status_item, "proxy_host", dump_config->tunnel.info.resource.vpn_server_host);
	cJSON_AddNumberToObject(status_item, "proxy_port", dump_config->tunnel.info.resource.vpn_server_port);
	//cJSON_AddNumberToObject(status_item, "proxy_latency", net_tool_ping_host(dump_config->tunnel.info.resource.vpn_server_host, 2));
	cJSON_AddStringToObject(status_item, "tunnel_vip", dump_config->tunnel.info.resource.vpn_ip);
	cJSON_AddNumberToObject(status_item, "tunnel_latency", dump_config->tunnel.info.latency);
	//cJSON_AddItemToObject(status_item, "peers", json_get_peers(dump_config->tunnel.tunnel_id, dump_config->tunnel.info.resource.vpn_server_host));
	cJSON_AddItemToObject(status_item, "vpaths", json_get_vpathlist(dump_config->tunnel_type, dump_config->tunnel.tunnel_id));
	cJSON_AddItemToObject(status_item, "public_vpaths", json_get_public_vpath(dump_config->tunnel_type, dump_config->tunnel.tunnel_id));
	cJSON_AddItemToObject(status_item, "package", json_get_package(&dump_config->tunnel));
	switch(dump_config->tunnel.info.status)
	{
		case TUNNEL_GET_RESOURCE:
			cJSON_AddStringToObject(status_item, "running_status", "selecting_resource");
			break;
		case TUNNEL_CONNECT:
			cJSON_AddStringToObject(status_item, "running_status", "connecting");
			break;
		case TUNNEL_DONE:
			cJSON_AddStringToObject(status_item, "running_status", "connected");
			break;
		default:
			cJSON_AddStringToObject(status_item, "running_status", "disable");
			break;
	}
	FREE_PTR(dump_config);
	return res;
}

cJSON *global_vpn_status = NULL;
pthread_mutex_t vpn_status_lock;


cJSON *global_vpn_peers = NULL;
pthread_mutex_t vpn_peers_lock;

void update_vpn_peers()
{
	cJSON *new_vpn_peers = json_get_vpn_peers();
	if (new_vpn_peers)
	{
		pthread_mutex_lock(&vpn_peers_lock);
		if (global_vpn_peers)
		{
			cJSON_Delete(global_vpn_peers);
		}
		global_vpn_peers = new_vpn_peers;
		pthread_mutex_unlock(&vpn_peers_lock);
	}
	return;
}

void *json_get_vpn_peers_thread(void *arg)
{
	pthread_detach(pthread_self());
	while(1)
	{
		update_vpn_peers();
		sleep(10);
	}
	return NULL;
}

void create_peers_update_thread()
{
	pthread_t nid;
	pthread_mutex_init(&vpn_peers_lock, NULL);
	pthread_create(&nid, NULL, json_get_vpn_peers_thread, NULL);
	return;
}

void sync_peer(cJSON *new_peers, cJSON *old_item)
{
	int new_cnt = cJSON_GetArraySize(new_peers);
	int i;

	cJSON *old_vip_item = cJSON_GetObjectItem(old_item, "peer_vip");
	//cJSON *old_server_item = cJSON_GetObjectItem(old_item, "peer_server");
	cJSON *old_latency_item = cJSON_GetObjectItem(old_item, "peer_latency");
	for(i = 0; i < new_cnt; i++)
	{
		cJSON *new_item = cJSON_GetArrayItem(new_peers, i);
		cJSON *vip_item = cJSON_GetObjectItem(new_item, "peer_vip");
		//cJSON *server_item = cJSON_GetObjectItem(new_item, "peer_server");
		//cJSON *latency_item = cJSON_GetObjectItem(new_item, "peer_latency");
		if (strcmp(vip_item->valuestring, old_vip_item->valuestring) == 0)
		{
			if (old_latency_item)
			{
				cJSON_AddNumberToObject(new_item, "peer_latency", old_latency_item->valueint);
			}
		}
	}
	return;
}

void sync_peers(cJSON *new_peers, cJSON *old_peers)
{
	int old_cnt = cJSON_GetArraySize(old_peers);
	int i;
	for(i = 0; i < old_cnt; i++)
	{
		cJSON *old_item = cJSON_GetArrayItem(old_peers, i);
		sync_peer(new_peers, old_item);
	}
	return;
}

void fix_vpnstatus_peers(cJSON *status, int tunnel_id)
{
	char peers_conf_file[100];
	sprintf(peers_conf_file, "/etc/site/vppn%d_peers.conf", tunnel_id);
	cJSON *tunnel_status_item = cJSON_GetObjectItem(status, "tunnel_status");
	cJSON *peers_item = cJSON_GetObjectItem(tunnel_status_item, "peers");
	cJSON *cur_peers = read_json_from_file(peers_conf_file);
	if (!cur_peers)
	{
		cur_peers = cJSON_CreateArray();
	}
	sync_peers(cur_peers, peers_item);
	cJSON_ReplaceItemInObject(tunnel_status_item, "peers", cur_peers);
}

void json_handle_get_vpnstatus(cJSON *jsonreq, ctrl_request_t *request)
{
	cJSON *res = NULL;
	res = json_get_vpn_status();
	cJSON *peers = NULL;
	struct vpn_config_s *dump_config = ctrl_get_tunnel_config();
	pthread_mutex_lock(&vpn_peers_lock);
	if (global_vpn_peers)
	{
		peers = cJSON_Duplicate(global_vpn_peers, 1);
	}
	pthread_mutex_unlock(&vpn_peers_lock);
	cJSON *status_item = cJSON_GetObjectItem(res, "tunnel_status");
	if (status_item && peers)
	{
		cJSON_AddItemToObject(status_item, "peers", cJSON_Duplicate(peers, 1));
		fix_vpnstatus_peers(res, dump_config->tunnel.tunnel_id);
	}
	if (peers)
	{
		cJSON_Delete(peers);
	}
	json_response(res, request);
	cJSON_Delete(res);
	FREE_PTR(dump_config);
	return;
}

static void skip_crlf(char *str)
{
	int len = strlen(str);
	int i;
	for(i = 0; i < len; i++)
	{
		if (str[i] == '\n' || str[i] == '\r')
		{
			str[i] = 0;
			break;
		}
	}
	return;
}

void get_sn(char *out)
{
	char *text = process_tool_run_cmd((char*)"artmtd -r sn");
	if (text)
	{
		skip_crlf(text);
		strcpy(out, text + 3);
		free(text);
	}
	return;
}

void get_module_name(char *out)
{
	char *text = read_text((char*)"/module_name");
	if (text)
	{
		skip_crlf(text);
		strcpy(out, text);
		free(text);
	}
	return;
}

void get_firmware_version(char *out)
{
	char *text = read_text((char*)"/firmware_version");
	if (text)
	{
		skip_crlf(text);
		strcpy(out, text);
		free(text);
	}
	return;
}

void get_http_password(char *out, int max_len)
{
	char *cmd_out = process_tool_run_cmd((char*)"config get http_passwd");
	if (cmd_out)
	{
		skip_crlf(cmd_out);
		if ((int)strlen(cmd_out) <= max_len / 2)
		{
			str_tool_base64_encode((const unsigned char*)cmd_out, strlen(cmd_out), out);
		}
		free(cmd_out);
	}
}

struct geoip_struct
{
	char public_ip[32];
	char latitude[32];
	char longtitude[32];
};
struct geoip_struct g_geoip;

void get_geoip(char *publicip_buf, char *latitude_buf, char *longtitude_buf)
{
	char *ptr = NULL;
	char *token = NULL;
	char *buf = NULL;

	static int got = 0;

	//int	ret = -1;

	int len;
	int geo_len = 0;
	if (got == 0)
	{
		char *geo_res = net_tool_http_client2(0, (char*)"geoip.bigit.com", 80, (char*)"/geoip.php", NULL, 0, NULL, &geo_len);
		if (geo_res)
		{
			MY_DEBUG_INFO("get response %s\n", geo_res);
			if (geo_len > 0)
			{
				/* skip the http response header */
				buf = strstr(geo_res, "\r\n\r\n");
				if (!buf)
				{
					buf = strstr(geo_res, "\n\n");
				}
				if (buf)
				{
					got = 1;
					if ((ptr = strstr(buf, "ipaddr:")))
					{
						ptr += strlen("ipaddr:");
						token = strchr(ptr, '<');
						len = token - ptr;
						if (len)
						{
							strncpy(g_geoip.public_ip, ptr, 32);
							//strncpy(publicip_buf, ptr, 32);
						}
					}
					if ((ptr = strstr(buf, "latitude:")))
					{
						ptr += strlen("latitude:");
						token = strchr(ptr, '<');
						len = token - ptr;
						if (len)
						{
							strncpy(g_geoip.latitude, ptr, 32);
							//strncpy(latitude_buf, ptr, 32);
						}
					}
					if ((ptr = strstr(buf, "longtitude:")))
					{
						ptr += strlen("longtitude:");
						token = strchr(ptr, '<');
						len = token - ptr;
						if (len)
						{
							strncpy(g_geoip.longtitude, ptr, 32);
							//strncpy(longtitude_buf, ptr, 32);
						}
					}
				}
			}
			free(geo_res);
		}
	}
	strncpy(publicip_buf, g_geoip.public_ip, 32);
	strncpy(latitude_buf, g_geoip.latitude, 32);
	strncpy(longtitude_buf, g_geoip.longtitude, 32);
	return;
}

void json_handle_get_deviceinfo(cJSON *jsonreq, ctrl_request_t *request)
{
	char wan_ip_buf[32] = "";
	char wan_mac_buf[32] = "";
	char lan_ip_buf[32] = "";
	char lan_mac_buf[32] = "";
	char sn_buf[32] = "";
	char module_name_buf[32] = "";
	char firmware_version_buf[32] = "";
	char http_password[200] = "";
	char latitude_buf[40] = "";
	char longtitude_buf[40] = "";
	char publicip_buf[40] = "";

	struct vpn_config_s *dump_config = ctrl_get_tunnel_config();
	net_tool_get_if_ip(dump_config->custom_wan_if, wan_ip_buf);
	net_tool_get_if_hwaddr(dump_config->custom_wan_if, wan_mac_buf);
	net_tool_get_if_ip(dump_config->custom_lan_if, lan_ip_buf);
	net_tool_get_if_hwaddr(dump_config->custom_lan_if, lan_mac_buf);
	get_sn(sn_buf);
	get_module_name(module_name_buf);
	get_firmware_version(firmware_version_buf);
	get_http_password(http_password, sizeof(http_password));
	get_geoip(publicip_buf, latitude_buf, longtitude_buf);

	cJSON *res = cJSON_CreateObject();
	cJSON_AddStringToObject(res, "wan_ip", wan_ip_buf);
	cJSON_AddStringToObject(res, "wan_mac", wan_mac_buf);
	cJSON_AddStringToObject(res, "lan_ip", lan_ip_buf);
	cJSON_AddStringToObject(res, "lan_mac", lan_mac_buf);
	cJSON_AddStringToObject(res, "sn", sn_buf);
	cJSON_AddStringToObject(res, "module_name", module_name_buf);
	cJSON_AddStringToObject(res, "firmware_version", firmware_version_buf);
	cJSON_AddStringToObject(res, "http_password", http_password);
	cJSON_AddStringToObject(res, "public_ip", publicip_buf);
	cJSON_AddStringToObject(res, "latitude", latitude_buf);
	cJSON_AddStringToObject(res, "longtitude", longtitude_buf);
	json_response(res, request);
	cJSON_Delete(res);
	FREE_PTR(dump_config);
}

#if 0
void json_handle_get_attachdevice(cJSON *jsonreq, ctrl_request_t *request)
{
	char *info = fetch_attach_device();
	cJSON *res = cJSON_CreateObject();
	int err_code = 1;
	if (info)
	{
		err_code = 0;
		cJSON_AddStringToObject(res, "attachdevice", info);
		free(info);
	}
	cJSON_AddNumberToObject(res, "err_code", err_code);
	json_response(res, request);
	cJSON_Delete(res);
	return;
}
#endif

void json_handle_get_package(cJSON *jsonreq, ctrl_request_t *request)
{
	int err_code = 0;
	struct vpn_config_s *dump_config = ctrl_get_tunnel_config();
	cJSON *res = json_get_package(&dump_config->tunnel);
	cJSON_AddNumberToObject(res, "select_code", dump_config->tunnel.last_select_code);
	cJSON_AddNumberToObject(res, "heartbeat_code", dump_config->tunnel.last_heartbeat_code);
	cJSON_AddNumberToObject(res, "err_code", err_code);
	json_response(res, request);
	cJSON_Delete(res);
	FREE_PTR(dump_config);
}

void json_handle_get_vport_on(cJSON *jsonreq, ctrl_request_t *request)
{
	//int err_code = 0;
	struct vpn_config_s *dump_config = ctrl_get_tunnel_config();
	int on = dump_config->tunnel.tunnel_on;
	cJSON *res = cJSON_CreateObject();
	cJSON_AddNumberToObject(res, "on", on);
	json_response(res, request);
	cJSON_Delete(res);
	FREE_PTR(dump_config);
}

void json_handle_dump_members(cJSON* jsonreq, ctrl_request_t* request)
{
	cJSON *res = cJSON_CreateObject();
	struct vpn_config_s *dump_config = ctrl_get_tunnel_config();

	int tunnel_on = dump_config->tunnel.tunnel_on;
	int tunnel_id = dump_config->tunnel.tunnel_id;
	int status = dump_config->tunnel.info.status;
	char tinc_pidfile[100] = "";
	char tinc_base[100] = "";
	sprintf(tinc_base, "/etc/tinc/site%d", tunnel_id);
	sprintf(tinc_pidfile, "/var/run/site%d.pid", tunnel_id);
	cJSON* nodes = NULL;
	if (tunnel_on && status == TUNNEL_DONE)
	{
#if 0
		char traffic_file[100];
		sprintf(traffic_file, "/tmp/traffic_site%d.info", tunnel_id);
		res = read_json_from_file(traffic_file);
#else
		nodes = tinctool_dump_traffic(tinc_base, tinc_pidfile);
#endif
	}
	if (!nodes)
	{
		nodes = cJSON_CreateArray();
	}

	cJSON* members = get_members(dump_config->cloud_host,
				dump_config->cloud_port,
				dump_config->self_id,
				dump_config->team_id, -1
			);

	update_members_traffic(members, nodes);
	cJSON_AddNumberToObject(res, "err_code", 0);
	cJSON_AddItemToObject(res, "members", members);
	json_response(res, request);
	cJSON_Delete(res);
	cJSON_Delete(nodes);
	FREE_PTR(dump_config);
}

void json_handle_get_traffic(cJSON *jsonreq, ctrl_request_t *request)
{
	cJSON *res = NULL;
	struct vpn_config_s *dump_config = ctrl_get_tunnel_config();
	int tunnel_on = dump_config->tunnel.tunnel_on;
	int tunnel_id = dump_config->tunnel.tunnel_id;
	int status = dump_config->tunnel.info.status;
	char tinc_pidfile[100] = "";
	char tinc_base[100] = "";
	sprintf(tinc_base, "/etc/tinc/site%d", tunnel_id);
	sprintf(tinc_pidfile, "/var/run/site%d.pid", tunnel_id);
	if (tunnel_on && status == TUNNEL_DONE)
	{
#if 0
		char traffic_file[100];
		sprintf(traffic_file, "/tmp/traffic_site%d.info", tunnel_id);
		res = read_json_from_file(traffic_file);
#else
		res = tinctool_dump_traffic(tinc_base, tinc_pidfile);
#endif
	}
	if (!res)
	{
		res = cJSON_CreateArray();
	}
	json_response(res, request);
	cJSON_Delete(res);
	FREE_PTR(dump_config);
}

void set_syslog_conf(char *log_host, char *log_port, char *log_level, char *vendor_name)
{
	char buf[1000] = "";
	if (log_host && log_port && log_level)
	{
		snprintf(buf, sizeof(buf), "log_host=%s\nlog_port=%s\nlog_level=%s\nvendor=%s", log_host, log_port, log_level, vendor_name);
	}
	write_text((char*)"/tmp/syslog_vppn.conf", buf);
	return;
}

void restart_syslog(char *log_host, char *log_port, char *log_level, char *vendor_name)
{
	set_syslog_conf(log_host, log_port, log_level, vendor_name);
	process_tool_system("/etc/init.d/syslogd.init restart");
	return;
}

void json_handle_set_syslog_on(cJSON *jsonreq, ctrl_request_t *request)
{
	cJSON *res = NULL;
	struct vpn_config_s *dump_config = ctrl_get_tunnel_config();
	//int tunnel_id = dump_config->tunnel.tunnel_id;
	cJSON *level_item = cJSON_GetObjectItem(jsonreq, "log_level");
	cJSON *syslog_host_item = cJSON_GetObjectItem(jsonreq, "sys_log_host");
	cJSON *syslog_port_item = cJSON_GetObjectItem(jsonreq, "sys_log_port");
	cJSON *syslog_level_item = cJSON_GetObjectItem(jsonreq, "sys_log_level");
	char syslog_host_buf[200] = "";
	char syslog_port_buf[200] = "";
	char syslog_level_buf[200] = "";
	char vendor_name[200] = "";
	net_tool_get_if_hwaddr(dump_config->custom_lan_if, vendor_name);
	snprintf(syslog_host_buf, sizeof(syslog_host_buf), "%s", syslog_host_item->valuestring);
	snprintf(syslog_port_buf, sizeof(syslog_port_buf), "%d", syslog_port_item->valueint);
	snprintf(syslog_level_buf, sizeof(syslog_level_buf), "%d", syslog_level_item->valueint);
	set_syslog_conf(syslog_host_buf, syslog_port_buf, syslog_level_buf, vendor_name);
	process_tool_system("/etc/init.d/syslogd.init restart");
	//dump_config->tunnel.log_on = 1;
	//dump_config->tunnel.log_level = level_item->valueint;
	ctrl_enable_log(dump_config->tunnel.tunnel_id, level_item->valueint);
	ctrl_refresh_vpn();
	res = cJSON_CreateObject();
	cJSON_AddNumberToObject(res, "err_code", 0);
	json_response(res, request);
	cJSON_Delete(res);
	FREE_PTR(dump_config);
	return;
}

void json_handle_set_syslog_off(cJSON *jsonreq, ctrl_request_t *request)
{
	cJSON *res = NULL;
	struct vpn_config_s *dump_config = ctrl_get_tunnel_config();
	set_syslog_conf(NULL, NULL, NULL, NULL);
	process_tool_system("/etc/init.d/syslogd.init restart");
	dump_config->tunnel.log_on = 0;
	ctrl_disable_log(dump_config->tunnel.tunnel_id);
	ctrl_refresh_vpn();
	res = cJSON_CreateObject();
	cJSON_AddNumberToObject(res, "err_code", 0);
	json_response(res, request);
	cJSON_Delete(res);
	FREE_PTR(dump_config);
	return;
}


void json_handle_default(cJSON *jsonreq, ctrl_request_t *request)
{
	cJSON *res = cJSON_CreateObject();
	json_response(res, request);
	cJSON_Delete(res);
}

void handle_vpn_jsonreq(cJSON *jsonreq, ctrl_request_t *request)
{
	cJSON *act_item = cJSON_GetObjectItem(jsonreq, "action");
	int action = act_item->valueint;
	MY_DEBUG_INFO("action = %d\n", action);
	cJSON_Dump(jsonreq);
	switch (action)
	{
		case ACT_AskNeighbor:
			json_handle_ask_neighbor(jsonreq, request);
			break;
		case ACT_GetVpnStatus:
			json_handle_get_vpnstatus(jsonreq, request);
			break;
		case ACT_StartVpn:
			json_handle_start_vpn(jsonreq, request);
			break;
		case ACT_StopVpn:
			json_handle_stop_vpn(jsonreq, request);
			break;
		case ACT_AddVpathList:
			json_handle_add_vpath_list(jsonreq, request);
			break;
		case ACT_DelVpathList:
			json_handle_del_vpath_list(jsonreq, request);
			break;
		case ACT_AddVpath:
			json_handle_add_vpath(jsonreq, request);
			break;
		case ACT_DelVpath:
			json_handle_del_vpath(jsonreq, request);
			break;
		case ACT_AddPeer:
			json_handle_add_peer(jsonreq, request);
			break;
		case ACT_DelPeer:
			json_handle_del_peer(jsonreq, request);
			break;
		case ACT_GetRoute:
			json_handle_get_route(jsonreq, request);
			break;
		case ACT_AddManager:
			json_handle_add_manager(jsonreq, request);
			break;
		case ACT_DelManager:
			json_handle_del_manager(jsonreq, request);
			break;
		case ACT_AddPublicVpathList:
			json_handle_add_public_vpath(jsonreq, request);
			break;
		case ACT_DelPublicVpathList:
			json_handle_del_public_vpath(jsonreq, request);
			break;
		case ACT_GetServerList:
			json_handle_get_serverlist(jsonreq, request);
			break;
		case ACT_GetDeviceInfo:
			json_handle_get_deviceinfo(jsonreq, request);
			break;
#if 0
		case ACT_GetAttachDevice:
			json_handle_get_attachdevice(jsonreq, request);
			break;
#endif
		case ACT_GetPackage:
			json_handle_get_package(jsonreq, request);
			break;
		case ACT_GetVportOn:
			json_handle_get_vport_on(jsonreq, request);
			break;
		/* will be dropped by ACT_DumpMembers */
		case ACT_GetTraffic:
			json_handle_get_traffic(jsonreq, request);
			break;
		case ACT_TurnOnVpnLog:
			json_handle_set_syslog_on(jsonreq, request);
			break;
		case ACT_TurnOffVpnLog:
			json_handle_set_syslog_off(jsonreq, request);
			break;
		case ACT_GetVpathList:
			json_handle_get_vpath_list(jsonreq, request);
			break;
		case ACT_ReloadMember:
			json_handle_reload_member(jsonreq, request);
			break;
		/* will be dropped by ACT_DumpMembers */
		case ACT_DumpNodes:
			json_handle_dump_nodes(jsonreq, request);
			break;
		case ACT_DumpMembers:
			json_handle_dump_members(jsonreq, request);
			break;
		case ACT_PingMembers:
			json_handle_ping_members(jsonreq, request);
			break;
		case ACT_SetDebugLevel:
			json_handle_set_debuglevel(jsonreq, request);
			break;
		case ACT_GetConnectInfo:
			json_handle_get_connectInfo(jsonreq, request);
			break;
		default:
			json_handle_default(jsonreq, request);
			break;
	}
	return;
}

void delete_vpn_jsonreq(cJSON *jsonreq)
{
	if (jsonreq)
	{
		cJSON_Delete(jsonreq);
	}
}

cJSON *new_vpn_jsonreq(ctrl_request_t *request)
{
	/* skip the first 4 char to parse json */
	cJSON *ret = cJSON_Parse((char*)request->data + strlen("json"));
	return ret;
}
