#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "nvram-common.h"
#include "nvram-op.h"
#include "cJSON.h"
#include "file_tool.h"
#include "net_tool.h"

#ifndef FREE_PTR
#define FREE_PTR(ptr) do{if (ptr) {free((ptr)); (ptr)=NULL;}}while(0);
#endif

enum VPN_Type
{
	TYPE_VPN,
	TYPE_VPPN
};

void dump_JSON(cJSON *root)
{
	if (root)
	{
		char *ptr = cJSON_Print(root);
		if (ptr)
		{
			printf("%s\n", ptr);
			free(ptr);
		}
	}
	return;
}

void get_file_by_id(char *fmt, int id, char *ret_buf)
{
	sprintf(ret_buf, fmt, id);
	return;
}

static char *my_strcat(char *str1, char *str2)
{
	char *ret = NULL;
	int ret_len;
	int str1_len = (str1?strlen(str1):0);

	ret_len = str1_len + strlen(str2) + strlen(":") + 1;
	ret = realloc(str1, ret_len);
	if (!str1_len)
	{
		ret[0] = 0;
	}
	else
	{
		strcat(ret, ":");
	}
	strcat(ret, str2);
	return ret;
}


void run_in_nodebug()
{
	int fd = open("/dev/null", O_RDWR);
	if (fd > 0)
	{
		dup2(2, fd);
		dup2(1, fd);
	}
}

void load_tunnel_conf(int conf_type, int id)
{
	char conf_tunnel_on[100];
	//char conf_tunnel_server[100];
	//char conf_tunnel_server_port[100];
	//char conf_tunnel_self[100];
	char conf_tunnel_teamid[100];
	char conf_tunnel_file[100];
	if (conf_type == TYPE_VPN)
	{
		sprintf(conf_tunnel_on, "vpn%d_enable", id);
		//sprintf(conf_tunnel_server, "vpn%d_server", id);
		//sprintf(conf_tunnel_server_port, "vpn%d_server_port", id);
		//sprintf(conf_tunnel_self, "vpn%d_self", id);
		sprintf(conf_tunnel_teamid, "vpn%d_teamid", id);
		sprintf(conf_tunnel_file, "/etc/vpn/vpn%d.conf", id);
	}
	else
	{
		sprintf(conf_tunnel_on, "site%d_on", id);
		//sprintf(conf_tunnel_server, "site%d_server", id);
		//sprintf(conf_tunnel_server_port, "site%d_server_port", id);
		//sprintf(conf_tunnel_self, "site%d_self", id);
		sprintf(conf_tunnel_teamid, "site%d_teamid", id);
		sprintf(conf_tunnel_file, "/etc/site/site%d.conf", id);
	}
	char *tunnel_on = GetConfig(conf_tunnel_on);
	//char *tunnel_server = GetConfig(conf_tunnel_server);
	//char *tunnel_server_port = GetConfig(conf_tunnel_server_port);
	//char *tunnel_self = GetConfig(conf_tunnel_self);
	char *tunnel_teamid = GetConfig(conf_tunnel_teamid);
	cJSON *obj = read_json_from_file(conf_tunnel_file);
	if (obj)
	{
		if (tunnel_on && tunnel_on[0])
		{
			cJSON_ReplaceItemInObject(obj, "on", cJSON_CreateNumber(atoi(tunnel_on)));
		}
		if (tunnel_teamid && tunnel_teamid[0])
		{
			cJSON_ReplaceItemInObject(obj, "team_id", cJSON_CreateString(tunnel_teamid));
		}
#if 0
		if (tunnel_server && tunnel_server[0])
		{
			cJSON_ReplaceItemInObject(obj, "server_addr", cJSON_CreateString(tunnel_server));
		}
		if (tunnel_server_port && tunnel_server_port[0])
		{
			cJSON_ReplaceItemInObject(obj, "server_port", cJSON_CreateNumber(atoi(tunnel_server_port)));
		}
		if (tunnel_self && tunnel_self[0])
		{
			cJSON_ReplaceItemInObject(obj, "myself_addr", cJSON_CreateString(tunnel_self));
		}
#endif
	}
	else
	{
		obj = cJSON_CreateObject();
		if (tunnel_on && tunnel_on[0])
		{
			cJSON_AddNumberToObject(obj, "on", atoi(tunnel_on));
		}
		else
		{
			cJSON_AddNumberToObject(obj, "on", 0);
		}
		if (tunnel_teamid && tunnel_teamid[0])
		{
			cJSON_AddStringToObject(obj, "team_id", tunnel_teamid);
		}
		else
		{
			cJSON_AddStringToObject(obj, "team_id", "");
		}

#if 0
		if (tunnel_server && tunnel_server[0])
		{
			cJSON_AddStringToObject(obj, "server_addr", tunnel_server);
		}
		else
		{
			cJSON_AddStringToObject(obj, "server_addr", "");
		}

		if (tunnel_server_port && tunnel_server_port[0])
		{
			cJSON_AddNumberToObject(obj, "server_port", atoi(tunnel_server_port));
		}
		else
		{
			cJSON_AddNumberToObject(obj, "server_port", 0);
		}
		if (tunnel_self && tunnel_self[0])
		{
			cJSON_AddStringToObject(obj, "myself_addr", tunnel_self);
		}
		else
		{
			cJSON_AddStringToObject(obj, "server_addr", "");
		}
#endif
	}

	write_json_to_file(conf_tunnel_file, obj);
	cJSON_Delete(obj);
	FREE_PTR(tunnel_on);
#if 0
	FREE_PTR(tunnel_server);
	FREE_PTR(tunnel_server_port);
	FREE_PTR(tunnel_self);
	FREE_PTR(tunnel_teamid);
	FREE_PTR(tunnel_server);
#endif
	return;
}

void save_tunnel_conf(int conf_type, int id)
{
	char conf_tunnel_on[100];
	char conf_tunnel_teamid[100];
	char conf_tunnel_file[100];
#if 0
	char conf_tunnel_server[100];
	char conf_tunnel_server_port[100];
	char conf_tunnel_self[100];
#endif
	if (conf_type == TYPE_VPN)
	{
		sprintf(conf_tunnel_on, "vpn%d_enable", id);
		sprintf(conf_tunnel_teamid, "vpn%d_teamid", id);
#if 0
		sprintf(conf_tunnel_server, "vpn%d_server", id);
		sprintf(conf_tunnel_server_port, "vpn%d_server_port", id);
		sprintf(conf_tunnel_self, "vpn%d_self", id);
#endif
		sprintf(conf_tunnel_file, "/etc/vpn/vpn%d.conf", id);
	}
	else
	{
		sprintf(conf_tunnel_on, "site%d_on", id);
		sprintf(conf_tunnel_teamid, "site%d_teamid", id);
#if 0
		sprintf(conf_tunnel_server, "site%d_server", id);
		sprintf(conf_tunnel_server_port, "site%d_server_port", id);
		sprintf(conf_tunnel_self, "site%d_self", id);
#endif
		sprintf(conf_tunnel_file, "/etc/site/site%d.conf", id);
	}
	//char *tunnel_on = GetConfig(conf_tunnel_on);
	//char *tunnel_server = GetConfig(conf_tunnel_server);
	char tunnel_on[100] = "0";
	char tunnel_teamid[100]="";
#if 0
	char tunnel_server[100]="";
	char tunnel_server_port[100]="";
	char tunnel_self[100]="";
#endif
	cJSON *obj = read_json_from_file(conf_tunnel_file);
	if (obj)
	{
		cJSON *on_item = cJSON_GetObjectItem(obj, "on");
		cJSON *teamid_item = cJSON_GetObjectItem(obj, "team_id");
#if 0
		cJSON *server_item = cJSON_GetObjectItem(obj, "server_addr");
		cJSON *server_port_item = cJSON_GetObjectItem(obj, "server_port");
		cJSON *self_item = cJSON_GetObjectItem(obj, "myself_addr");
#endif
		if (on_item)
		{
			sprintf(tunnel_on, "%d", on_item->valueint);
		}
		if (teamid_item)
		{
			sprintf(tunnel_teamid, "%s", teamid_item->valuestring);
		}
#if 0
		if (server_item)
		{
			sprintf(tunnel_server, "%s", server_item->valuestring);
		}

		if (server_port_item)
		{
			sprintf(tunnel_server_port, "%d", server_port_item->valueint);
		}

		if (self_item)
		{
			sprintf(tunnel_self, "%s", self_item->valuestring);
		}
#endif
		cJSON_Delete(obj);
	}

	SetConfig(conf_tunnel_on, tunnel_on);
	SetConfig(conf_tunnel_teamid, tunnel_teamid);
#if 0
	SetConfig(conf_tunnel_server, tunnel_server);
	SetConfig(conf_tunnel_server_port, tunnel_server_port);
	SetConfig(conf_tunnel_self, tunnel_self);
#endif
	return;
}

void load_manager(int conf_type)
{
	char conf_manager_host[100];
	char conf_manager_port[100];
	char conf_manager_file[100];
	if (conf_type == TYPE_VPN)
	{
		sprintf(conf_manager_host, "vpn_manager_host");
		sprintf(conf_manager_port, "vpn_manager_port");
		sprintf(conf_manager_file, "/etc/vpn/manager");
	}
	else
	{
		sprintf(conf_manager_host, "vppn_manager_host");
		sprintf(conf_manager_port, "vppn_manager_port");
		sprintf(conf_manager_file, "/etc/site/manager");
	}

	char *host = GetConfig(conf_manager_host);
	char *port = GetConfig(conf_manager_port);
	cJSON *obj = read_json_from_file(conf_manager_file);
	if (obj)
	{
		if (host && host[0])
		{
			cJSON_ReplaceItemInObject(obj, CLOUD_HOST, cJSON_CreateString(host));
		}
		if (port && port[0])
		{
			int port_num = atoi(port);
			cJSON_ReplaceItemInObject(obj, CLOUD_PORT, cJSON_CreateNumber(port_num));
		}
		write_json_to_file(FILE_SITE_MANAGER, obj);
		cJSON_Delete(obj);
	}
	else
	{

	}

	FREE_PTR(host);
	FREE_PTR(port);
	return;
}

void save_manager(int conf_type)
{
	char conf_manager_host[100];
	char conf_manager_port[100];
	char conf_manager_file[100];
	if (conf_type == TYPE_VPN)
	{
		sprintf(conf_manager_host, "vpn_manager_host");
		sprintf(conf_manager_port, "vpn_manager_port");
		sprintf(conf_manager_file, "/etc/vpn/manager");
	}
	else
	{
		sprintf(conf_manager_host, "vppn_manager_host");
		sprintf(conf_manager_port, "vppn_manager_port");
		sprintf(conf_manager_file, "/etc/site/manager");
	}

	cJSON *obj = read_json_from_file(conf_manager_file);
	if (obj)
	{
		cJSON *host_item = cJSON_GetObjectItem(obj, CLOUD_HOST);
		if (host_item)
		{
			SetConfig(conf_manager_host, host_item->valuestring);
		}
		cJSON *port_item = cJSON_GetObjectItem(obj, CLOUD_PORT);
		if (port_item)
		{
			char buf[100];
			sprintf(buf, "%d", port_item->valueint);
			SetConfig(conf_manager_port, buf);
		}
		cJSON_Delete(obj);
	}
	return;
}

cJSON *parse_tunnel_peers(char *ptr)
{
	char *save_ptr1 = NULL;
	char *str1;
	char *token;

	cJSON *ret = cJSON_CreateArray();
	if (ptr && ptr[0])
	{
		for(str1 = ptr; ; str1 = NULL)
		{
			token = strtok_r(str1, ":", &save_ptr1);
			if (token == NULL)
			{
				break;
			}
			char *separator = strchr(token, '@');
			*separator = 0;
			char *peer_vip = token;
			char *peer_server = ++separator;
			cJSON *obj = cJSON_CreateObject();
			cJSON_AddStringToObject(obj, "peer_vip", peer_vip);
			cJSON_AddStringToObject(obj, "peer_server", peer_server);
			cJSON_AddItemToArray(ret, obj);
		}
	}
	return ret;
}

void set_peer_cnt(int id, int cnt)
{
	char conf_peer[100];
	char conf_peer_buf[100];
	sprintf(conf_peer, "vppn_peer%d_cnt", id);
	sprintf(conf_peer_buf, "%d", cnt);
	SetConfig(conf_peer, conf_peer_buf);
	return;
}

int get_peer_cnt(int id)
{
	int ret = 0;
	char conf_peer[100];
	sprintf(conf_peer, "vppn_peer%d_cnt", id);
	char *conf_ptr = GetConfig(conf_peer);
	if (conf_ptr)
	{
		ret = atoi(conf_ptr);
		free(conf_ptr);
	}
	return ret;
}

cJSON *get_peer_conf(int tunnel_id, int index)
{
	char *ptr = NULL;
	cJSON *obj = NULL;
	char conf_peer[100];
	sprintf(conf_peer, "vppn_peer%d_item%d", tunnel_id, index);
	ptr = GetConfig(conf_peer);
	if (ptr)
	{
		char* sep = strchr(ptr, '@');
		*sep = 0;
		char* team_id = sep+1;
		char *peer_vip = ptr;
		obj = cJSON_CreateObject();
		cJSON_AddStringToObject(obj, "peer_vip", peer_vip);
		cJSON_AddStringToObject(obj, "peer_teamid", team_id);
		free(ptr);
	}
	return obj;
}

void set_peer_conf(int tunnel_id, int index, cJSON *peer)
{
	char conf_peer[100];
	sprintf(conf_peer, "vppn_peer%d_item%d", tunnel_id, index);
	char *str = NULL;
	cJSON *vip_item = cJSON_GetObjectItem(peer, "peer_vip");
	//cJSON *server_item = cJSON_GetObjectItem(peer, "peer_server");
	str = malloc(strlen(vip_item->valuestring) + 1);
	if (str)
	{
		str[0] = 0;
		strcpy(str, vip_item->valuestring);
		if (strlen(str) <= 100)
		{
			SetConfig(conf_peer, str);
		}
		else
		{
			UnsetConfig(conf_peer);
		}
		free(str);
	}
	return;
}

void load_peer_conf2(int conf_type, int id)
{
	int	peer_cnt = get_peer_cnt(id);
	int i;
	char conf_peer_file[100];
	sprintf(conf_peer_file, "/etc/site/vppn%d_peers.conf", id);
	cJSON *array = cJSON_CreateArray();
	for(i = 0; i < peer_cnt; i++)
	{
		cJSON *obj = get_peer_conf(id, i);
		if (obj)
		{
			cJSON_AddItemToArray(array, obj);
		}
	}
	write_json_to_file(conf_peer_file, array);
	cJSON_Delete(array);
	return;
}

void load_peer_conf(int conf_type, int id)
{
	char conf_peer[100];
	char conf_peer_file[100];

	char *conf_ptr = NULL;
	if (conf_type == TYPE_VPPN)
	{
		sprintf(conf_peer, "vppn%d_peers", id);
		sprintf(conf_peer_file, "/etc/site/vppn%d_peers.conf", id);
		conf_ptr = GetConfig(conf_peer);
		cJSON *peers = parse_tunnel_peers(conf_ptr);
		if (peers)
		{
			write_json_to_file(conf_peer_file, peers);
			cJSON_Delete(peers);
		}
	}
	else
	{
		return;
	}
	FREE_PTR(conf_ptr);
	return;
}

void load_peer_confs(int conf_type)
{
	int i;
	for(i = 0; i < 5; i++)
	{
		load_peer_conf2(conf_type, i);
	}
	return;
}

void save_peer_conf(int conf_type, int id)
{
	char conf_peer[100];
	char conf_peer_file[100];
	if (conf_type == TYPE_VPPN)
	{
		sprintf(conf_peer, "vppn%d_peers", id);
		sprintf(conf_peer_file, "/etc/site/vppn%d_peers.conf", id);
		cJSON *peers =read_json_from_file(conf_peer_file);
		if (peers)
		{
			int i;
			int peer_cnt = cJSON_GetArraySize(peers);
			char *save_conf = NULL;
			for (i = 0; i < peer_cnt; i++)
			{
				cJSON *peer = cJSON_GetArrayItem(peers, i);
				cJSON *peer_vip_item = cJSON_GetObjectItem(peer, "peer_vip");
				cJSON *peer_server_item = cJSON_GetObjectItem(peer, "peer_teamid");
				char *peer_conf = malloc(strlen(peer_vip_item->valuestring) + strlen(peer_server_item->valuestring) + strlen("@") + 1);
				strcpy(peer_conf, peer_vip_item->valuestring);
				strcat(peer_conf, "@");
				strcat(peer_conf, peer_server_item->valuestring);
				save_conf = my_strcat(save_conf, peer_conf);
				free(peer_conf);
			}
			if (save_conf)
			{
				SetConfig(conf_peer, save_conf);
				free(save_conf);
			}
			cJSON_Delete(peers);
		}
	}
	else
	{
		return;
	}
	return;
}

void save_peer_conf2(int conf_type, int id)
{
	char conf_peer[100];
	char conf_peer_file[100];
	if (conf_type == TYPE_VPPN)
	{
		sprintf(conf_peer, "vppn%d_peers", id);
		sprintf(conf_peer_file, "/etc/site/vppn%d_peers.conf", id);
		cJSON *peers =read_json_from_file(conf_peer_file);
		if (peers)
		{
			int i;
			int peer_cnt = cJSON_GetArraySize(peers);
			set_peer_cnt(id, peer_cnt);
			for (i = 0; i < peer_cnt; i++)
			{
				cJSON *peer = cJSON_GetArrayItem(peers, i);
				set_peer_conf(id, i, peer);
			}
			cJSON_Delete(peers);
		}
		else
		{
			set_peer_cnt(id, 0);
		}
	}
	else
	{
		return;
	}
	return;
}

void save_peer_confs(int conf_type)
{
	int i;
	for(i = 0; i < 5; i++)
	{
		save_peer_conf2(conf_type, i);
	}
	return;
}

cJSON *parse_tunnel_vpath(char *ptr, int conf_type)
{
	char *save_ptr1 = NULL;
	char *str1;
	char *token;

	cJSON *ret = cJSON_CreateArray();
	if (ptr)
	{
		for(str1 = ptr; ; str1 = NULL)
		{
			token = strtok_r(str1, ":", &save_ptr1);
			if (token == NULL)
			{
				break;
			}
			char *uri = NULL;
			char *proxy = NULL;
			char *server = NULL;

			uri = token;
			if (conf_type == TYPE_VPPN)
			{
				char *separator = strchr(uri, '@');
				*separator = 0;
				proxy = ++separator;
				separator = strchr(proxy, '@');
				*separator = 0;
				server = ++separator;
			}
			else
			{
			}
			cJSON *obj = cJSON_CreateObject();
			cJSON_AddStringToObject(obj, "uri", uri);
			if (conf_type == TYPE_VPPN)
			{
				cJSON_AddStringToObject(obj, "vproxy", proxy);
				cJSON_AddStringToObject(obj, "server", server);
			}
			cJSON_AddItemToArray(ret, obj);
		}
	}
	return ret;
}

cJSON *parse_tunnel_old_vpath(char *ptr, int conf_type)
{
	char *save_ptr1 = NULL;
	char *str1;
	char *token;

	cJSON *ret = cJSON_CreateArray();
	if (ptr)
	{
		for(str1 = ptr; ; str1 = NULL)
		{
			token = strtok_r(str1, ":", &save_ptr1);
			if (token == NULL)
			{
				break;
			}
			char *uri = NULL;
			char *proxy = NULL;

			uri = token;
			if (conf_type == TYPE_VPPN)
			{
				char *separator = strchr(uri, '@');
				*separator = 0;
				proxy = ++separator;
			}
			else
			{
			}
			cJSON *obj = cJSON_CreateObject();
			cJSON_AddStringToObject(obj, "uri", uri);
			if (conf_type == TYPE_VPPN)
			{
				cJSON_AddStringToObject(obj, "vproxy", proxy);
			}
			cJSON_AddItemToArray(ret, obj);
		}
	}
	return ret;
}

void load_vpath_conf(int conf_type, int id)
{
	char conf_vpath[100];
	char conf_vpath_file[100];
	char *vpath;
	if (conf_type == TYPE_VPPN)
	{
		sprintf(conf_vpath, "vppn%d_vpath", id);
		sprintf(conf_vpath_file, "/etc/site/vppn%d_vpath.conf", id);

	}
	else
	{
		sprintf(conf_vpath, "vpn%d_vpath", id);
		sprintf(conf_vpath_file, "/etc/vpn/vpn%d_vpath.conf", id);
	}

	vpath = GetConfig(conf_vpath);
	if (vpath && vpath[0])
	{
		cJSON *tunnel_vpath = parse_tunnel_vpath(vpath, conf_type);
		if (tunnel_vpath)
		{
			write_json_to_file(conf_vpath_file, tunnel_vpath);
			cJSON_Delete(tunnel_vpath);
		}
	}
	FREE_PTR(vpath);
	return;
}

int get_vpath_cnt(int tunnel_id)
{
	int ret = 0;
	char conf_vpath[100];
	sprintf(conf_vpath, "vppn%d_vpath_cnt", tunnel_id);
	char *ptr = GetConfig(conf_vpath);
	if (ptr)
	{
		ret = atoi(ptr);
		free(ptr);
	}
	return ret;
}

void set_vpath_cnt(int tunnel_id, int cnt)
{
	char conf_vpath[100];
	sprintf(conf_vpath, "vppn%d_vpath_cnt", tunnel_id);
	char value[100];
	sprintf(value, "%d", cnt);
	SetConfig(conf_vpath, value);
	return;
}

cJSON *get_vpath_conf(int tunnel_id, int index)
{
	cJSON *obj = NULL;
	char *uri = NULL;
	char *proxy = NULL;
	char *team_id = NULL;
	char conf_vpath[100];
	sprintf(conf_vpath, "vppn%d_vpath%d", tunnel_id, index);
	char *str = GetConfig(conf_vpath);
	if (str)
	{
		if (strlen(str) < 100)
		{
			uri = str;
			char *separator = strchr(uri, '@');
			*separator = 0;
			proxy = ++separator;
			separator = strchr(proxy, '@');
			*separator = 0;
			team_id = ++separator;
			obj = cJSON_CreateObject();
			cJSON_AddStringToObject(obj, "uri", uri);
			cJSON_AddStringToObject(obj, "vproxy", proxy);
			cJSON_AddStringToObject(obj, "team_id", team_id);
		}
		free(str);
	}
	return obj;
}

void set_vpath_conf(int tunnel_id, int index, cJSON *obj)
{
	char *str = NULL;
	char conf_vpath[100];
	sprintf(conf_vpath, "vppn%d_vpath%d", tunnel_id, index);
	cJSON *uri_item = cJSON_GetObjectItem(obj, "uri");
	cJSON *proxy_item = cJSON_GetObjectItem(obj, "vproxy");
	cJSON *team_id_item = cJSON_GetObjectItem(obj, "team_id");
	int total_len = strlen(uri_item->valuestring) + strlen(proxy_item->valuestring) + strlen(team_id_item->valuestring) + strlen("@") + strlen("@") + 1;
	if (total_len < 100)
	{
		str = malloc(total_len + 1);
		if (str)
		{
			strcpy(str, uri_item->valuestring);
			strcat(str, "@");
			strcat(str, proxy_item->valuestring);
			strcat(str, "@");
			strcat(str, team_id_item->valuestring);
			SetConfig(conf_vpath, str);
		}
	}
	return;
}

void load_vpath_conf2(int conf_type, int id)
{
	char conf_vpath_file[100];

	sprintf(conf_vpath_file, "/etc/site/vppn%d_vpath.conf", id);

	cJSON *array = cJSON_CreateArray();
	int vpath_cnt = get_vpath_cnt(id);
	int i;
	for(i = 0; i < vpath_cnt; i++)
	{
		cJSON *obj = get_vpath_conf(id, i);
		if (obj)
		{
			cJSON_AddItemToArray(array, obj);
		}
	}
	write_json_to_file(conf_vpath_file, array);
	cJSON_Delete(array);
	return;
}

void save_vpath_conf2(int conf_type, int id)
{
	char conf_vpath[100];
	char conf_vpath_file[100];

	sprintf(conf_vpath, "vppn%d_vpath", id);
	sprintf(conf_vpath_file, "/etc/site/vppn%d_vpath.conf", id);

	cJSON *tunnel_vpath = read_json_from_file(conf_vpath_file);
	if (tunnel_vpath)
	{
		int vpath_cnt = cJSON_GetArraySize(tunnel_vpath);
		int i;
		set_vpath_cnt(id, vpath_cnt);
		for(i = 0; i < vpath_cnt; i++)
		{
			cJSON *obj = cJSON_GetArrayItem(tunnel_vpath, i);
			set_vpath_conf(id, i, obj);
		}
		cJSON_Delete(tunnel_vpath);
	}
	return;
}

void save_vpath_json_to_conf(cJSON *tunnel_vpath, int conf_type, int id)
{
	char conf_vpath[100];
	char conf_vpath_file[100];
	if (conf_type == TYPE_VPPN)
	{
		sprintf(conf_vpath, "vppn%d_vpath", id);
		sprintf(conf_vpath_file, "/etc/site/vppn%d_vpath.conf", id);

	}
	else
	{
		sprintf(conf_vpath, "vpn%d_vpath", id);
		sprintf(conf_vpath_file, "/etc/vpn/vpn%d_vpath.conf", id);
	}

	char *save_ptr = NULL;
	if (tunnel_vpath)
	{
		int i;
		int vpath_cnt = cJSON_GetArraySize(tunnel_vpath);
		for(i = 0; i < vpath_cnt; i++)
		{
			char *vpath_conf = NULL;
			cJSON *one_item = cJSON_GetArrayItem(tunnel_vpath, i);
			cJSON *uri_item = cJSON_GetObjectItem(one_item, "uri");
			cJSON *proxy_item = cJSON_GetObjectItem(one_item, "vproxy");
			cJSON *server_item = cJSON_GetObjectItem(one_item, "server");
			if (conf_type == TYPE_VPPN)
			{
				vpath_conf = malloc(strlen(uri_item->valuestring) + strlen(proxy_item->valuestring) + strlen(server_item->valuestring) + strlen("@") + strlen("@") + 1);
				strcpy(vpath_conf, uri_item->valuestring);
				strcat(vpath_conf, "@");
				strcat(vpath_conf, proxy_item->valuestring);
				strcat(vpath_conf, "@");
				strcat(vpath_conf, server_item->valuestring);
			}
			else
			{
				vpath_conf = malloc(strlen(uri_item->valuestring) + 1);
				strcpy(vpath_conf, uri_item->valuestring);
			}

			save_ptr = my_strcat(save_ptr, vpath_conf);
			FREE_PTR(vpath_conf);
		}
		if (save_ptr)
		{
			SetConfig(conf_vpath, save_ptr);
			free(save_ptr);
		}
	}
	return;
}

void save_vpath_conf(int conf_type, int id)
{
	char conf_vpath[100];
	char conf_vpath_file[100];
	if (conf_type == TYPE_VPPN)
	{
		sprintf(conf_vpath, "vppn%d_vpath", id);
		sprintf(conf_vpath_file, "/etc/site/vppn%d_vpath.conf", id);

	}
	else
	{
		sprintf(conf_vpath, "vpn%d_vpath", id);
		sprintf(conf_vpath_file, "/etc/vpn/vpn%d_vpath.conf", id);
	}

	char *save_ptr = NULL;
	cJSON *tunnel_vpath = read_json_from_file(conf_vpath_file);
	if (tunnel_vpath)
	{
		int i;
		int vpath_cnt = cJSON_GetArraySize(tunnel_vpath);
		for(i = 0; i < vpath_cnt; i++)
		{
			char *vpath_conf = NULL;
			cJSON *one_item = cJSON_GetArrayItem(tunnel_vpath, i);
			cJSON *uri_item = cJSON_GetObjectItem(one_item, "uri");
			cJSON *proxy_item = cJSON_GetObjectItem(one_item, "vproxy");
			cJSON *server_item = cJSON_GetObjectItem(one_item, "server");
			if (conf_type == TYPE_VPPN)
			{
				vpath_conf = malloc(strlen(uri_item->valuestring) + strlen(proxy_item->valuestring) + strlen(server_item->valuestring) + strlen("@") + strlen("@") + 1);
				strcpy(vpath_conf, uri_item->valuestring);
				strcat(vpath_conf, "@");
				strcat(vpath_conf, proxy_item->valuestring);
				strcat(vpath_conf, "@");
				strcat(vpath_conf, server_item->valuestring);
			}
			else
			{
				vpath_conf = malloc(strlen(uri_item->valuestring) + 1);
				strcpy(vpath_conf, uri_item->valuestring);
			}

			save_ptr = my_strcat(save_ptr, vpath_conf);
			FREE_PTR(vpath_conf);
		}
		if (save_ptr)
		{
			SetConfig(conf_vpath, save_ptr);
			free(save_ptr);
		}
		cJSON_Delete(tunnel_vpath);
	}
	return;
}

void load_vpath_confs(int conf_type)
{
	int i;
	for(i = 0; i < 5; i++)
	{
		load_vpath_conf2(conf_type, i);
	}
	return;
}

void save_vpath_confs(int conf_type)
{
	int i;
	for(i = 0; i < 5; i++)
	{
		save_vpath_conf2(conf_type, i);
	}
	return;
}

void load_tunnel_confs(int conf_type)
{
	int i;
	load_manager(conf_type);
	for (i = 0; i < 5; i++)
	{
		load_tunnel_conf(conf_type, i);
	}
	return;
}

void save_tunnel_confs(int conf_type)
{
	int i;
	save_manager(conf_type);
	for (i = 0; i < 5; i++)
	{
		save_tunnel_conf(conf_type, i);
	}
	return;
}

int check_r7800()
{
	int ret = 0;
	FILE *fp = fopen("/module_name", "r");
	if (fp)
	{
		char line_buf[4096] = "";
		fgets(line_buf, sizeof (line_buf), fp);
		if (strncmp(line_buf, "R78", 3) == 0)
		{
			ret = 1;
		}
		fclose(fp);
	}
	return ret;
}

void preload_7800_old_tunnel_peers(cJSON *p2p_array, int tunnel_id)
{
	char new_peers_file[100];
	sprintf(new_peers_file, "/etc/site/vppn%d_peers.conf", tunnel_id);
	cJSON *new_peers = cJSON_CreateArray();
	int cnt = cJSON_GetArraySize(p2p_array);
	int i;
	for(i = 0; i < cnt; i++)
	{
		cJSON *peer = cJSON_GetArrayItem(p2p_array, i);
		cJSON *ip_item = cJSON_GetObjectItem(peer, "ip");
		cJSON *tunnel_id_item = cJSON_GetObjectItem(peer, "tunnel_id");
		if (tunnel_id_item->valueint == tunnel_id)
		{
			cJSON * new_obj1 = cJSON_CreateObject();
			cJSON_AddStringToObject(new_obj1, "peer_vip", ip_item->valuestring);
			cJSON_AddStringToObject(new_obj1, "peer_server", "220.168.30.11");

			cJSON * new_obj2 = cJSON_CreateObject();
			cJSON_AddStringToObject(new_obj2, "peer_vip", ip_item->valuestring);
			cJSON_AddStringToObject(new_obj2, "peer_server", "220.168.30.12");

			cJSON_AddItemToArray(new_peers, new_obj1);
			cJSON_AddItemToArray(new_peers, new_obj2);
		}
	}
	write_json_to_file(new_peers_file, new_peers);
	cJSON_Delete(new_peers);
	return;
}

void preload_7800_old_peers()
{
	char peers_file[100] = "/etc/site/bird_info.txt";
	cJSON *old_peers = read_json_from_file(peers_file);
	if (old_peers)
	{
		cJSON *p2p_array = cJSON_GetObjectItem(old_peers, "p2p_info");
		if (p2p_array)
		{
			int i;
			for(i = 0; i < 5; i++)
			{
				preload_7800_old_tunnel_peers(p2p_array, i);
			}
		}
		cJSON_Delete(old_peers);
	}
	remove(peers_file);
}

cJSON *parse_old_tunnel_peers(char *ptr)
{
	char *save_ptr1 = NULL;
	char *str1;
	char *token;

	cJSON *ret = cJSON_CreateArray();
	if (ptr && ptr[0])
	{
		for(str1 = ptr; ; str1 = NULL)
		{
			token = strtok_r(str1, ":", &save_ptr1);
			if (token == NULL)
			{
				break;
			}
			char *peer_vip = token;
			cJSON *obj1 = cJSON_CreateObject();
			cJSON_AddStringToObject(obj1, "peer_vip", peer_vip);
			cJSON_AddStringToObject(obj1, "peer_server", "220.168.30.11");

			cJSON *obj2 = cJSON_CreateObject();
			cJSON_AddStringToObject(obj2, "peer_vip", peer_vip);
			cJSON_AddStringToObject(obj2, "peer_server", "220.168.30.12");

			cJSON_AddItemToArray(ret, obj1);
			cJSON_AddItemToArray(ret, obj2);
		}
	}
	return ret;
}

void add_old_into_new(cJSON *new, cJSON *old_item)
{
	cJSON *old_peer_vip_item = cJSON_GetObjectItem(old_item, "peer_vip");
	cJSON *old_peer_server_item = cJSON_GetObjectItem(old_item, "peer_server");
	int new_cnt = cJSON_GetArraySize(new);
	int i;
	int found = 0;
	for(i = 0; i < new_cnt; i++)
	{
		cJSON *new_item = cJSON_GetArrayItem(new, i);
		cJSON *peer_vip_item = cJSON_GetObjectItem(new_item, "peer_vip");
		cJSON *peer_server_item = cJSON_GetObjectItem(new_item, "peer_server");
		if (strcmp(peer_vip_item->valuestring, old_peer_vip_item->valuestring) == 0 && strcmp(peer_server_item->valuestring, old_peer_server_item->valuestring) == 0)
		{
			found = 1;
			break;
		}
	}
	if (!found)
	{
		cJSON_AddItemToArray(new, cJSON_Duplicate(old_item, 1));
	}
	return;
}

void merge_old_into_new(cJSON *new, cJSON *old)
{
	int i;
	int old_cnt = cJSON_GetArraySize(old);
	for(i = 0; i < old_cnt; i++)
	{
		cJSON *old_item = cJSON_GetArrayItem(old, i);
		add_old_into_new(new, old_item);
	}
	return;
}

void save_peers_json_to_conf(cJSON *peers, int id)
{
	char conf_peer[100];
	char conf_peer_file[100];

	sprintf(conf_peer, "vppn%d_peers", id);
	sprintf(conf_peer_file, "/etc/site/vppn%d_peers.conf", id);
	if (peers)
	{
		int i;
		int peer_cnt = cJSON_GetArraySize(peers);
		char *save_conf = NULL;
		for (i = 0; i < peer_cnt; i++)
		{
			cJSON *peer = cJSON_GetArrayItem(peers, i);
			cJSON *peer_vip_item = cJSON_GetObjectItem(peer, "peer_vip");
			cJSON *peer_server_item = cJSON_GetObjectItem(peer, "peer_server");
			char *peer_conf = malloc(strlen(peer_vip_item->valuestring) + strlen(peer_server_item->valuestring) + strlen("@") + 1);
			strcpy(peer_conf, peer_vip_item->valuestring);
			strcat(peer_conf, "@");
			strcat(peer_conf, peer_server_item->valuestring);
			save_conf = my_strcat(save_conf, peer_conf);
			free(peer_conf);
		}
		if (save_conf)
		{
			SetConfig(conf_peer, save_conf);
			free(save_conf);
		}
	}

	return;
}

void preload_non_7800_old_tunnel_peers(int tunnel_id)
{
	char old_peers_conf[100];
	char new_peers_conf[100];
	sprintf(old_peers_conf, "site_remote_peer%d", tunnel_id);
	sprintf(new_peers_conf, "vppn%d_peers", tunnel_id);
	char *new_conf = GetConfig(new_peers_conf);
	char *old_conf = GetConfig(old_peers_conf);
	cJSON *new_conf_array = parse_tunnel_peers(new_conf);
	cJSON *old_conf_array = parse_old_tunnel_peers(old_conf);
	merge_old_into_new(new_conf_array, old_conf_array);
	save_peers_json_to_conf(new_conf_array, tunnel_id);
	UnsetConfig(old_peers_conf);
	FREE_PTR(new_conf);
	FREE_PTR(old_conf);
}

void preload_non_7800_old_peers()
{
	int i;
	for(i = 0; i < 5; i++)
	{
		preload_non_7800_old_tunnel_peers(i);
	}
	return;
}

void preload_old_peers()
{
	if (check_r7800())
	{
		preload_7800_old_peers();
	}
	else
	{
		preload_non_7800_old_peers();
		system("config commit");
	}
	return;
}

void add_vpn_new_path(cJSON *new_array, cJSON *old_item)
{
	int i;
	int found = 0;
	int cnt = cJSON_GetArraySize(new_array);
	for(i = 0; i < cnt; i++)
	{
		cJSON *item = cJSON_GetArrayItem(new_array, i);
		cJSON *uri_item = cJSON_GetObjectItem(item, "uri");
		if (strcmp(uri_item->valuestring, old_item->valuestring) == 0)
		{
			found = 1;
			break;
		}
	}
	if (!found)
	{
		cJSON *new_item = cJSON_CreateObject();
		cJSON_AddStringToObject(new_item, "uri", old_item->valuestring);
		cJSON_AddItemToArray(new_array, new_item);
	}
	return;
}

void merge_old_vpn_vpath_into_new(cJSON *new_array, cJSON *old_array)
{
	if (old_array)
	{
		int i;
		int old_cnt = cJSON_GetArraySize(old_array);
		for(i = 0; i < old_cnt; i++)
		{
			cJSON *old_item = cJSON_GetArrayItem(old_array, i);
			add_vpn_new_path(new_array, old_item);
		}
	}
	return;
}

void add_vppn_new_path(cJSON *new_array, cJSON *old_item)
{
	int i;
	int found = 0;
	cJSON *old_uri_item = cJSON_GetObjectItem(old_item, "uri");
	cJSON *old_vproxy_item = cJSON_GetObjectItem(old_item, "vproxy");
	int cnt = cJSON_GetArraySize(new_array);
	for(i = 0; i < cnt; i++)
	{
		cJSON *item = cJSON_GetArrayItem(new_array, i);
		cJSON *uri_item = cJSON_GetObjectItem(item, "uri");
		cJSON *vproxy_item = cJSON_GetObjectItem(item, "vproxy");
		if (strcmp(uri_item->valuestring, old_uri_item->valuestring) == 0 &&
				strcmp(vproxy_item->valuestring, old_vproxy_item->valuestring) == 0)
		{
			found = 1;
			break;
		}
	}
	if (!found)
	{
		cJSON *dup_old1 = cJSON_Duplicate(old_item, 1);
		cJSON_AddStringToObject(dup_old1, "server", "220.168.30.11");
		cJSON *dup_old2 = cJSON_Duplicate(old_item, 1);
		cJSON_AddStringToObject(dup_old2, "server", "220.168.30.12");
		cJSON_AddItemToArray(new_array, dup_old1);
		cJSON_AddItemToArray(new_array, dup_old2);
	}
	return;
}

void merge_old_vppn_vpath_into_new(cJSON *new_array, cJSON *old_array)
{
	if (old_array)
	{
		int i;
		int old_cnt = cJSON_GetArraySize(old_array);
		for(i = 0; i < old_cnt; i++)
		{
			cJSON *old_obj = cJSON_GetArrayItem(old_array, i);
			add_vppn_new_path(new_array, old_obj);
		}
	}
	return;
}

void preload_7800_old_tunnel_vpath(int conf_type, int id)
{
	char old_vpath_file[100];
	char new_vpath_file[100];

	if (conf_type == 0)
	{
		sprintf(old_vpath_file, "/etc/vpn/whitelist%d.conf", id);
		sprintf(new_vpath_file, "/etc/vpn/vpn%d_vpath.conf", id);
		cJSON *new_vpath = read_json_from_file(new_vpath_file);
		if (!new_vpath)
		{
			new_vpath = cJSON_CreateArray();
		}
		cJSON *old_vpath = read_json_from_file(old_vpath_file);
		if (!old_vpath)
		{
			old_vpath = cJSON_CreateObject();
		}
		merge_old_vpn_vpath_into_new(new_vpath, cJSON_GetObjectItem(old_vpath, "whitelist"));
		write_json_to_file(new_vpath_file, new_vpath);
		remove(old_vpath_file);
		cJSON_Delete(new_vpath);
		cJSON_Delete(old_vpath);
	}
	else
	{
		sprintf(old_vpath_file, "/etc/site/whitelist%d.conf", id);
		sprintf(new_vpath_file, "/etc/site/vppn%d_vpath.conf", id);
		cJSON *new_vpath = read_json_from_file(new_vpath_file);
		if (!new_vpath)
		{
			new_vpath = cJSON_CreateArray();
		}
		cJSON *old_vpath = read_json_from_file(old_vpath_file);
		if (!old_vpath)
		{
			old_vpath = cJSON_CreateArray();
		}

		merge_old_vppn_vpath_into_new(new_vpath, old_vpath);
		write_json_to_file(new_vpath_file, new_vpath);
		remove(old_vpath_file);
		cJSON_Delete(new_vpath);
		cJSON_Delete(old_vpath);
	}

	remove(old_vpath_file);
	return;
}

void preload_7800_old_vpaths(int conf_type)
{
	int i;
	for(i = 0; i < 5; i++)
	{
		preload_7800_old_tunnel_vpath(conf_type, i);
	}
	return;
}

void preload_non_7800_old_tunnel_vpath(int conf_type, int id)
{
	char *old_conf = NULL;
	char *new_conf = NULL;
	char old_vpath_conf[100];
	char new_vpath_conf[100];
	/* ignore vpn's vpath */
	if (conf_type == 0)
	{
		sprintf(old_vpath_conf, "vpn_whitelist%d", id);
		sprintf(new_vpath_conf, "vpn%d_vpath", id);
		old_conf = GetConfig(old_vpath_conf);
		new_conf = GetConfig(new_vpath_conf);

	}
	else
	{
		sprintf(old_vpath_conf, "site_whitelist%d", id);
		sprintf(new_vpath_conf, "vppn%d_vpath", id);
	}
	cJSON *new_array = parse_tunnel_vpath(new_conf, conf_type);
	cJSON *old_array = parse_tunnel_old_vpath(old_conf, conf_type);
	if (conf_type == 0)
	{
		merge_old_vpn_vpath_into_new(new_array, old_array);
	}
	else
	{
		merge_old_vppn_vpath_into_new(new_array, old_array);
	}
	save_vpath_json_to_conf(new_array, conf_type, id);
	cJSON_Delete(new_array);
	cJSON_Delete(old_array);
	FREE_PTR(old_conf);
	FREE_PTR(new_conf);
	UnsetConfig(old_vpath_conf);
	return;
}

void preload_non_7800_old_vpaths(int conf_type)
{
	int i;
	for(i = 0; i < 5; i++)
	{
		preload_non_7800_old_tunnel_vpath(conf_type, i);
	}
	return;
}

void preload_old_vpath(int conf_type)
{
	if (check_r7800())
	{
		preload_7800_old_vpaths(conf_type);
	}
	else
	{
		preload_non_7800_old_vpaths(conf_type);
		system("config commit");
	}
	return;
}

void load_public_vpath_switch_conf(int conf_type, int tunnel_id)
{
	char public_vpath_switch_file[100];
	char conf_public_vpath_switch_on[100];
	char conf_public_vpath_switch_vproxy[100];
	char conf_public_vpath_switch_server[100];

	char *conf_public_vpath_switch_on_str = NULL;
	char *conf_public_vpath_switch_vproxy_str = NULL;
	char *conf_public_vpath_switch_server_str = NULL;
	cJSON *conf_json = cJSON_CreateObject();
	if (conf_type == TYPE_VPN)
	{
		sprintf(public_vpath_switch_file, "/etc/vpn/public_vpath%d_switch.conf", tunnel_id);
		sprintf(conf_public_vpath_switch_on, "public_vpn_vpath%d_switch_on", tunnel_id);
	}
	else
	{
		sprintf(public_vpath_switch_file, "/etc/site/public_vpath%d_switch.conf", tunnel_id);
		sprintf(conf_public_vpath_switch_on, "public_vppn_vpath%d_switch_on", tunnel_id);
		sprintf(conf_public_vpath_switch_vproxy, "public_vppn_vpath%d_switch_vproxy", tunnel_id);
		sprintf(conf_public_vpath_switch_server, "public_vppn_vpath%d_switch_server", tunnel_id);
	}
	conf_public_vpath_switch_on_str = GetConfig(conf_public_vpath_switch_on);
	conf_public_vpath_switch_vproxy_str = GetConfig(conf_public_vpath_switch_on);
	conf_public_vpath_switch_server_str = GetConfig(conf_public_vpath_switch_on);

	if (conf_public_vpath_switch_on_str && conf_public_vpath_switch_on_str[0] == '1')
	{
		if (conf_type == TYPE_VPPN)
		{
			if (conf_public_vpath_switch_vproxy_str && conf_public_vpath_switch_server_str)
			{
				cJSON_AddNumberToObject(conf_json, "on", 1);
				cJSON_AddStringToObject(conf_json, "vpath_tunnel", conf_public_vpath_switch_vproxy_str);
				cJSON_AddStringToObject(conf_json, "tunnel_server", conf_public_vpath_switch_server_str);
			}
			/* think wrong conf */
			else
			{
				cJSON_AddNumberToObject(conf_json, "on", 0);
			}
		}
		else
		{
			cJSON_AddNumberToObject(conf_json, "on", 1);
		}
	}
	else
	{
		cJSON_AddNumberToObject(conf_json, "on", 0);
	}
	write_json_to_file(public_vpath_switch_file, conf_json);
	cJSON_Delete(conf_json);
	FREE_PTR(conf_public_vpath_switch_on_str);
	FREE_PTR(conf_public_vpath_switch_vproxy_str);
	FREE_PTR(conf_public_vpath_switch_server_str);
	return;
}

void load_public_vpath_switch_confs(int conf_type)
{
	int i;
	for(i = 0; i < 5; i++)
	{
		load_public_vpath_switch_conf(conf_type, i);
	}
	return;
}

void save_public_vpath_switch_conf(int conf_type, int tunnel_id)
{
	char public_vpath_switch_file[100];
	char conf_public_vpath_switch_on[100];
	char conf_public_vpath_switch_vproxy[100];
	char conf_public_vpath_switch_server[100];

	if (conf_type == TYPE_VPN)
	{
		sprintf(public_vpath_switch_file, "/etc/vpn/public_vpath%d_switch.conf", tunnel_id);
		sprintf(conf_public_vpath_switch_on, "public_vpn_vpath%d_switch_on", tunnel_id);
	}
	else
	{
		sprintf(public_vpath_switch_file, "/etc/site/public_vpath%d_switch.conf", tunnel_id);
		sprintf(conf_public_vpath_switch_on, "public_vppn_vpath%d_switch_on", tunnel_id);
		sprintf(conf_public_vpath_switch_vproxy, "public_vppn_vpath%d_switch_vproxy", tunnel_id);
		sprintf(conf_public_vpath_switch_server, "public_vppn_vpath%d_switch_server", tunnel_id);
	}
	cJSON *conf_json = read_json_from_file(public_vpath_switch_file);
	if (!conf_json)
	{
		conf_json = cJSON_CreateObject();
		cJSON_AddNumberToObject(conf_json, "on", 0);
	}

	cJSON *on_item = cJSON_GetObjectItem(conf_json, "on");
	cJSON *vproxy_item = cJSON_GetObjectItem(conf_json, "vpath_tunnel");
	cJSON *server_item = cJSON_GetObjectItem(conf_json, "tunnel_server");


	if (conf_type == TYPE_VPPN)
	{
		if (on_item && vproxy_item && server_item
				&&
				on_item->valueint == 1
				&&
				vproxy_item->valuestring
				&&
				server_item->valuestring
				)
		{

			SetConfig(conf_public_vpath_switch_on, "1");
			SetConfig(conf_public_vpath_switch_vproxy, vproxy_item->valuestring);
			SetConfig(conf_public_vpath_switch_server, server_item->valuestring);
		}
		else
		{
			SetConfig(conf_public_vpath_switch_on, "0");
		}
	}
	else
	{
		if (on_item && on_item->valueint == 1)
		{
			SetConfig(conf_public_vpath_switch_on, "1");
		}
		else
		{
			SetConfig(conf_public_vpath_switch_on, "0");
		}
	}
	cJSON_Delete(conf_json);
	return;
}

void save_public_vpath_switch_confs(int conf_type)
{
	int i;
	for(i = 0; i < 5; i++)
	{
		save_public_vpath_switch_conf(conf_type, i);
	}
	return;
}

int main(int argc, char **argv)
{
	int ret = 0;
	int conf_type;
	run_in_nodebug();
	if (argc == 3)
	{
		if (strcmp(argv[2], "vpn") == 0)
		{
			conf_type = TYPE_VPN;
		}
		else
		{
			conf_type = TYPE_VPPN;
		}
		if (strcmp(argv[1], "loadconfig") == 0)
		{
			load_tunnel_confs(conf_type);
			//load_peer_confs(conf_type);
			load_vpath_confs(conf_type);
			//load_public_vpath_switch_confs(conf_type);
		}
		else if (strcmp(argv[1], "saveconfig") == 0)
		{
			save_tunnel_confs(conf_type);
			//save_peer_confs(conf_type);
			save_vpath_confs(conf_type);
			//save_public_vpath_switch_confs(conf_type);
			system("config commit");
		}
		else if (strcmp(argv[1], "adapt_old_config") == 0)
		{
			preload_old_peers();
			preload_old_vpath(conf_type);
		}
	}
	return ret;
}
