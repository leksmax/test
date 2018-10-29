#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include "vpn_tool.h"
#include "net_tool.h"
#include "my-device.h"
#include "cJSON.h"
#include "uds_client.h"

cJSON* vpn_tool_stop_vpn(char* team_id)
{
	cJSON* local_req = cJSON_CreateObject();
	cJSON_AddNumberToObject(local_req, "channel", 0);
	cJSON_AddNumberToObject(local_req, "action", 3);
	cJSON_AddStringToObject(local_req, "team_id", team_id);
	set_vppn_status(0);
	cJSON* res = net_tool_tcp_json_client_with_size((char*)"127.0.0.1", 4100, local_req, (char*)"json", strlen("json"));
	return res;
}

cJSON* vpn_tool_start_vpn(char* team_id)
{
	cJSON* local_req = cJSON_CreateObject();
	cJSON_AddNumberToObject(local_req, "channel", 0);
	cJSON_AddNumberToObject(local_req, "action", 2);
	cJSON_AddStringToObject(local_req, "team_id", team_id);
	set_vppn_status(1);
	cJSON* res = net_tool_tcp_json_client_with_size((char*)"127.0.0.1", 4100, local_req, (char*)"json", strlen("json"));
	return res;
}

/*
 *	reconnect_flag: 0 no need reconnect_flag
 *	1 need reconnect if the porxyIp is the same as now connecting to
 *	2 need reconnect forced
 * */
cJSON* vpn_tool_reload_member(int reconnect_flag, char* proxyIp)
{
	cJSON* local_req = cJSON_CreateObject();
	cJSON_AddNumberToObject(local_req, "action", 25);
	cJSON_AddNumberToObject(local_req, "channel", 0);
	cJSON_AddNumberToObject(local_req, "reconnect_flag", reconnect_flag);

	if (proxyIp)
	{
		cJSON_AddStringToObject(local_req, "proxyIp", proxyIp);
	}

	cJSON* res = net_tool_tcp_json_client_with_size((char*)"127.0.0.1", 4100, local_req, (char*)"json", strlen("json"));
	cJSON_Delete(local_req);
	return res;
}

cJSON* vpn_tool_get_vpn_traffic()
{
	cJSON* local_req = cJSON_CreateObject();
	cJSON_AddNumberToObject(local_req, "action", 20);
	cJSON_AddNumberToObject(local_req, "channel", 0);
	cJSON* res = net_tool_tcp_json_client_with_size((char*)"127.0.0.1", 4100, local_req, (char*)"json", strlen("json"));
	cJSON_Delete(local_req);
	return res;
}

cJSON* vpn_tool_get_direct_list(char* team_id)
{
	cJSON* local_req = cJSON_CreateObject();
	cJSON_AddNumberToObject(local_req, "action", 26);
	cJSON_AddNumberToObject(local_req, "channel", 0);
	cJSON_AddStringToObject(local_req, "team_id", team_id);
	cJSON* res = net_tool_tcp_json_client_with_size((char*)"127.0.0.1", 4100, local_req, (char*)"json", strlen("json"));
	cJSON_Delete(local_req);
	return res;
}

cJSON* vpn_tool_add_whitelist(char* team_id, cJSON* list_item)
{
	cJSON* local_req = cJSON_CreateObject();
	cJSON_AddNumberToObject(local_req, "channel", 0);
	cJSON_AddNumberToObject(local_req, "action", 4);
	cJSON_AddStringToObject(local_req, "team_id", team_id);
	cJSON_AddItemToObject(local_req, "list", cJSON_Duplicate(list_item, 1));
	cJSON* res = net_tool_tcp_json_client_with_size((char*)"127.0.0.1", 4100, local_req, (char*)"json", strlen("json"));
	cJSON_Delete(local_req);
	return res;
}

cJSON* vpn_tool_del_whitelist(char* team_id, cJSON* list_item)
{
	cJSON* local_req = cJSON_CreateObject();
	cJSON_AddNumberToObject(local_req, "channel", 0);
	cJSON_AddNumberToObject(local_req, "action", 5);
	cJSON_AddStringToObject(local_req, "team_id", team_id);
	cJSON_AddItemToObject(local_req, "list", cJSON_Duplicate(list_item, 1));
	cJSON* res = net_tool_tcp_json_client_with_size((char*)"127.0.0.1", 4100, local_req, (char*)"json", strlen("json"));
	cJSON_Delete(local_req);
	return res;
}

cJSON* vpn_tool_get_whitelist(char* team_id)
{
	cJSON* local_req = cJSON_CreateObject();
	cJSON_AddNumberToObject(local_req, "channel", 0);
	cJSON_AddNumberToObject(local_req, "action", 24);
	cJSON_AddStringToObject(local_req, "team_id", team_id);
	cJSON* res = net_tool_tcp_json_client_with_size((char*)"127.0.0.1", 4100, local_req, (char*)"json", strlen("json"));
	cJSON_Delete(local_req);
	return res;
}

cJSON* vpn_tool_get_members_traffic()
{
	cJSON* local_req = cJSON_CreateObject();
	cJSON_AddNumberToObject(local_req, "channel", 0);
	cJSON_AddNumberToObject(local_req, "action", 27);
	//cJSON_AddStringToObject(local_req, "team_id", team_id);
	cJSON* res = net_tool_tcp_json_client_with_size((char*)"127.0.0.1", 4100, local_req, (char*)"json", strlen("json"));
	cJSON_Delete(local_req);
	return res;
}

cJSON* vpn_tool_get_members_ping()
{
	cJSON* local_req = cJSON_CreateObject();
	cJSON_AddNumberToObject(local_req, "channel", 0);
	cJSON_AddNumberToObject(local_req, "action", 28);
	//cJSON_AddStringToObject(local_req, "team_id", team_id);
	cJSON* res = net_tool_tcp_json_client_with_size((char*)"127.0.0.1", 4100, local_req, (char*)"json", strlen("json"));
	cJSON_Delete(local_req);
	return res;
}

cJSON* vpn_tool_get_connectInfo()
{
	cJSON* local_req = cJSON_CreateObject();
	cJSON_AddNumberToObject(local_req, "channel", 0);
	cJSON_AddNumberToObject(local_req, "action", 29);
	//cJSON_AddStringToObject(local_req, "team_id", team_id);
	cJSON* res = net_tool_tcp_json_client_with_size((char*)"127.0.0.1", 4100, local_req, (char*)"json", strlen("json"));
	cJSON_Delete(local_req);
	return res;
}

int vpn_tool_get_member_bandwidth(char* ip, int* upload, int* download)
{
	int found = 0;
	int perf_ret = -1;
	char rbuf[1024];
	//printf("member bandwidth 1\n");
	cJSON* req = cJSON_CreateObject();
	cJSON* data = cJSON_CreateArray();
	cJSON* obj = cJSON_CreateObject();
	cJSON_AddItemToArray(data, obj);
	cJSON_AddStringToObject(obj, "ip", ip);
	cJSON_AddItemToObject(req, "data", data);
	cJSON_AddStringToObject(req, "cmd", "perf");
	//printf("member bandwidth 2\n");
	//cJSON_Dump(req);
	char *str = cJSON_PrintUnformatted(req);
	if (str)
	{
		//printf("member bandwidth 2.0\n");
		perf_ret = uds_client_request((char*)"/var/run/vpnperf.sock", str, strlen(str), rbuf, sizeof(rbuf), 30);
		//printf("member bandwidth 2.1:perf_ret = %d\n", perf_ret);
		free(str);
	}
	//printf("member bandwidth 2.2\n");

	if (perf_ret >= 0)
	{
		//printf("member bandwidth 3.0:rbuf:%s\n", rbuf);
		cJSON* response = cJSON_Parse(rbuf);
		if (response)
		{
		//printf("member bandwidth 3.1\n");
			cJSON* code = cJSON_GetObjectItem(response, "code");
			if (code && code->valueint == 0)
			{
				cJSON* result = cJSON_GetObjectItem(response, "data");
				int data_cnt = cJSON_GetArraySize(result);
				if (data_cnt > 0)
				{
					cJSON* first_item = cJSON_GetArrayItem(result, 0);
					cJSON* upload_item = cJSON_GetObjectItem(first_item, "upload");
					cJSON* download_item = cJSON_GetObjectItem(first_item, "download");
					
					*upload = upload_item->valueint;
					*download = download_item->valueint;
					found = 1;
				}
			}
			cJSON_Delete(response);
		}
	}
	//printf("member bandwidth 3\n");
	
	if (!found)
	{
		*upload  = 0;
		*download  = 0;
	}
	//printf("member bandwidth 4\n");
	cJSON_Delete(req);
	return found;
}
