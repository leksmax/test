#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "file_tool.h"
#include "my-device.h"
#include "net_tool.h"
#include "input-param.h"
#include "process-input.h"
#include "cJSON.h"
#include "vpn_cloud.h"
#include "process_tool.h"
#include "system-config.h"
#include "str_tool.h"

cJSON* handle_get_vpn_status(char* cloud_host, int cloud_port)
{
	cJSON* ret = cJSON_CreateObject();
	char my_id[100] = "";
	char my_teamid[100] = "";
	get_my_id(my_id);
	get_my_teamid(my_teamid);
	int on = 0;
	cJSON* conf = read_json_from_file((char*)"/etc/site/site0.conf");
	if (conf)
	{
		cJSON* on_item = cJSON_GetObjectItem(conf, "on");
		on = on_item->valueint;
		cJSON_Delete(conf);
	}
	cJSON* req = cJSON_CreateObject();
	cJSON_AddStringToObject(req, "mac", my_id);
	cJSON* req2 = cJSON_CreateObject();
	cJSON_AddStringToObject(req2, "userId", my_id);
	cJSON* response = vpn_cloud_tool3((char*)"/vppn/api/v1/client/searchTeamAndMemberByMac", req);
	if (response)
	{
		//cJSON_Dump(response);
		cJSON* teams_item = cJSON_GetObjectItem(response, "teams");
		cJSON_AddStringToObject(ret, "code", "200");
		cJSON_AddItemToObject(ret, "teams",  cJSON_Duplicate(teams_item, 1));
		cJSON_Delete(response);
	}
	else
	{
		cJSON_AddStringToObject(ret, "code", "201");
	}
	cJSON* response2 = vpn_cloud_tool3((char*)"/vppn/api/v1/client/searchTeam", req2);
	if (response2)
	{
		cJSON* teams_item = cJSON_GetObjectItem(response2, "teams");
		cJSON_AddItemToObject(ret, "have_teams",  cJSON_Duplicate(teams_item, 1));
		cJSON_Delete(response2);
	}
	cJSON_AddStringToObject(ret, "cur_team", my_teamid);
	if (on)
	{
		cJSON_AddStringToObject(ret, "on", "1");
	}
	else
	{
		cJSON_AddStringToObject(ret, "on", "0");
	}

	FILE* fp = NULL;
	fp = fopen("/proc/simple_config/cloud_led", "r");
	if (fp)
	{
		char line[100] = "";
		memset(line, 0, sizeof line);
		fgets(line, sizeof(line) - 1, fp);
		str_tool_replaceFirst(line, '\r', '\0');
		str_tool_replaceFirst(line, '\n', '\0');
		cJSON_AddStringToObject(ret, "cloud_led_on", line);
		fclose(fp);
	}
	else
	{
		cJSON_AddStringToObject(ret, "cloud_led_on", "0");
	}

	cJSON_AddStringToObject(ret, "sn", my_id);
	cJSON_Delete(req);
	cJSON_Delete(req2);
	return ret;
}

#if 0
cJSON* handle_get_vpn_devices(char *cloud_host, int cloud_port, char* team_name)
{
	
}
#endif

cJSON* handle_create_team(char *cloud_host, int cloud_port, char* team_name)
{
	cJSON* ret = NULL;
	cJSON* req = cJSON_CreateObject();
	cJSON_AddStringToObject(req, "teamName", team_name);
	char my_id[100] = "";
	get_my_id(my_id);
	char team_des[100] = "";
	sprintf(team_des, "agent-%s", my_id);
	cJSON_AddStringToObject(req, "teamDes", team_des);
	cJSON_AddStringToObject(req, "userId", my_id);
	cJSON_AddNumberToObject(req, "siteCount", 10);
	cJSON_AddNumberToObject(req, "terminalCount", 10);

#if 0
	char headers[2][100];
	char base64_buf[100];
	memset(base64_buf, 0, sizeof(base64_buf));
	char agent_id[100] = "";
	char base64_src_buf[100] = "";
	GetConfig("x_agent_id", agent_id);
	str_tool_replaceAll(agent_id, '\n', 0);
	sprintf(base64_src_buf, "%s:%s", g_config.self_id, agent_id);
	base64_encode(base64_src_buf, strlen(base64_src_buf), base64_buf);
	//str_tool_replaceAll(base64_buf, '\n', 0);
	sprintf(headers[0],"Apikey: XXXXXXXXX");
	sprintf(headers[1],"Authorization: %s", base64_buf);
	//MY_DEBUG_INFO("===%s\n", base64_src_buf);
	//MY_DEBUG_INFO("===%s\n", base64_buf);
	char *headers_ptr[2];
	headers_ptr[0] = headers[0];
	headers_ptr[1] = headers[1];

	cJSON* response = net_tool_https_json_client(1, cloud_host, 443, "/vppn/api/v1/client/createTeam", req, headers_ptr, 2, NULL);
#else
	cJSON* response = vpn_cloud_tool3((char*)"/vppn/api/v1/client/createTeam", req);
	//cJSON* response = net_tool_http_json_client2(1, cloud_host, cloud_port, (char*)"/vppn/api/v1/client/createTeam", req, (char*)"Authorization: Basic YWRtaW46cHVibGlj\r\n");
#endif
	if (response)
	{
		//cJSON_Dump(response);
		cJSON* code_item = cJSON_GetObjectItem(response, "code");
		if (code_item->valueint == 200)
		{
			cJSON* team_id_item = cJSON_GetObjectItem(response, "teamId");
			ret = cJSON_CreateObject();
			cJSON_AddStringToObject(ret, "code", "200");
			cJSON_AddStringToObject(ret, "team_id", team_id_item->valuestring);
		}
		cJSON_Delete(response);
	}
	cJSON_Delete(req);
	return ret;
}

cJSON* handle_delete_team(char *cloud_host, int cloud_port, char* team_id)
{
	cJSON* ret = NULL;
	cJSON* req = cJSON_CreateObject();
	char my_id[100] = "";
	get_my_id(my_id);
	cJSON_AddStringToObject(req, "teamId", team_id);
	cJSON_AddStringToObject(req, "userId", my_id);
#if 0
	char headers[2][100];
	char base64_buf[100];
	memset(base64_buf, 0, sizeof(base64_buf));
	char agent_id[100] = "";
	char base64_src_buf[100] = "";
	GetConfig("x_agent_id", agent_id);
	str_tool_replaceAll(agent_id, '\n', 0);
	sprintf(base64_src_buf, "%s:%s", g_config.self_id, agent_id);
	base64_encode(base64_src_buf, strlen(base64_src_buf), base64_buf);
	//str_tool_replaceAll(base64_buf, '\n', 0);
	sprintf(headers[0],"Apikey: XXXXXXXXX");
	sprintf(headers[1],"Authorization: %s", base64_buf);
	//MY_DEBUG_INFO("===%s\n", base64_src_buf);
	//MY_DEBUG_INFO("===%s\n", base64_buf);
	char *headers_ptr[2];
	headers_ptr[0] = headers[0];
	headers_ptr[1] = headers[1];

	cJSON* response = net_tool_https_json_client(1, cloud_host, 443, "/vppn/api/v1/client/deleteTeam", req, headers_ptr, 2, NULL);
#else
	cJSON* response = vpn_cloud_tool3((char*)"/vppn/api/v1/client/deleteTeam", req);
	//cJSON* response = net_tool_http_json_client2(1, cloud_host, cloud_port, (char*)"/vppn/api/v1/client/deleteTeam", req, (char*)"Authorization: Basic YWRtaW46cHVibGlj\r\n");
#endif
	if (response)
	{
		//cJSON_Dump(response);
		cJSON* code_item = cJSON_GetObjectItem(response, "code");
		if (code_item->valueint == 200)
		{
			ret = cJSON_CreateObject();
			cJSON_AddStringToObject(ret, "code", "200");
		}
		cJSON_Delete(response);
	}
	cJSON_Delete(req);
	return ret;
}

cJSON* handle_add_device(char *cloud_host, int cloud_port, char* team_id, char* sn, char* vip, char* proxy_ip)
{
	cJSON* ret = NULL;
	cJSON* req = cJSON_CreateObject();
	//cJSON_AddStringToObject(req, "teamName", team_name);
	char my_id[100] = "";
	get_my_id(my_id);
	char team_des[100] = "";
	sprintf(team_des, "agent-%s", my_id);
	cJSON_AddStringToObject(req, "teamId", team_id);
	cJSON_AddStringToObject(req, "userId", my_id);
	cJSON_AddStringToObject(req, "mac", sn);
	cJSON_AddStringToObject(req, "ip", vip);
	cJSON_AddStringToObject(req, "proxyIp", proxy_ip);
#if 0
	char headers[2][100];
	char base64_buf[100];
	memset(base64_buf, 0, sizeof(base64_buf));
	char agent_id[100] = "";
	char base64_src_buf[100] = "";
	GetConfig("x_agent_id", agent_id);
	str_tool_replaceAll(agent_id, '\n', 0);
	sprintf(base64_src_buf, "%s:%s", g_config.self_id, agent_id);
	base64_encode(base64_src_buf, strlen(base64_src_buf), base64_buf);
	//str_tool_replaceAll(base64_buf, '\n', 0);
	sprintf(headers[0],"Apikey: XXXXXXXXX");
	sprintf(headers[1],"Authorization: %s", base64_buf);
	//MY_DEBUG_INFO("===%s\n", base64_src_buf);
	//MY_DEBUG_INFO("===%s\n", base64_buf);
	char *headers_ptr[2];
	headers_ptr[0] = headers[0];
	headers_ptr[1] = headers[1];
	cJSON* response = net_tool_https_json_client(1, cloud_host, 443, "/vppn/api/v1/client/joinTeam", req, headers_ptr, 2, NULL);
#else
	cJSON* response = vpn_cloud_tool3((char*)"/vppn/api/v1/client/joinTeam", req);
	//cJSON* response = net_tool_http_json_client2(1, cloud_host, cloud_port, (char*)"/vppn/api/v1/client/joinTeam", req, (char*)"Authorization: Basic YWRtaW46cHVibGlj\r\n");
#endif
	if (response)
	{
		cJSON* code_item = cJSON_GetObjectItem(response, "code");
		if (code_item->valueint == 200)
		{
			ret = cJSON_CreateObject();
			cJSON_AddStringToObject(ret, "code", "200");
		}
		cJSON_Delete(response);
	}
	cJSON_Delete(req);
	return ret;
}

cJSON* handle_del_device(char *cloud_host, int cloud_port, char* team_id, char* sn, char* vip)
{
	cJSON* ret = NULL;
	cJSON* req = cJSON_CreateObject();
	char my_id[100] = "";
	get_my_id(my_id);
	char team_des[100] = "";
	sprintf(team_des, "agent-%s", my_id);
	cJSON_AddStringToObject(req, "teamId", team_id);
	cJSON_AddStringToObject(req, "userId", my_id);
	cJSON_AddStringToObject(req, "mac", sn);
	cJSON* response = vpn_cloud_tool3((char*)"/vppn/api/v1/client/outTeam", req);
	//cJSON* response = net_tool_http_json_client2(1, cloud_host, cloud_port, (char*)"/vppn/api/v1/client/outTeam", req, (char*)"Authorization: Basic YWRtaW46cHVibGlj\r\n");
	if (response)
	{
		//cJSON_Dump(response);
		cJSON* code_item = cJSON_GetObjectItem(response, "code");
		if (code_item->valueint == 200)
		{
			ret = cJSON_CreateObject();
			cJSON_AddStringToObject(ret, "code", "200");
		}
		cJSON_Delete(response);
	}
	cJSON_Delete(req);
	return ret;
}

cJSON* handle_modify_subnet(char* team_id, char *sn, char* new_subnet)
{
	cJSON* ret = NULL;
	char cmd_buf[100];
	sprintf(cmd_buf, "mqtt-agent -n -1 %s -2 %s -3 %s -4 %s", sn, "modify_subnet", team_id, new_subnet);
	system(cmd_buf);
	ret = cJSON_CreateObject();
	cJSON_AddStringToObject(ret, "code", "200");
	return ret;
}

cJSON* handle_start_vpn(char* team_id, char* sn, char* vip)
{
	cJSON* ret = NULL;
	char cmd_buf[100];
	sprintf(cmd_buf, "mqtt-agent -n -1 %s -2 %s -3 %s -4 %s", sn, "start_vpn", team_id, vip);
	system(cmd_buf);
	ret = cJSON_CreateObject();
	cJSON_AddStringToObject(ret, "code", "200");
	return ret;
}

cJSON* handle_stop_vpn(char* team_id, char* sn)
{
	cJSON* ret = NULL;
	char cmd_buf[100];
	sprintf(cmd_buf, "mqtt-agent -n -1 %s -2 %s -3 %s", sn, "stop_vpn", team_id);
	system(cmd_buf);
	ret = cJSON_CreateObject();
	cJSON_AddStringToObject(ret, "code", "200");
	return ret;
}

cJSON* handle_get_device_info()
{
	cJSON* ret = NULL;
	ret = get_my_device_info();
	return ret;
}

cJSON* handle_get_devices()
{
	cJSON* ret = NULL;
	char team_id[100] = "";
	get_my_teamid(team_id);
	char *str_ret = process_tool_run_cmd((char*)"monitor-agent vpn_traffic");
	if (str_ret)
	{
		ret = cJSON_Parse(str_ret);
		if (ret)
		{
			cJSON_AddStringToObject(ret, "team_id", team_id);
		}
		free(str_ret);
	}
	return ret;
}

cJSON* process_input(char *input)
{
	cJSON* ret = NULL;
	cJSON* params = gen_input_params(input);
	char* action = find_input_param(params, (char*)"action");
	char* sn = find_input_param(params, (char*)"sn");
	char* team_id = find_input_param(params, (char*)"team_id");
	char* vip = find_input_param(params, (char*)"vip");
	char* new_subnet = find_input_param(params, (char*)"new_subnet");
	char* proxy_ip = find_input_param(params, (char*)"proxyIp");
	char* team_name = find_input_param(params, (char*)"team_name");
	cJSON* cloud_host_item = NULL;
	cJSON* cloud_port_item = NULL;
	cJSON* manager = read_json_from_file((char*)"/etc/site/manager");
	if (manager)
	{
		cloud_host_item = cJSON_GetObjectItem(manager, "cloud_host");
		cloud_port_item = cJSON_GetObjectItem(manager, "cloud_port");
	}
	//printf("cloud => %s:%d\n", cloud_host_item->valuestring, cloud_port_item->valueint);
	if (strcmp(action, "get_vpn_status") == 0)
	{
		ret = handle_get_vpn_status(cloud_host_item->valuestring, cloud_port_item->valueint);
	}
	else if (strcmp(action, "create_team") == 0)
	{
		ret = handle_create_team(cloud_host_item->valuestring, cloud_port_item->valueint, team_name);
	}
	else if (strcmp(action, "delete_team") == 0)
	{
		ret = handle_delete_team(cloud_host_item->valuestring, cloud_port_item->valueint, team_id);
	}
	else if (strcmp(action, "add_device") == 0)
	{
		ret = handle_add_device(cloud_host_item->valuestring, cloud_port_item->valueint, team_id, sn, vip, proxy_ip);
	}
	else if (strcmp(action, "del_device") == 0)
	{
		ret = handle_del_device(cloud_host_item->valuestring, cloud_port_item->valueint, team_id, sn, vip);
	}
	else if(strcmp(action, "get_devices") == 0)
	{
		ret = handle_get_devices();
	}
	else if (strcmp(action, "modify_subnet") == 0)
	{
		ret = handle_modify_subnet(team_id, sn, new_subnet);
	}
	else if (strcmp(action, "start_vpn") == 0)
	{
		ret = handle_start_vpn(team_id, sn, vip);
	}
	else if (strcmp(action, "stop_vpn") == 0)
	{
		ret = handle_stop_vpn(team_id, sn);
	}
	else if (strcmp(action, "get_device_info") == 0)
	{
		ret = handle_get_device_info();
	}
	if (params)
	{
		cJSON_Delete(params);
	}
	if (manager)
	{
		cJSON_Delete(manager);
	}
	return ret;
}
