#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include "vlan-topic.h"
#include "ctrl-config.h"
#include "net_tool.h"
#include "my-device.h"
#include "system-config.h"
#include "vpn_tool.h"
#include "file_tool.h"
#include "str_tool.h"
#include "process_tool.h"
#include "monitor_tool.h"

using namespace std;

extern void skip_crlf(char*);

cJSON* handle_server_topic_checkService(cJSON* req_json, char* req_topic, char* ret_topic, char* add_topic, char* del_topic, char* from, cJSON* req_message_item)
{
	sprintf(ret_topic, "vppn/monitor/%s", from);
	cJSON* message_item = cJSON_CreateObject();
	//cJSON_Dump(req_json);
	cJSON* host_item = cJSON_GetObjectItem(req_message_item, "host");
	cJSON* port_item = cJSON_GetObjectItem(req_message_item, "port");
	time_t now_time = time(NULL);
	cJSON_AddNumberToObject(message_item, "format", 1);
	cJSON_AddNumberToObject(message_item, "lastTime", (int)now_time);
	int reachable = 0;
	if (host_item && port_item)
	{
		cJSON_AddStringToObject(message_item, "host", host_item->valuestring);
		cJSON_AddNumberToObject(message_item, "port", port_item->valueint);
		reachable = net_tool_tcp_port_reachable(host_item->valuestring, port_item->valueint);
	}
	if (reachable)
	{
		cJSON_AddNumberToObject(message_item, "reachable", 1);
	}
	else
	{
		cJSON_AddNumberToObject(message_item, "reachable", 0);
	}
	return message_item;
}

cJSON* handle_server_topic_serverLatency(cJSON* req_json, char* req_topic, char* ret_topic, char* add_topic, char* del_topic, char* from, cJSON* req_message_item)
{
	sprintf(ret_topic, "vppn/monitor/%s", from);
	//cJSON* message_item = cJSON_CreateObject();
	cJSON* message_item = NULL;
	cJSON* host_item = cJSON_GetObjectItem(req_message_item, "host");
	//cJSON* port_item = cJSON_GetObjectItem(req_json, "port");
	if (host_item)
	{
		//cJSON_AddStringToObject(message_item, "host", host_item->valuestring);
		cJSON* ip_array = cJSON_CreateArray();
		cJSON* ip_item = cJSON_CreateObject();
		cJSON_AddStringToObject(ip_item, "host", host_item->valuestring);
		cJSON_AddItemToArray(ip_array, ip_item);
		net_tool_ping_hosts3(ip_array, (char*)"host", (char*)"latency", (char*)"latency_list", 
				(char*)"loss", 5, 10);
		cJSON* ip_ret_item = cJSON_GetArrayItem(ip_array, 0);
		message_item = cJSON_Duplicate(ip_ret_item, 1);
		cJSON_Delete(ip_array);
		//cJSON_AddNumberToObject(message_item, "port", port_item->valueint);
		//reachable = net_tool_tcp_port_reachable(host_item->valuestring, port_item->valueint);
	}
	
	if (message_item)
	{
		time_t now_time = time(NULL);
		cJSON_AddNumberToObject(message_item, "format", 1);
		cJSON_AddNumberToObject(message_item, "lastTime", (int)now_time);
	}
	return message_item;
}

cJSON* handle_server_topic_checkProxy(cJSON* req_json, char* req_topic, char* ret_topic, char* add_topic, char* del_topic, char* from)
{
	sprintf(ret_topic, "vppn/monitor/%s", from);
	cJSON* message_item = cJSON_CreateObject();
	int reachable = 0;
	cJSON* proxy_item = vpn_tool_get_connectInfo();
	if (proxy_item)
	{
		cJSON* host_item = cJSON_GetObjectItem(proxy_item, "host");
		if (host_item)
		{
			cJSON_AddStringToObject(message_item, "host", host_item->valuestring);
			cJSON_AddNumberToObject(message_item, "port", 50069);
			reachable = net_tool_tcp_port_reachable(host_item->valuestring, 50069);
		}
		cJSON_Delete(proxy_item);
	}
	if (reachable)
	{
		cJSON_AddNumberToObject(message_item, "reachable", 1);
	}
	else
	{
		cJSON_AddNumberToObject(message_item, "reachable", 0);
	}
	
	if (message_item)
	{
		time_t now_time = time(NULL);
		cJSON_AddNumberToObject(message_item, "format", 1);
		cJSON_AddNumberToObject(message_item, "lastTime", (int)now_time);
	}
	return message_item;
}

cJSON* handle_server_topic_proxyLatency(cJSON* req_json, char* req_topic, char* ret_topic, char* add_topic, char* del_topic, char* from)
{
	sprintf(ret_topic, "vppn/monitor/%s", from);
	//cJSON* message_item = cJSON_CreateObject();
	cJSON* message_item = NULL;
	cJSON* proxy_item = vpn_tool_get_connectInfo();
	if (proxy_item)
	{
		cJSON* host_item = cJSON_GetObjectItem(proxy_item, "host");
		if (host_item)
		{
			//cJSON_AddStringToObject(message_item, "host", host_item->valuestring);
			cJSON* ip_array = cJSON_CreateArray();
			cJSON* ip_item = cJSON_CreateObject();
			cJSON_AddStringToObject(ip_item, "host", host_item->valuestring);
			cJSON_AddItemToArray(ip_array, ip_item);
			net_tool_ping_hosts3(ip_array, (char*)"host", (char*)"latency", (char*)"latency_list", 
					(char*)"loss", 5, 10);
			cJSON* ip_ret_item = cJSON_GetArrayItem(ip_array, 0);
			message_item = cJSON_Duplicate(ip_ret_item, 1);
			cJSON_Delete(ip_array);
		//cJSON_AddNumberToObject(message_item, "port", port_item->valueint);
		//reachable = net_tool_tcp_port_reachable(host_item->valuestring, port_item->valueint);
		}
		cJSON_Delete(proxy_item);
	}
	
	if (message_item)
	{
		time_t now_time = time(NULL);
		cJSON_AddNumberToObject(message_item, "format", 1);
		cJSON_AddNumberToObject(message_item, "lastTime", (int)now_time);
	}
	return message_item;
}

#if 0
cJSON* handle_topic_get_process()
{

}
#endif

cJSON* handle_topic_start_vpn(cJSON* req_json, char* req_topic, char* ret_topic, char* add_topic, char* del_topic)
{
	cJSON* ret = NULL;
	cJSON* teamIdItem = cJSON_GetObjectItem(req_json, "teamId");
	cJSON* idItem = cJSON_GetObjectItem(req_json, "id");
	cJSON* virtualIpItem = cJSON_GetObjectItem(req_json, "virtualIp");
	if (teamIdItem
			&& idItem
			)
	{
		sprintf(ret_topic, "vppn/%s", teamIdItem->valuestring);
		sprintf(add_topic, "vppn/%s", teamIdItem->valuestring);

		set_my_teamid(teamIdItem->valuestring);
		//strcpy(ret_topic, "vppn/12345678");

		//cJSON* res = net_tool_tcp_json_client_with_size((char*)"127.0.0.1", 4100, local_req, (char*)"json", strlen("json"));
		cJSON* res = vpn_tool_start_vpn(teamIdItem->valuestring);
		if (res)
		{
			ret = cJSON_CreateObject();
			cJSON_AddStringToObject(ret, "code", "200");
			cJSON_AddStringToObject(ret, "type", "start_vpn_response");
			cJSON_AddStringToObject(ret, "id", idItem->valuestring);
			char lanSubnet[100] = "";
			char wanSubnet[100] = "";
			get_my_lansubnet(lanSubnet);
			get_my_wansubnet(wanSubnet);
			cJSON* all_subnets = get_all_lan_subnets();
			if (all_subnets)
			{
				cJSON_AddItemToObject(ret, "lan_array", all_subnets);
			}
			cJSON_AddStringToObject(ret, "lanSubnet", lanSubnet);
			cJSON_AddStringToObject(ret, "wanSubnet", wanSubnet);
			if (virtualIpItem && virtualIpItem->valuestring)
			{
				cJSON_AddStringToObject(ret, "virtualIp", virtualIpItem->valuestring);
			}
			char my_id[100] = "";
			get_my_id(my_id);
			cJSON_AddStringToObject(ret, "sn", my_id);
			cJSON_Delete(res);
		}
	}
	return ret;
}

cJSON* handle_topic_check_vpn(cJSON* req_json, char* req_topic, char* ret_topic, char* add_topic, char* del_topic)
{
	cJSON* ret = NULL;
	cJSON* proxyIpItem = cJSON_GetObjectItem(req_json, "proxyIp");
	cJSON* idItem = cJSON_GetObjectItem(req_json, "id");
	cJSON* userIdItem = cJSON_GetObjectItem(req_json, "userId");
	if (idItem
			&&
			proxyIpItem
			&&
			userIdItem
			)
	{
		sprintf(ret_topic, "vppn/%s", userIdItem->valuestring);
		ret = cJSON_CreateObject();
		cJSON_AddStringToObject(ret, "code", "200");
		cJSON_AddStringToObject(ret, "type", "check_vpn_response");
		cJSON_AddStringToObject(ret, "id", idItem->valuestring);
		int reachable = net_tool_tcp_port_reachable(proxyIpItem->valuestring, 50069);
		char* pubkey = read_text((char*)"/tmp/vppn_pub.pem");
		if (pubkey)
		{
			cJSON_AddStringToObject(ret, "vpn_pub_key", pubkey);
			free(pubkey);
		}
		cJSON* ip_array = cJSON_CreateArray();
		cJSON* ip_item = cJSON_CreateObject();
		cJSON_AddStringToObject(ip_item, "host", (char*)"10.255.255.254");
		cJSON_AddItemToArray(ip_array, ip_item);
		net_tool_ping_hosts3(ip_array, (char*)"host", (char*)"latency", (char*)"latency_list", 
				(char*)"loss", 5, 10);
		cJSON* ip_ret_item = cJSON_GetArrayItem(ip_array, 0);
		cJSON_AddNumberToObject(ret, "vpn_port_reachable", reachable);
		cJSON* latency_item = cJSON_GetObjectItem(ip_ret_item, "latency");
		cJSON_AddNumberToObject(ret, "vpn_latency", latency_item->valueint);
		char leaderIp[100] = "";
		system_config_get("vppn_cloudhost", leaderIp);
		cJSON_AddStringToObject(ret, "leader_host", leaderIp);
		char sn[100] = "";
		get_my_id(sn);
		cJSON_AddStringToObject(ret, "sn", sn);
		char teamId[100] = "";
		get_my_teamid(teamId);
		cJSON_AddStringToObject(ret, "team_id", teamId);
		cJSON_Delete(ip_array);
	}
	return ret;
}

cJSON* handle_topic_nmap_scan(cJSON* req_json, char* req_topic, char* ret_topic, char* add_topic, char* del_topic)
{
	cJSON* ret = NULL;
	//cJSON* proxyIpItem = cJSON_GetObjectItem(req_json, "proxyIp");
	cJSON* idItem = cJSON_GetObjectItem(req_json, "id");
	cJSON* userIdItem = cJSON_GetObjectItem(req_json, "userId");
	if (idItem
			&&
			userIdItem
			)
	{
		sprintf(ret_topic, "vppn/%s", userIdItem->valuestring);
		ret = cJSON_CreateObject();
		char sn[100] = "";
		get_my_id(sn);
		cJSON_AddStringToObject(ret, "code", "200");
		cJSON_AddStringToObject(ret, "type", "nmap_scan_response");
		cJSON_AddStringToObject(ret, "id", idItem->valuestring);
		cJSON_AddStringToObject(ret, "sn", sn);
		cJSON* nmap_obj = monitor_tool_nmap();
		if (!nmap_obj)
		{
			nmap_obj = cJSON_CreateObject();
		}
		cJSON_AddItemToObject(ret, "nmap_scan", nmap_obj);
	}
	return ret;
}

cJSON* handle_topic_stop_vpn(cJSON* req_json, char* req_topic, char* ret_topic, char* add_topic, char* del_topic)
{
	cJSON* ret = NULL;
	cJSON* teamIdItem = cJSON_GetObjectItem(req_json, "teamId");
	cJSON* idItem = cJSON_GetObjectItem(req_json, "id");
	if (teamIdItem
			&& idItem
			)
	{
		sprintf(ret_topic, "vppn/%s", teamIdItem->valuestring);
		cJSON* res = vpn_tool_stop_vpn(teamIdItem->valuestring);
		if (res)
		{
			ret = cJSON_CreateObject();
			cJSON_AddStringToObject(ret, "code", "200");
			cJSON_AddStringToObject(ret, "type", "stop_vpn_response");
			cJSON_AddStringToObject(ret, "id", idItem->valuestring);
			char lanSubnet[100] = "";
			char wanSubnet[100] = "";
			get_my_lansubnet(lanSubnet);
			get_my_wansubnet(wanSubnet);
			cJSON_AddStringToObject(ret, "lanSubnet", lanSubnet);
			cJSON_AddStringToObject(ret, "wanSubnet", wanSubnet);
			char my_id[100] = "";
			get_my_id(my_id);
			cJSON_AddStringToObject(ret, "sn", my_id);
			cJSON_Delete(res);
		}
		//unset_my_teamid();
		//cJSON_Delete(local_req);
	}
	return ret;
}

cJSON* handle_topic_del_member(cJSON* req_json, char* req_topic, char* ret_topic, char* add_topic, char* del_topic)
{
	cJSON* ret = NULL;
	cJSON* teamIdItem = cJSON_GetObjectItem(req_json, "teamId");
	cJSON* idItem = cJSON_GetObjectItem(req_json, "id");
	char virtualIp[100] = "";
	get_my_virtualip(virtualIp);
	if (teamIdItem
			&& idItem
			)
	{
		char virtualIp[100] = "";
		net_tool_get_if_ip((char*)"site0", virtualIp);
		cJSON* res = vpn_tool_stop_vpn(teamIdItem->valuestring);
		if (res)
		{	
			sprintf(ret_topic, "vppn/%s", teamIdItem->valuestring);
			sprintf(del_topic, "vppn/%s", teamIdItem->valuestring);
			ret = cJSON_CreateObject();
			cJSON_AddStringToObject(ret, "code", "200");
			cJSON_AddStringToObject(ret, "type", "del_member_response");
			cJSON_AddStringToObject(ret, "id", idItem->valuestring);
			char my_id[100] = "";
			get_my_id(my_id);
			cJSON_AddStringToObject(ret, "sn", my_id);
			cJSON_AddStringToObject(ret, "virtualIp", virtualIp);
			cJSON_Delete(res);
		}
		unset_my_teamid();
	}
	return ret;
}

cJSON* handle_topic_add_whitelist(cJSON* req_json, char* req_topic, char* ret_topic, char* add_topic, char* del_topic)
{
	cJSON* ret = NULL;
	cJSON* teamIdItem = cJSON_GetObjectItem(req_json, "teamId");
	cJSON* userIdItem = cJSON_GetObjectItem(req_json, "userId");
	cJSON* idItem = cJSON_GetObjectItem(req_json, "id");
	cJSON* listItem = cJSON_GetObjectItem(req_json, "list");
	printf("enter add whitelist\n");
	if (teamIdItem
			&& idItem
			)
	{
		cJSON* res = vpn_tool_add_whitelist(teamIdItem->valuestring, listItem);
		if (res)
		{
			sprintf(ret_topic, "vppn/%s", userIdItem->valuestring);
			ret = cJSON_CreateObject();
			cJSON_AddStringToObject(ret, "code", "200");
			cJSON_AddStringToObject(ret, "type", "add_whitelist_response");
			cJSON_AddStringToObject(ret, "id", idItem->valuestring);
			cJSON_Delete(res);
		}
	}
	return ret;
}

cJSON* handle_topic_del_whitelist(cJSON* req_json, char* req_topic, char* ret_topic, char* add_topic, char* del_topic)
{
	cJSON* ret = NULL;
	cJSON* teamIdItem = cJSON_GetObjectItem(req_json, "teamId");
	cJSON* idItem = cJSON_GetObjectItem(req_json, "id");
	cJSON* userIdItem = cJSON_GetObjectItem(req_json, "userId");
	cJSON* listItem = cJSON_GetObjectItem(req_json, "list");
	if (teamIdItem
			&& idItem
			)
	{
		cJSON* res = vpn_tool_del_whitelist(teamIdItem->valuestring, listItem);
		if (res)
		{
			sprintf(ret_topic, "vppn/%s", userIdItem->valuestring);
			ret = cJSON_CreateObject();
			cJSON_AddStringToObject(ret, "code", "200");
			cJSON_AddStringToObject(ret, "type", "del_whitelist_response");
			cJSON_AddStringToObject(ret, "id", idItem->valuestring);
			cJSON_Delete(res);
		}
	}
	return ret;
}

cJSON* handle_topic_get_whitelist(cJSON* req_json, char* req_topic, char* ret_topic, char* add_topic, char* del_topic)
{
	cJSON* ret = NULL;
	cJSON* teamIdItem = cJSON_GetObjectItem(req_json, "teamId");
	cJSON* idItem = cJSON_GetObjectItem(req_json, "id");
	cJSON* userIdItem = cJSON_GetObjectItem(req_json, "userId");
	if (teamIdItem
			&& idItem
			)
	{
		ret = cJSON_CreateObject();
		cJSON_AddStringToObject(ret, "code", "200");
		cJSON_AddStringToObject(ret, "type", "get_whitelist_response");
		cJSON_AddStringToObject(ret, "id", idItem->valuestring);
		cJSON* res = vpn_tool_get_whitelist(teamIdItem->valuestring);
		if (res)
		{
			cJSON* list_item = cJSON_GetObjectItem(res, "list");
			if (list_item)
			{
				cJSON_AddItemToObject(ret, "list", cJSON_Duplicate(list_item, 1));
			}
			else
			{
				cJSON_AddItemToObject(ret, "list", cJSON_CreateArray());
			}
			sprintf(ret_topic, "vppn/%s", userIdItem->valuestring);
			cJSON_Delete(res);
		}
	}
	return ret;
}

cJSON* handle_topic_update_proxy_key(cJSON* req_json, char* req_topic, char* ret_topic, char* add_topic, char* del_topic)
{
	cJSON* ret = NULL;
	cJSON* proxyIpItem = cJSON_GetObjectItem(req_json, "proxyIp");
	if (proxyIpItem)
	{
		cJSON* res = vpn_tool_reload_member(1, proxyIpItem->valuestring);
		if (res)
		{
			cJSON_Delete(res);
		}
	}
	return ret;
}

cJSON* handle_topic_proxy_stop_event(cJSON* req_json, char* req_topic, char* ret_topic, char* add_topic, char* del_topic)
{
	cJSON* ret = NULL;
	cJSON* proxyIpItem = cJSON_GetObjectItem(req_json, "proxyIp");
	if (proxyIpItem)
	{
		//set_http_manager_server_to_local(proxyIpItem->valuestring, "443");
		cJSON* res = vpn_tool_reload_member(1, proxyIpItem->valuestring);
		if (res)
		{
			cJSON_Delete(res);
		}
	}
	return ret;
}

cJSON* handle_topic_changeservice_event(cJSON* req_json, char* req_topic, char* ret_topic, char* add_topic, char* del_topic)
{
	cJSON* ret = NULL;
	cJSON* proxyIpItem = cJSON_GetObjectItem(req_json, "leaderIP");
	if (proxyIpItem)
	{
		set_http_manager_server_to_local(proxyIpItem->valuestring, (char*)"443");
		cJSON* res = vpn_tool_reload_member(2, proxyIpItem->valuestring);
		if (res)
		{
			cJSON_Delete(res);
		}
	}
	return ret;
}

cJSON* handle_topic_get_traffic(cJSON* req_json, char* req_topic, char* ret_topic, char* add_topic, char* del_topic)
{
	cJSON* ret = NULL;
	cJSON* teamIdItem = cJSON_GetObjectItem(req_json, "teamId");
	cJSON* idItem = cJSON_GetObjectItem(req_json, "id");
	cJSON* userIdItem = cJSON_GetObjectItem(req_json, "userId");
	if (teamIdItem
			&& idItem
			)
	{
		ret = cJSON_CreateObject();
		cJSON_AddStringToObject(ret, "code", "200");
		cJSON_AddStringToObject(ret, "type", "get_traffic_response");
		cJSON_AddStringToObject(ret, "id", idItem->valuestring);
		cJSON* res = vpn_tool_get_vpn_traffic();
		if (res)
		{
			cJSON_AddItemToObject(ret, "list", cJSON_Duplicate(res, 1));
			cJSON_Delete(res);
		}
		else
		{
			cJSON_AddItemToObject(ret, "list", cJSON_CreateArray());
		}
		sprintf(ret_topic, "vppn/%s", userIdItem->valuestring);
	}
	return ret;
}

void set_auth_header(char* header_buf)
{
	char http_username[100] = "";
	char http_password[100] = "";
	char auth_in_buf[100] = ""; 
	char auth_out_buf[100] = ""; 
	system_config_get("http_username", http_username);
	system_config_get("http_passwd", http_password);
	sprintf(auth_in_buf, "%s:%s", http_username, http_password);
	//base64_encode((const unsigned char*)auth_in_buf, auth_out_buf, strlen(auth_in_buf));
	str_tool_base64_encode((const unsigned char*)auth_in_buf, strlen(auth_in_buf), auth_out_buf);
	sprintf(header_buf, "Authorization: Basic %s\r\n", auth_out_buf);
	return;
}

void handle_http_multi_login()
{
	int recv_len = 0;
	char change_header[200] = "";
	char auth_header[100] = "";
	set_auth_header(auth_header);
	sprintf(change_header, "Referer: http://127.0.0.1/multi_login.html\r\n%s", auth_header);
	char *ret = net_tool_http_client2(0, (char*)"127.0.0.1", 80, (char*)"/change_user.html", NULL, 0, change_header, &recv_len);
	if (ret)
	{
		free(ret);
	}
	ret = net_tool_http_client2(0, (char*)"127.0.0.1", 80, (char*)"/change_user.html", NULL, 0, change_header, &recv_len);
	if (ret)
	{
		free(ret);
	}
	return;
}

cJSON* handle_server_topic_http(cJSON* req_json, char* ret_topic)
{
	cJSON* ret = cJSON_CreateObject();

	cJSON* methodItem = cJSON_GetObjectItem(req_json, "method");
	cJSON* uriItem = cJSON_GetObjectItem(req_json, "url");
	cJSON* bodyItem = cJSON_GetObjectItem(req_json, "body");
	//cJSON* ret_topicItem = cJSON_GetObjectItem(req_json, "ret_topic");
	printf("methodItem= %p, uriItem = %p, bodyItem=%p\n", methodItem, uriItem, bodyItem);
	char* http_ret = NULL;
	if (methodItem 
			//&& ret_topicItem 
			&& uriItem 
			&& bodyItem)
	{
		int method;
		char auth_header[200];

		if(strcmp(methodItem->valuestring, "get") == 0)
		{
			method = 0;
		}
		else
		{
			method = 1;
		}
		set_auth_header(auth_header);
		int recv_len = 0;
		char *response = net_tool_http_client2(method, (char*)"127.0.0.1", 80, uriItem->valuestring, bodyItem->valuestring, strlen(bodyItem->valuestring), auth_header, &recv_len);
		printf("http response = %s\n", response);
		if (response)
		{
			if (strstr(response, "unauth.cgi"))
			{
				free(response);
				response = net_tool_http_client2(method, (char*)"127.0.0.1", 80, uriItem->valuestring, bodyItem->valuestring, strlen(bodyItem->valuestring), auth_header, &recv_len);
			}
			else if(strstr(response, "multi_login.html"))
			{
				free(response);
				handle_http_multi_login();
				response = net_tool_http_client2(method, (char*)"127.0.0.1", 80, uriItem->valuestring, bodyItem->valuestring, strlen(bodyItem->valuestring), auth_header, &recv_len);
			}

			http_ret = response;
		}
		//strcpy(ret_topic, ret_topicItem->valuestring);
	}

	if (http_ret)
	{
		cJSON_AddStringToObject(ret, "code", "200");
		cJSON_AddStringToObject(ret, "response", http_ret);
		free(http_ret);
	}
	else
	{
		cJSON_AddStringToObject(ret, "code", "201");
		cJSON_AddStringToObject(ret, "response", "");
	}
	return ret;
}

cJSON* handle_topic_get_direct_list(cJSON* req_json, char* req_topic, char* ret_topic, char* add_topic, char* del_topic)
{
	cJSON* ret = cJSON_CreateObject();
	cJSON* teamIdItem = cJSON_GetObjectItem(req_json, "teamId");
	cJSON* idItem = cJSON_GetObjectItem(req_json, "id");
	cJSON* userIdItem = cJSON_GetObjectItem(req_json, "userId");
	if (teamIdItem
			&& idItem
			)
	{
		cJSON* list_item = NULL;
		cJSON* res = vpn_tool_get_direct_list(teamIdItem->valuestring);
		if (res)
		{
			cJSON* res_list_item = cJSON_GetObjectItem(res, "direct_list");
			if (res_list_item)
			{
				list_item = cJSON_Duplicate(res_list_item, 1);
			}
			cJSON_Delete(res);
		}
		if (!list_item)
		{
			list_item = cJSON_CreateArray();
		}
		cJSON_AddItemToObject(ret, "direct_list", list_item);
		sprintf(ret_topic, "vppn/%s", userIdItem->valuestring);
	}
	cJSON_AddStringToObject(ret, "code", "200");
	cJSON_AddStringToObject(ret, "type", "get_direct_list_response");
	cJSON_AddStringToObject(ret, "id", idItem->valuestring);
	return ret;
}


void parse_subnet_for_form(char* subnet, char* out)
{
	char *ptr = strchr(subnet, '/');
	ptr -= 1;
	if (*ptr == '\\')
	{
		ptr -= 1;
	}
	ptr -= 1;
	strncpy(out, subnet, ptr - subnet);
}

void modify_subnet(char* new_subnet, char* old_subnet)
{
	char cmd_buf[100];
	char new_form_subnet_buf[100] = "";
	char old_form_subnet_buf[100] = "";
	char dhcp_start[100] = "";
	char dhcp_end[100] = "";
	parse_subnet_for_form(new_subnet, new_form_subnet_buf);
	parse_subnet_for_form(old_subnet, old_form_subnet_buf);
	char new_lan_ip[100];
	char old_lan_ip[100];
	sprintf(new_lan_ip, "%s.1", new_form_subnet_buf);
	sprintf(old_lan_ip, "%s.1", old_form_subnet_buf);
	sprintf(dhcp_start, "%s.2", new_form_subnet_buf);
	sprintf(dhcp_end, "%s.254", new_form_subnet_buf);
	sprintf(cmd_buf, "config set old_lan_ipaddr=%s", old_lan_ip);
	printf("%s\n", cmd_buf);
	system(cmd_buf);
	sprintf(cmd_buf, "config set lan_dhcp=1");
	printf("%s\n", cmd_buf);
	system(cmd_buf);
	sprintf(cmd_buf, "config set lan_ipaddr=%s", new_lan_ip);
	printf("%s\n", cmd_buf);
	system(cmd_buf);
	sprintf(cmd_buf, "config set dhcp_start=%s", dhcp_start);
	printf("%s\n", cmd_buf);
	system(cmd_buf);
	sprintf(cmd_buf, "config set dhcp_end=%s", dhcp_end);
	printf("%s\n", cmd_buf);
	system(cmd_buf);
	sprintf(cmd_buf, "config commit");
	printf("%s\n", cmd_buf);
	system(cmd_buf);
	sprintf(cmd_buf, "/etc/init.d/net-lan restart");
	printf("%s\n", cmd_buf);
	system(cmd_buf);
	return;
}

cJSON* handle_topic_modify_subnet(cJSON* req_json, char* req_topic, char* ret_topic, char* add_topic, char* del_topic)
{
	cJSON* ret = NULL;
	cJSON* teamIdItem = cJSON_GetObjectItem(req_json, "teamId");
	cJSON* idItem = cJSON_GetObjectItem(req_json, "id");
	cJSON* lanSubnetItem = cJSON_GetObjectItem(req_json, "lanSubnet");
	cJSON* modify_arrayItem = cJSON_GetObjectItem(req_json, "modify_array");
	if (teamIdItem
			&& idItem
			)
	{
		char wanSubnet[100] = "";
		char lanSubnet[100] = "";
		char vip[100] = "";
		get_my_lansubnet(lanSubnet);
		net_tool_get_if_ip((char*)"site0", vip);
		get_my_wansubnet(wanSubnet);
		if (!wanSubnet[0])
		{
			net_tool_get_if_subnet((char*)"ppp0", wanSubnet);
		}
		ret = cJSON_CreateObject();
		char my_id[100] = "";
		get_my_id(my_id);
		sprintf(ret_topic, "vppn/%s", teamIdItem->valuestring);
		cJSON_AddStringToObject(ret, "id", idItem->valuestring);
		cJSON_AddStringToObject(ret, "type", "modify_subnet_response");
		cJSON_AddStringToObject(ret, "sn", my_id);
		cJSON_AddStringToObject(ret, "virtualIp", vip);
		cJSON_AddStringToObject(ret, "lanSubnet", lanSubnetItem->valuestring);
		if (modify_arrayItem)
		{
			set_lan_subnets(modify_arrayItem);
		}
		else if (lanSubnetItem)
		{
			modify_subnet(lanSubnetItem->valuestring, lanSubnet);
			cJSON_AddStringToObject(ret, "code", "200");
		}
#if 0
		else if ((strcmp(lanSubnet, lanSubnetItem->valuestring) == 0)
				|| (strcmp(lanSubnet, lanSubnetItem->valuestring) == 0) 
				|| (strncmp(lanSubnetItem->valuestring, "192.168.", strlen("192.168.")) != 0))
		{
			cJSON_AddStringToObject(ret, "code", "201");
		}
		else
		{
			modify_subnet(lanSubnetItem->valuestring, lanSubnet);
			cJSON_AddStringToObject(ret, "code", "200");
		}
#endif
	}
	return ret;
}

cJSON* handle_topic_member_response(cJSON* req_json, char* req_topic, char* ret_topic, char* add_topic, char* del_topic)
{
	cJSON* sn_item = cJSON_GetObjectItem(req_json, "sn");
	char my_id[100] = "";
	get_my_id(my_id);
	if (sn_item && sn_item->valuestring)
	{
		cJSON* res = vpn_tool_reload_member(0, NULL);
		if (res)
		{
			cJSON_Delete(res);
		}
	}
	return NULL;
}

cJSON* handle_server_topic_monitor_cpu(cJSON* req_json, char* req_topic, char* ret_topic, char* add_topic, char* del_topic, char* from)
{
	double avg_load = 0;
	sprintf(ret_topic, "vppn/monitor/%s", from);
	cJSON* message_item = cJSON_CreateObject();
	cJSON* cpus = GetCPUJSON2(&avg_load);
	cJSON_AddItemToObject(message_item, "cpus", cpus);
	cJSON_AddNumberToObject(message_item, "format", 1);
	cJSON_AddNumberToObject(message_item, "cpuAvg", avg_load);
	time_t now_time = time(NULL);
	cJSON_AddNumberToObject(message_item, "lastTime", (int)now_time);
	return message_item;
}

cJSON* handle_server_topic_monitor_memory(cJSON* req_json, char* req_topic, char* ret_topic, char* add_topic, char* del_topic, char* from)
{
	double mem_usage = 0;
	unsigned int total_mem = 0;
	unsigned int free_mem = 0;
	mem_usage = Get_Mem_Info(&total_mem, &free_mem);
	sprintf(ret_topic, "vppn/monitor/%s", from);
	cJSON* message_item = cJSON_CreateObject();
	cJSON_AddNumberToObject(message_item, "format", 1);
	cJSON_AddNumberToObject(message_item, "totalMemory", total_mem);
	cJSON_AddNumberToObject(message_item, "freeMemory", free_mem);
	cJSON_AddNumberToObject(message_item, "useMemory", total_mem - free_mem);
	cJSON_AddNumberToObject(message_item, "usageMemory", mem_usage);
	time_t now_time = time(NULL);
	cJSON_AddNumberToObject(message_item, "lastTime", (int)now_time);
	return message_item;
}

cJSON* handle_server_topic_monitor_vpntraffic(cJSON* req_json, char* req_topic, char* ret_topic, char* add_topic, char* del_topic, char* from)
{
	//sprintf(ret_topic, "vppn/%s", from);
	sprintf(ret_topic, "vppn/monitor/%s", from);
	cJSON* message_item = cJSON_CreateObject();
	time_t now_time = time(NULL);
	cJSON_AddNumberToObject(message_item, "format", 1);
	cJSON_AddNumberToObject(message_item, "lastTime", (int)now_time);
	cJSON* members = NULL;
	cJSON* res = vpn_tool_get_members_traffic();
	if (res)
	{
		cJSON* members_item = cJSON_GetObjectItem(res, "members");
		if (members_item)
		{
			members = cJSON_Duplicate(members_item, 1);
		}
		cJSON_Delete(res);
	}

	if (members)
	{
		cJSON_AddItemToObject(message_item, "members", members);
	}
	else
	{
		cJSON_AddItemToObject(message_item, "members", cJSON_CreateArray());
	}
	return message_item;
}

cJSON* handle_server_topic_monitor_vpnping(cJSON* req_json, char* req_topic, char* ret_topic, char* add_topic, char* del_topic, char* from)
{
	//sprintf(ret_topic, "vppn/%s", from);
	sprintf(ret_topic, "vppn/monitor/%s", from);
	cJSON* message_item = cJSON_CreateObject();
	time_t now_time = time(NULL);
	cJSON_AddNumberToObject(message_item, "format", 1);
	cJSON_AddNumberToObject(message_item, "lastTime", (int)now_time);
	cJSON* members = NULL;
	cJSON* res = vpn_tool_get_members_ping();
	if (res)
	{
		cJSON* members_item = cJSON_GetObjectItem(res, "members");
		if (members_item)
		{
			members = cJSON_Duplicate(members_item, 1);
		}
		cJSON_Delete(res);
	}

	if (members)
	{
		cJSON_AddItemToObject(message_item, "members", members);
	}
	else
	{
		cJSON_AddItemToObject(message_item, "members", cJSON_CreateArray());
	}
	return message_item;
}

cJSON* handle_server_topic_monitor_vpnbandwidth(cJSON* req_json, char* req_topic, char* ret_topic, char* add_topic, char* del_topic, char* from, char* ip)
{
	//sprintf(ret_topic, "vppn/%s", from);
	sprintf(ret_topic, "vppn/monitor/%s", from);
	cJSON* message_item = cJSON_CreateObject();
	time_t now_time = time(NULL);
	cJSON_AddNumberToObject(message_item, "format", 1);
	cJSON_AddNumberToObject(message_item, "lastTime", (int)now_time);
	int upload;
	int download;
	vpn_tool_get_member_bandwidth(ip, &upload, &download);
	cJSON_AddNumberToObject(message_item, "upload_bandwidth", upload);
	cJSON_AddNumberToObject(message_item, "download_bandwidth", download);
	return message_item;
}

#if 0
cJSON* handle_server_topic_monitor_equipmentInfo(cJSON* req_json, char* req_topic, char* ret_topic, char* add_topic, char* del_topic, char* from)
{
	sprintf(ret_topic, "vppn/%s", from);
	cJSON* message_item = cJSON_CreateObject();
	time_t now_time = time(NULL);
	cJSON_AddNumberToObject(message_item, "format", 1);
	cJSON_AddNumberToObject(message_item, "lastTime", (int)now_time);
	return message_item;
}
#endif

cJSON* handle_server_topic_monitor_link(cJSON* req_json, char* req_topic, char* ret_topic, char* add_topic, char* del_topic, char* from)
{
	//sprintf(ret_topic, "vppn/%s", from);
	sprintf(ret_topic, "vppn/monitor/%s", from);
	cJSON* message_item = cJSON_CreateObject();
	time_t now_time = time(NULL);
	cJSON_AddNumberToObject(message_item, "format", 1);
	cJSON_AddNumberToObject(message_item, "lastTime", (int)now_time);
	cJSON* attach = get_attach_devices();
	cJSON_AddItemToObject(message_item, "links", attach);
	return message_item;
}

cJSON* handle_server_topic_monitor_equipmentInfo(cJSON* req_json, char* req_topic, char* ret_topic, char* add_topic, char* del_topic, char* from)
{
	//sprintf(ret_topic, "vppn/%s", from);
	sprintf(ret_topic, "vppn/monitor/%s", from);
	cJSON* message_item = cJSON_CreateObject();
	time_t now_time = time(NULL);
	cJSON_AddNumberToObject(message_item, "format", 1);
	cJSON_AddNumberToObject(message_item, "lastTime", (int)now_time);
	cJSON_AddStringToObject(message_item, "type", "Router");
    /* MAC address */
	char mac[100] = "";
	net_tool_get_if_hwaddr((char*)"br0", mac);
	cJSON_AddStringToObject(message_item, "mac", mac);

	/* IP address */
	char ip[100] = "";
	net_tool_get_if_ip((char*)"br0", ip);
	cJSON_AddStringToObject(message_item, "ip", ip);

    /* wan MAC address */
	char wan_mac[100] = "";
	net_tool_get_if_hwaddr((char*)"brwan", wan_mac);
	cJSON_AddStringToObject(message_item, "wan_mac", wan_mac);

	/* wan IP address */
	char wan_ip[100] = "";
	net_tool_get_if_ip((char*)"brwan", wan_ip);
	cJSON_AddStringToObject(message_item, "wan_ip", wan_ip);

	cJSON* all_subnets = get_all_lan_subnets();
	if (all_subnets)
	{
		cJSON_AddItemToObject(message_item, "lan_subnets", all_subnets);
	}
    /* get firmware version */
	char * firmware = read_text((char*)"/firmware_version");
	if (firmware)
	{
		skip_crlf(firmware);
		cJSON_AddStringToObject(message_item, "version", firmware);
		free(firmware);
	}
	else
	{
		cJSON_AddStringToObject(message_item, "version", "unknown");
	}

    /* get hardware version */
    char * hardware = read_text((char*)"/hardware_version");
	if (hardware)
	{
		skip_crlf(hardware);
		cJSON_AddStringToObject(message_item, "equipmentName", hardware);
		free(hardware);
	}
    else
	{
		cJSON_AddStringToObject(message_item, "equipmentName", "unknown");
	}

    cJSON *other_json = cJSON_CreateObject();
    char serial[32];
    get_my_id(serial);
    cJSON_AddStringToObject(other_json, "serial", serial);

    
    char geoip_host[128] = "52.25.79.82";
	int geoip_port = 10000;
	char geoip_uri[100] = "/geoip_json.php";

	cJSON* geoip_res = net_tool_http_json_client2(0, geoip_host, geoip_port, geoip_uri, NULL, NULL);
	if (geoip_res)
	{
	}
	else
	{
		geoip_res = cJSON_CreateObject();
	}
    cJSON_AddItemToObject(other_json, "geoip", geoip_res);
    cJSON_AddItemToObject(message_item, "other", other_json);
	return message_item;
}

cJSON* handle_server_topic_monitor_temprature(cJSON* req_json, char* req_topic, char* ret_topic, char* add_topic, char* del_topic, char* from)
{
	//sprintf(ret_topic, "vppn/%s", from);
	sprintf(ret_topic, "vppn/monitor/%s", from);
	cJSON* message_item = cJSON_CreateObject();
	time_t now_time = time(NULL);
	char* cmd_res = process_tool_run_cmd((char*)"cat /sys/class/thermal/thermal_zone0/temp");
	if (cmd_res)
	{
		skip_crlf(cmd_res);
		cJSON_AddNumberToObject(message_item, "temperature", atoi(cmd_res));
		free(cmd_res);
	}
	else
	{
		cJSON_AddNumberToObject(message_item, "temperature", 0);
	}
	cJSON_AddNumberToObject(message_item, "format", 1);
	cJSON_AddNumberToObject(message_item, "lastTime", (int)now_time);
	return message_item;
}

cJSON* handle_mqtt_topic_json(cJSON* req_json, char* req_topic, char* ret_topic, char* add_topic, char* del_topic)
{
	cJSON* ret = NULL;
	cJSON* type_item = cJSON_GetObjectItem(req_json, "type");
	if (type_item)
	{
		if (type_item->valuestring)
		{
			printf("get request:%s\n", type_item->valuestring);
			if (strcmp(type_item->valuestring, "start_vpn_request") == 0)
			{
				ret = handle_topic_start_vpn(req_json, req_topic, ret_topic, add_topic, del_topic);
			}
			else if (strcmp(type_item->valuestring, "stop_vpn_request") == 0)
			{
				ret = handle_topic_stop_vpn(req_json, req_topic, ret_topic, add_topic, del_topic);
			}
			else if (strcmp(type_item->valuestring, "del_member_request") == 0)
			{
				ret = handle_topic_del_member(req_json, req_topic, ret_topic, add_topic, del_topic);
			}
			else if (strcmp(type_item->valuestring, "add_whitelist_request") == 0)
			{
				ret = handle_topic_add_whitelist(req_json, req_topic, ret_topic, add_topic, del_topic);
			}
			else if (strcmp(type_item->valuestring, "del_whitelist_request") == 0)
			{
				ret = handle_topic_del_whitelist(req_json, req_topic, ret_topic, add_topic, del_topic);
			}
			else if (strcmp(type_item->valuestring, "get_whitelist_request") == 0)
			{
				ret = handle_topic_get_whitelist(req_json, req_topic, ret_topic, add_topic, del_topic);
			}
			else if (strcmp(type_item->valuestring, "get_traffic_request") == 0)
			{
				ret = handle_topic_get_traffic(req_json, req_topic, ret_topic, add_topic, del_topic);
			}
			else if (strcmp(type_item->valuestring, "proxy_key_update_event") == 0)
			{
				ret = handle_topic_update_proxy_key(req_json, req_topic, ret_topic, add_topic, del_topic);
			}
			else if (strcmp(type_item->valuestring, "proxy_stop_event") == 0)
			{
				ret = handle_topic_proxy_stop_event(req_json, req_topic, ret_topic, add_topic, del_topic);
			}
			else if (strcmp(type_item->valuestring, "changeservice_event") == 0)
			{
				ret = handle_topic_changeservice_event(req_json, req_topic, ret_topic, add_topic, del_topic);
			}
			else if (strcmp(type_item->valuestring, "check_vpn_request") == 0)
			{
				ret = handle_topic_check_vpn(req_json, req_topic, ret_topic, add_topic, del_topic);
			}
			else if (strcmp(type_item->valuestring, "modify_subnet_request") == 0)
			{
				ret = handle_topic_modify_subnet(req_json, req_topic, ret_topic, add_topic, del_topic);
				//need restart tinc
				char team_id[100] = "";
				get_my_teamid(team_id);
				if (team_id[0])
				{
					cJSON* res = NULL;
				   	res = vpn_tool_stop_vpn(team_id);
					if (res)
					{
						cJSON_Delete(res);
					}
					sleep(3);
					res = vpn_tool_start_vpn(team_id);
					if (res)
					{
						cJSON_Delete(res);
					}
				}
			}
			else if (strcmp(type_item->valuestring, "start_vpn_response") == 0 || strcmp(type_item->valuestring, "del_member_response") == 0)
			{
				ret = handle_topic_member_response(req_json, req_topic, ret_topic, add_topic, del_topic);
			}
			else if (strcmp(type_item->valuestring, "get_direct_list_request") == 0)
			{
				ret = handle_topic_get_direct_list(req_json, req_topic, ret_topic, add_topic, del_topic);
			}
			else if (strcmp(type_item->valuestring, "nmap_scan_request") == 0)
			{
				ret = handle_topic_nmap_scan(req_json, req_topic, ret_topic, add_topic, del_topic);
			}
		}
	}
	else
	{
		cJSON* business_item = cJSON_GetObjectItem(req_json, "businessType");
		cJSON* apptype_item = cJSON_GetObjectItem(req_json, "appType");
		cJSON* from_item = cJSON_GetObjectItem(req_json, "from");
		cJSON* id_item = cJSON_GetObjectItem(req_json, "id");
		cJSON* message_item = cJSON_GetObjectItem(req_json, "message");
		cJSON* message_type_item = cJSON_GetObjectItem(req_json, "messageType");
		cJSON* server_ret = NULL;
		if (business_item 
				&& apptype_item 
				&& from_item
				&& message_item
				&& message_type_item
				)
		{
			char my_id[100] = "";
			char my_team_id[100] = "";
			get_my_id(my_id);
			get_my_teamid(my_team_id);
			server_ret = cJSON_CreateObject();
			cJSON_AddStringToObject(server_ret, "appType", apptype_item->valuestring);
			cJSON_AddStringToObject(server_ret, "businessType", business_item->valuestring);
			cJSON_AddStringToObject(server_ret, "id", id_item->valuestring);
			cJSON_AddStringToObject(server_ret, "from", my_id);
			cJSON_AddStringToObject(server_ret, "messageType", "res");
			if (strcmp(business_item->valuestring, "0") == 0)
			{
				cJSON* obj = cJSON_Parse(message_item->valuestring);
				if (obj)
				{
					cJSON* ip_item = cJSON_GetObjectItem(obj, "ip");
					if (!ip_item)
					{
						ip_item = cJSON_GetObjectItem(obj, "id");
					}
					cJSON* port_item = cJSON_GetObjectItem(obj, "port");
					set_http_manager_server_to_local(ip_item->valuestring, port_item->valuestring);
					vpn_upload_key_once(my_id);
					cJSON_Delete(obj);
				}
			}
			/* team deleted by team manager, from cloud */
			else if (strcmp(business_item->valuestring, "5") == 0)
			{
				cJSON* obj = cJSON_Parse(message_item->valuestring);
				if (obj)
				{
					cJSON* team_item = cJSON_GetObjectItem(obj, "teamId");
					if (strcmp(my_team_id, team_item->valuestring) == 0)
					{
						cJSON* res = vpn_tool_stop_vpn(team_item->valuestring);
						if (res)
						{
							cJSON_Delete(res);
						}
						unset_my_teamid();
					}
					cJSON_Delete(obj);
				}
			}
			else if (strcmp(business_item->valuestring, "monitor:cpu") == 0)
			{
				char *str_response = NULL;
				cJSON* ret_message_item = handle_server_topic_monitor_cpu(req_json, req_topic, ret_topic, add_topic, del_topic, from_item->valuestring);
				if (ret_message_item)
				{
					str_response = cJSON_PrintUnformatted(ret_message_item);
					if (str_response)
					{
						cJSON_AddStringToObject(server_ret, "message", str_response);
						//cJSON_AddStringToObject(server_ret, "message", "hello");
						free(str_response);
					}
					cJSON_Delete(ret_message_item);
				}
			}
			else if (strcmp(business_item->valuestring, "monitor:memory") == 0)
			{	
				char *str_response = NULL;
				cJSON* ret_message_item = handle_server_topic_monitor_memory(req_json, req_topic, ret_topic, add_topic, del_topic, from_item->valuestring);
				if (ret_message_item)
				{
					str_response = cJSON_PrintUnformatted(ret_message_item);
					if (str_response)
					{
						cJSON_AddStringToObject(server_ret, "message", str_response);
						//cJSON_AddStringToObject(server_ret, "message", "hello");
						free(str_response);
					}
					cJSON_Delete(ret_message_item);
				}
			}
			else if (strcmp(business_item->valuestring, "monitor:equipmentInfo") == 0)
			{	
				char *str_response = NULL;
				cJSON* ret_message_item = handle_server_topic_monitor_equipmentInfo(req_json, req_topic, ret_topic, add_topic, del_topic, from_item->valuestring);
				if (ret_message_item)
				{
					str_response = cJSON_PrintUnformatted(ret_message_item);
					if (str_response)
					{
						cJSON_AddStringToObject(server_ret, "message", str_response);
						//cJSON_AddStringToObject(server_ret, "message", "hello");
						free(str_response);
					}
					cJSON_Delete(ret_message_item);
				}
			}
			else if (strcmp(business_item->valuestring, "monitor:link") == 0)
			{	
				char *str_response = NULL;
				cJSON* ret_message_item = handle_server_topic_monitor_link(req_json, req_topic, ret_topic, add_topic, del_topic, from_item->valuestring);
				if (ret_message_item)
				{
					str_response = cJSON_PrintUnformatted(ret_message_item);
					if (str_response)
					{
						cJSON_AddStringToObject(server_ret, "message", str_response);
						//cJSON_AddStringToObject(server_ret, "message", "hello");
						free(str_response);
					}
					cJSON_Delete(ret_message_item);
				}
			}
			else if (strcmp(business_item->valuestring, "monitor:temperature") == 0)
			{	
				char *str_response = NULL;
				cJSON* ret_message_item = handle_server_topic_monitor_temprature(req_json, req_topic, ret_topic, add_topic, del_topic, from_item->valuestring);
				if (ret_message_item)
				{
					str_response = cJSON_PrintUnformatted(ret_message_item);
					if (str_response)
					{
						cJSON_AddStringToObject(server_ret, "message", str_response);
						//cJSON_AddStringToObject(server_ret, "message", "hello");
						free(str_response);
					}
					cJSON_Delete(ret_message_item);
				}
			}
			else if (strcmp(business_item->valuestring, "monitor:routerLatency") == 0)
			{	
				char *str_response = NULL;
				cJSON* ret_message_item = handle_server_topic_monitor_vpnping(req_json, req_topic, ret_topic, add_topic, del_topic, from_item->valuestring);
				if (ret_message_item)
				{
					str_response = cJSON_PrintUnformatted(ret_message_item);
					if (str_response)
					{
						cJSON_AddStringToObject(server_ret, "message", str_response);
						//cJSON_AddStringToObject(server_ret, "message", "hello");
						free(str_response);
					}
					cJSON_Delete(ret_message_item);
				}
			}
			else if (strcmp(business_item->valuestring, "monitor:routerFlow") == 0)
			{	
				char *str_response = NULL;
				cJSON* ret_message_item = handle_server_topic_monitor_vpntraffic(req_json, req_topic, ret_topic, add_topic, del_topic, from_item->valuestring);
				if (ret_message_item)
				{
					str_response = cJSON_PrintUnformatted(ret_message_item);
					if (str_response)
					{
						cJSON_AddStringToObject(server_ret, "message", str_response);
						//cJSON_AddStringToObject(server_ret, "message", "hello");
						free(str_response);
					}
					cJSON_Delete(ret_message_item);
				}
			}
			else if (strcmp(business_item->valuestring, "monitor:checkServiceReachable") == 0)
			{	
				char *str_response = NULL;
				cJSON* obj = cJSON_Parse(message_item->valuestring);
				if (obj)
				{
					cJSON* ret_message_item = handle_server_topic_checkService(req_json, req_topic, ret_topic, add_topic, del_topic, from_item->valuestring, obj);
					if (ret_message_item)
					{
						str_response = cJSON_PrintUnformatted(ret_message_item);
						if (str_response)
						{
							cJSON_AddStringToObject(server_ret, "message", str_response);
							//cJSON_AddStringToObject(server_ret, "message", "hello");
							free(str_response);
						}
						cJSON_Delete(ret_message_item);
					}
					cJSON_Delete(obj);
				}
			}
			else if (strcmp(business_item->valuestring, "monitor:serverLatency") == 0)
			{	
				char *str_response = NULL;
				cJSON* obj = cJSON_Parse(message_item->valuestring);
				if (obj)
				{
					cJSON* ret_message_item = handle_server_topic_serverLatency(req_json, req_topic, ret_topic, add_topic, del_topic, from_item->valuestring, obj);
					if (ret_message_item)
					{
						str_response = cJSON_PrintUnformatted(ret_message_item);
						if (str_response)
						{
							cJSON_AddStringToObject(server_ret, "message", str_response);
							//cJSON_AddStringToObject(server_ret, "message", "hello");
							free(str_response);
						}
						cJSON_Delete(ret_message_item);
					}
					cJSON_Delete(obj);
				}
			}
			else if (strcmp(business_item->valuestring, "monitor:checkProxyReachable") == 0)
			{
				char *str_response = NULL;
				cJSON* ret_message_item = handle_server_topic_checkProxy(req_json, req_topic, ret_topic, add_topic, del_topic, from_item->valuestring);
				if (ret_message_item)
				{
					str_response = cJSON_PrintUnformatted(ret_message_item);
					if (str_response)
					{
						cJSON_AddStringToObject(server_ret, "message", str_response);
						//cJSON_AddStringToObject(server_ret, "message", "hello");
						free(str_response);
					}
					cJSON_Delete(ret_message_item);
				}
			}
			else if (strcmp(business_item->valuestring, "monitor:proxyLatency") == 0)
			{	
				char *str_response = NULL;
				cJSON* ret_message_item = handle_server_topic_proxyLatency(req_json, req_topic, ret_topic, add_topic, del_topic, from_item->valuestring);
				if (ret_message_item)
				{
					str_response = cJSON_PrintUnformatted(ret_message_item);
					if (str_response)
					{
						cJSON_AddStringToObject(server_ret, "message", str_response);
						//cJSON_AddStringToObject(server_ret, "message", "hello");
						free(str_response);
					}
					cJSON_Delete(ret_message_item);
				}
			}
			else if (strcmp(business_item->valuestring, "monitor:routerBandwidth") == 0)
			{	
				char ip[100] = "";
				printf("bandwidth 0\n");
				cJSON* obj = cJSON_Parse(message_item->valuestring);
				if (obj)
				{
					cJSON* ip_item = cJSON_GetObjectItem(obj, "ip");
					strcpy(ip, ip_item->valuestring);
					cJSON_Delete(obj);
				}
				printf("bandwidth 1:%s\n", ip);
				char *str_response = NULL;
				cJSON* ret_message_item = handle_server_topic_monitor_vpnbandwidth(req_json, req_topic, ret_topic, add_topic, del_topic, from_item->valuestring, ip);
				if (ret_message_item)
				{
					str_response = cJSON_PrintUnformatted(ret_message_item);
					if (str_response)
					{
						cJSON_AddStringToObject(server_ret, "message", str_response);
						//cJSON_AddStringToObject(server_ret, "message", "hello");
						free(str_response);
					}
					cJSON_Delete(ret_message_item);
				}
			}
			/* deleted by team manager, from cloud */
			else if (strcmp(business_item->valuestring, "6") == 0)
			{
				cJSON* obj = cJSON_Parse(message_item->valuestring);
				if (obj)
				{
					cJSON* mac_item = cJSON_GetObjectItem(obj, "mac");
					cJSON* team_item = cJSON_GetObjectItem(obj, "teamId");
					if (mac_item && team_item)
					{
						if (mac_item->valuestring[0] == 0 ||
								strcmp(mac_item->valuestring, my_id) == 0
								)
						{
							cJSON* res = vpn_tool_stop_vpn(team_item->valuestring);
							if (res)
							{
								cJSON_Delete(res);
							}
							unset_my_teamid();
						}
					}
					cJSON_Delete(obj);
				}
			}
			/* get http request from cloud */
			else if(strcmp(business_item->valuestring, "100") == 0)
			{
				char *str_response = NULL;
				sprintf(ret_topic, "vppn/%s", from_item->valuestring);
				printf("message: %s\n", message_item->valuestring);
				cJSON* obj = cJSON_Parse(message_item->valuestring);
				if (obj)
				{
					printf("obj :\n");
					cJSON_Dump(obj);
					cJSON* method_item = cJSON_GetObjectItem(obj, "method");
					cJSON* uri_item = cJSON_GetObjectItem(obj, "url");
					if (method_item && uri_item)
					{
						if (strncmp(uri_item->valuestring, "/vppn/api/get_device_info", strlen("/vppn/api/get_device_info")) == 0)
						{
							cJSON* dev_info = get_my_device_info();
							if (dev_info)
							{
								str_response = cJSON_PrintUnformatted(dev_info);
								cJSON_Delete(dev_info);
							}
							ret = server_ret;
						}
						else
						{
							cJSON* http_response = handle_server_topic_http(obj, ret_topic);
							if (http_response)
							{
								cJSON* res_item = cJSON_GetObjectItem(http_response, "response");
								if (res_item)
								{
									str_response = strdup(res_item->valuestring);
								}
								else
								{
									str_response = strdup("");
								}
								//str_response = cJSON_PrintUnformatted(http_response);
								cJSON_Delete(http_response);
							}
						}
					}
					cJSON_Delete(obj);
				}
				if (str_response)
				{
					cJSON_AddStringToObject(server_ret, "message", str_response);
					//cJSON_AddStringToObject(server_ret, "message", "hello");
					free(str_response);
				}
			}
		}
		ret = server_ret;
	}
	return ret;
}

char* handle_mqtt_topic(char* req_str, int req_len, char* req_topic, char* ret_topic, char* add_topic, char* del_topic)
{
	char *ret = NULL;
	add_topic[0] = 0;
	del_topic[0] = 0;
	ret_topic[0] = 0;
	char* dup_str = (char*)malloc(req_len + 1);
	if (dup_str)
	{
		strncpy(dup_str, req_str, req_len);
		dup_str[req_len] = 0;
		printf("[%s]:%s\n", req_topic, dup_str);
		cJSON* req_json = cJSON_Parse(dup_str);
		if (req_json)
		{
			cJSON* res = handle_mqtt_topic_json(req_json, req_topic, ret_topic, add_topic, del_topic);
			if (res)
			{
				ret = cJSON_PrintUnformatted(res);
				cJSON_Delete(res);
			}
			cJSON_Delete(req_json);
		}
		else{
			printf("Can't parse json\n");
		}
		free(dup_str);
	}
	return ret;
}
