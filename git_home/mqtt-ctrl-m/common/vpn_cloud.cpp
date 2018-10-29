#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <iostream>
#include "compress_tool.h"
#include "net_tool.h"
#include "file_tool.h"
#include "str_tool.h"
#include "system-config.h"
//#include "vpn_config.h"
#include "cJSON.h"
#include "vpn_cloud.h"
#include "my-device.h"
#include "process_tool.h"

#include "HttpClient.h"

using namespace std;

/* POST plain http body, recv plain response */
cJSON *vpn_cloud_tool(cJSON *req, char *cloud_host, int cloud_port, char *uri)
{
	cJSON *response = net_tool_http_json_client(cloud_host, cloud_port, uri, req);
	return response;
}

#if 0
/* POST gzip http body, recv plain response */
cJSON *vpn_cloud_tool_gzip(cJSON *req, char *cloud_host, int cloud_port, char *uri)
{
	cJSON *res = NULL;
	char *str_req = cJSON_PrintUnformatted(req);
	if (str_req)
	{
		uLong src_len = (uLong)strlen(str_req);
		uLong dst_len = (uLong)src_len * 2;
		Bytef *src = (Bytef *)str_req;
		Bytef *dst = (Bytef *)malloc(dst_len);
		int recv_len = 0;
		if (dst)
		{
			memset(dst, 0, dst_len);
			int err = gzcompress(src, src_len, dst, &dst_len);
			//int err = gzcompress(dst, &dst_len, src, src_len);
			if (err == 0)
			//int err = compress(dst, &dst_len, src, src_len);
			//if (err == Z_OK)
			{
			printf("dst_len = %d, src_len = %d\n", (int)dst_len, (int)src_len);
				char *http_res = net_tool_http_client_raw(cloud_host, cloud_port, uri, dst, dst_len, &recv_len);
				if (http_res && recv_len > 0)
				{
					res = cJSON_Parse(http_res);
					free(http_res);
				}
			}
			free(dst);
		}
		free(str_req);
	}
	return res;
}
#endif

#if 0
int vpn_cloud_auth()
{
	int auth_ok = 0;
	cJSON* ret = NULL;
	char uri[200] = "";
	char uuid[40] = "";
	char agentid[40] = "";
	char cloud_host[100] = "";
	char cloud_port[100] = "";
	char headers[2][100];
	char id[100] = "";
	get_my_id(id);
	system_config_get("vppn_uuid", uuid);
	system_config_get("x_agent_id", agentid);
	system_config_get("vppn_cloudhost", cloud_host);
	system_config_get("vppn_cloudport", cloud_port);
	if (uuid[0] 
			&&
			cloud_host[0] 
			&& 
			cloud_port[0])
	{
		char password[200] = "";
		sprintf(password, "%s:%s", id, agentid);
		sprintf(uri, "/mqtt/auth?clientid=%s&username=%s&password=%s", uuid, id, password);
		char *headers_ptr[2];
		headers_ptr[0] = headers[0];
		headers_ptr[1] = headers[1];
		ret = net_tool_https_json_client(1, cloud_host, atoi(cloud_port), uri, NULL, headers_ptr, 0, NULL);
		if (ret)
		{
			auth_ok = 1;
			cJSON_Delete(ret);
		}
		//ret = net_tool_https_json_client(1, cloud_host, atoi(cloud_port), "/vppn/api/v1/client/searchTeamById", req, headers_ptr, 2, NULL);
	}
	else
	{
		
	}
	return auth_ok;
}
#else

int vpn_cloud_auth()
{
	int auth_ok = 0;
	//cJSON* ret = NULL;
	char uri[200] = "";
	char uuid[40] = "";
	char agentid[40] = "";
	char cloud_host[100] = "";
	char cloud_port[100] = "";
	//char headers[2][100];
	char id[100] = "";
	get_my_id(id);
	system_config_get("vppn_uuid", uuid);
	system_config_get("x_agent_id", agentid);
	system_config_get("vppn_cloudhost", cloud_host);
	system_config_get("vppn_cloudport", cloud_port);
	if (uuid[0] 
			&&
			cloud_host[0] 
			&& 
			cloud_port[0])
	{
		char password[200] = "";
		memset(password, 0, sizeof(password));
		str_tool_md5((const unsigned char*)agentid, strlen(agentid), (char*)password);
		sprintf(uri, "/mqtt/auth?clientid=%s&username=%s&password=%s", uuid, id, password);
		string url = "https://";
		url += cloud_host;
		url += ":";
		url += cloud_port;
		url += uri;
		HttpRequest http_req(url);
		string data("");
		HttpResponse* http_resp = http_req.Post(data, 15, (char*)"/etc/site/insight_ca.crt");
		if (http_resp)
		{	
			//printf("");
			delete http_resp;
		}
		//ret = net_tool_https_json_client(1, cloud_host, atoi(cloud_port), "/vppn/api/v1/client/searchTeamById", req, headers_ptr, 2, NULL);
	}
	else
	{
		
	}
	return auth_ok;
}
#endif


#if 0
cJSON* vpn_cloud_tool2(char* uri, cJSON* req)
{
	cJSON* ret = NULL;
	char uuid[40] = "";
	char cloud_host[100] = "";
	char cloud_port[100] = "";
	char headers[2][100];
	char base64_buf[100];
	char base64_src_buf[100];
	char id[100] = "";
	get_my_id(id);
	system_config_get("vppn_uuid", uuid);
	system_config_get("vppn_cloudhost", cloud_host);
	system_config_get("vppn_cloudport", cloud_port);
	if (uuid[0] 
			&&
			cloud_host[0] 
			&& 
			cloud_port[0])
	{
		sprintf(base64_src_buf, "%s:%s", id, uuid);
		memset(base64_buf, 0, sizeof(base64_buf));
		str_tool_base64_encode((const unsigned char*)base64_src_buf, strlen(base64_src_buf), base64_buf);
		//str_tool_replaceAll(base64_buf, '\n', 0);
		//sprintf(headers[0],"Apikey: XXXXXXXXX");
		sprintf(headers[0],"Apikey: 0cde13b523sf9aa5a403dc9f5661344b91d77609f70952eb488f31641");
		sprintf(headers[1],"Authorization: %s", base64_buf);
		//MY_DEBUG_INFO("===%s\n", base64_src_buf);
		//MY_DEBUG_INFO("===%s\n", base64_buf);
		char *headers_ptr[2];
		headers_ptr[0] = headers[0];
		headers_ptr[1] = headers[1];
		ret = net_tool_https_json_client(1, cloud_host, atoi(cloud_port), uri, req, headers_ptr, 2, NULL);
		if (ret)
		{
			cJSON* code_item = cJSON_GetObjectItem(ret, "code");
			if (code_item && code_item->valueint == 401)
			{
				vpn_cloud_auth();
			}
			cJSON_Delete(ret);
			ret = NULL;
		}
		//ret = net_tool_https_json_client(1, cloud_host, atoi(cloud_port), "/vppn/api/v1/client/searchTeamById", req, headers_ptr, 2, NULL);
	}
	else
	{
		
	}
	return ret;
}
#else

cJSON* vpn_cloud_tool2(char* uri, cJSON* req)
{
	cJSON* ret = NULL;
	char uuid[40] = "";
	char cloud_host[100] = "";
	char cloud_port[100] = "";
	char headers[2][100];
	char base64_buf[100];
	char base64_src_buf[100];
	char id[100] = "";
	get_my_id(id);
	system_config_get("vppn_uuid", uuid);
	system_config_get("vppn_cloudhost", cloud_host);
	system_config_get("vppn_cloudport", cloud_port);
	if (uuid[0] 
			&&
			cloud_host[0] 
			&& 
			cloud_port[0])
	{
		sprintf(base64_src_buf, "%s:%s", id, uuid);
		memset(base64_buf, 0, sizeof(base64_buf));
		str_tool_base64_encode((const unsigned char*)base64_src_buf, strlen(base64_src_buf), base64_buf);
		//str_tool_replaceAll(base64_buf, '\n', 0);
		//sprintf(headers[0],"Apikey: XXXXXXXXX");
		sprintf(headers[0],"Apikey: 0cde13b523sf9aa5a403dc9f5661344b91d77609f70952eb488f31641");
		sprintf(headers[1],"Authorization: %s", base64_buf);
		//MY_DEBUG_INFO("===%s\n", base64_src_buf);
		//MY_DEBUG_INFO("===%s\n", base64_buf);
		string header1 = headers[0];
		string header2 = headers[1];
		string url = "https://";
		url += cloud_host;
		url += ":";
		url += cloud_port;
		url += uri;
		HttpRequest http_req(url);
		//cout << "header: " << header1 << endl;
		//cout << "header: " << header2 << endl;
		http_req.AddHeader(header1);
		http_req.AddHeader(header2);
		//cout << "url: " << url << endl;
		string data;
		if (req)
		{
			char* req_str = cJSON_PrintUnformatted(req);
			if (req_str)
			{
				data = req_str;
				free(req_str);
			}
			else
			{
				data = "";
			}
		}
		HttpResponse* http_resp = http_req.Post(data, 15, (char*)"/etc/site/insight_ca.crt");
		if (http_resp)
		{
			string body = http_resp->GetBody();
			//cout << "body: " << body << endl;
			ret = cJSON_Parse(body.c_str());
			if (ret)
			{
				//cJSON_Dump(ret);
				cJSON* code_item = cJSON_GetObjectItem(ret, "code");
				if (code_item)
				{
				   	if (code_item->valueint == 401)
					{
						vpn_cloud_auth();
						cJSON_Delete(ret);
						ret = NULL;
					}
					else if(code_item->valueint == 902)
					{
						cJSON* message_item = cJSON_GetObjectItem(ret, "message");
						if (message_item && message_item->valuestring &&
								message_item->valuestring[0] != 0)
						{
							set_http_manager_server_to_local(message_item->valuestring, (char*)"443");
						}
					}
				}
			}
			delete(http_resp);
		}
		else
		{
			//cout << "http no response" << endl;
		}
		//ret = net_tool_https_json_client(1, cloud_host, atoi(cloud_port), "/vppn/api/v1/client/searchTeamById", req, headers_ptr, 2, NULL);
	}
	else
	{
		
	}
	return ret;
}

cJSON* vpn_cloud_tool3(char* uri, cJSON* req)
{
	cJSON* ret = NULL;
	char* req_str = cJSON_PrintUnformatted(req);
	if (req_str)
	{
		int cmd_len = strlen(req_str) + 300; //reserve 300 to store command and uri
		char* cmd_buf = (char*)malloc(cmd_len);
		if (cmd_buf)
		{
			sprintf(cmd_buf, "vpncloud_agent '%s' '%s'", uri, req_str);
			//printf("vpn_cloud_tool3:1 %s\n", cmd_buf);
			char* res = process_tool_run_cmd(cmd_buf);
			//printf("vpn_cloud_tool3:2 %s\n", res);
			if (res)
			{
				ret = cJSON_Parse(res);
				//cJSON_Dump(ret);
				free(res);
			}
			free(cmd_buf);
		}
		free(req_str);
	}
	return ret;
}

#endif

