#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include "compress_tool.h"
#include "net_tool.h"
#include "file_tool.h"
#include "vpn_config.h"
#include "cJSON.h"

/* POST plain http body, recv plain response */
cJSON *vpn_cloud_tool(cJSON *req, char *cloud_host, int cloud_port, char *uri)
{
	cJSON *response = net_tool_http_json_client(cloud_host, cloud_port, uri, req);
	return response;
}

/* POST gzip http body, recv plain response */
cJSON *vpn_cloud_tool_gzip(cJSON *req, char *cloud_host, int cloud_port, char *uri)
{
	cJSON *res = NULL;
	char *str_req = cJSON_Print(req);
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

cJSON* vpn_cloud_tool2(char* uri, cJSON* req)
{
	cJSON* ret = NULL;
	char uuid[40] = "";
	char cloud_host[100] = "";
	char cloud_port[100] = "";
	char headers[2][100];
	char base64_buf[100];
	char base64_src_buf[100];
	system_config_get("vppn_uuid", uuid);
	system_config_get("vppn_cloudhost", cloud_host);
	system_config_get("vppn_cloudport", cloud_port);
	if (uuid[0] 
			&&
			cloud_host[0] 
			&& 
			cloud_port[0])
	{
		strcpy(base64_src_buf, uuid);
		memset(base64_buf, 0, sizeof(base64_buf));
		base64_encode(base64_src_buf, strlen(base64_src_buf), base64_buf);
		//str_tool_replaceAll(base64_buf, '\n', 0);
		sprintf(headers[0],"Apikey: XXXXXXXXX");
		sprintf(headers[1],"Authorization: %s", base64_buf);
		//MY_DEBUG_INFO("===%s\n", base64_src_buf);
		//MY_DEBUG_INFO("===%s\n", base64_buf);
		char *headers_ptr[2];
		headers_ptr[0] = headers[0];
		headers_ptr[1] = headers[1];
		ret = net_tool_https_json_client(1, cloud_host, atoi(cloud_port), "/vppn/api/v1/client/searchTeamById", req, headers_ptr, 2, NULL);
		//ret = net_tool_https_json_client(1, cloud_host, atoi(cloud_port), "/vppn/api/v1/client/searchTeamById", req, headers_ptr, 2, NULL);
	}
	else
	{
		
	}
	return ret;
}
