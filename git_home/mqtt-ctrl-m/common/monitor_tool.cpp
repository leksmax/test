#include <stdio.h>
#include <string.h>
#include "my-device.h"
#include "monitor_tool.h"
#include "vpn_tool.h"
#include "file_tool.h"
#include "net_tool.h"
#include "uds_client.h"

extern void skip_crlf(char*);

cJSON* monitor_tool_cpu()
{
	double avg_load = 0;
	cJSON* message_item = cJSON_CreateObject();
	cJSON* cpus = GetCPUJSON2(&avg_load);
	cJSON_AddItemToObject(message_item, "cpus", cpus);
	cJSON_AddNumberToObject(message_item, "cpuAvg", avg_load);
	return message_item;
}

cJSON* monitor_tool_memory()
{
	double mem_usage = 0;
	unsigned int total_mem = 0;
	unsigned int free_mem = 0;
	mem_usage = Get_Mem_Info(&total_mem, &free_mem);
	//sprintf(ret_topic, "vppn/monitor/%s", from);
	cJSON* message_item = cJSON_CreateObject();
	cJSON_AddNumberToObject(message_item, "totalMemory", total_mem);
	cJSON_AddNumberToObject(message_item, "freeMemory", free_mem);
	cJSON_AddNumberToObject(message_item, "useMemory", total_mem - free_mem);
	cJSON_AddNumberToObject(message_item, "usageMemory", mem_usage);
	return message_item;
}

cJSON* monitor_tool_vpntraffic()
{
	//sprintf(ret_topic, "vppn/%s", from);
	cJSON* message_item = cJSON_CreateObject();
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

cJSON* monitor_tool_vpnping()
{
	//sprintf(ret_topic, "vppn/monitor/%s", from);
	cJSON* message_item = cJSON_CreateObject();
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

cJSON* monitor_tool_vpnband(char* ip)
{
	cJSON* message_item = cJSON_CreateObject();
	int upload;
	int download;
	vpn_tool_get_member_bandwidth(ip, &upload, &download);
	cJSON_AddNumberToObject(message_item, "upload_bandwidth", upload);
	cJSON_AddNumberToObject(message_item, "download_bandwidth", download);
	return message_item;
}

cJSON* monitor_tool_link()
{
	cJSON* message_item = cJSON_CreateObject();
	cJSON* attach = get_attach_devices();
	cJSON_AddItemToObject(message_item, "links", attach);
	return message_item;
}

cJSON* monitor_tool_equipment_info()
{
	cJSON* message_item = cJSON_CreateObject();
   /* MAC address */
	char mac[100] = "";
	net_tool_get_if_hwaddr((char*)"br0", mac);
	cJSON_AddStringToObject(message_item, "mac", mac);

	/* IP address */
	char ip[100] = "";
	net_tool_get_if_ip((char*)"br0", ip);
	cJSON_AddStringToObject(message_item, "ip", ip);

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

cJSON* monitor_tool_temprature()
{
	cJSON* message_item = cJSON_CreateObject();
	char* cmd_res = read_text((char*)"/sys/class/thermal/thermal_zone0/temp");
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
	return message_item;
}

#define NMAP_BUF_SIZE (10240)

cJSON* monitor_tool_nmap()
{
	int perf_ret = -1;
	cJSON* ret = NULL;
	char *rbuf = (char*)calloc(1, NMAP_BUF_SIZE);
	if (rbuf)
	{
		//printf("member bandwidth 1\n");
		cJSON* req = cJSON_CreateObject();
		cJSON_AddStringToObject(req, "data", "");
		cJSON_AddStringToObject(req, "cmd", "get_nmap_data");
		//printf("member bandwidth 2\n");
		//cJSON_Dump(req);
		char *str = cJSON_PrintUnformatted(req);
		if (str)
		{
			perf_ret = uds_client_request((char*)"/var/run/nmap-scan.sock", str, strlen(str), rbuf, NMAP_BUF_SIZE - 1, 30);
			if (perf_ret >= 0)
			{
				ret = cJSON_Parse(rbuf);
			}
			free(str);
		}
		free(rbuf);
	}
	return ret;
}

#if 0
cJSON* init_processes()
{
	cJSON* array = cJSON_CreateArray();
}

cJSON* monitor_tool_processes()
{
	cJSON* ret = NULL;
	return ret;
}
#endif
