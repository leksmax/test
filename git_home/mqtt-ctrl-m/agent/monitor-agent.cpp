#include <stdio.h>
#include <string.h>
#include "cJSON.h"
#include "monitor_tool.h"

void printUsage()
{
	printf("Usage:\n");
	printf(" monitor_agent command ...\n");
	printf("\n");
	printf("Available commands:\n");
	printf(" cpu\n");
	printf(" memory\n");
	printf(" attach_devices\n");
	printf(" device_info\n");
	printf(" temprature\n");
	printf(" vpn_traffic\n");
	printf(" vpn_ping\n");
	printf(" vpn_bandwidth\n");
}

int main(int argc, char** argv)
{
	if (argc < 2)
	{
		printUsage();
		return -1;
	}
	cJSON* root = NULL;
	if (strcmp(argv[1], "cpu") == 0)
	{
		root = monitor_tool_cpu();
	}
	else if (strcmp(argv[1], "memory") == 0)
	{
		root = monitor_tool_memory();
	}
	else if (strcmp(argv[1], "attach_devices") == 0)
	{
		root = monitor_tool_link();
	}
	else if (strcmp(argv[1], "device_info") == 0)
	{
		root = monitor_tool_equipment_info();
	}
	else if (strcmp(argv[1], "temprature") == 0)
	{
		root = monitor_tool_temprature();
	}
	else if (strcmp(argv[1], "vpn_traffic") == 0)
	{
		//root = monitor_tool_vpntraffic();
		root = monitor_tool_vpnping();
	}
	else if (strcmp(argv[1], "vpn_ping") == 0)
	{
		root = monitor_tool_vpnping();
	}
	else if (strcmp(argv[1], "vpn_bandwidth") == 0)
	{
		if (argc < 3)
		{
			printf("monitor-agent vpn_bandwidth ip\n");
			printf("Note:ip is a vitual ip address assigned to a device\n");
			printf(" eg. 10.1.3.10\n");
			return -1;
		}
		root = monitor_tool_vpnband(argv[2]);
	}
	else
	{
		printUsage();
		return -1;
	}
	cJSON_Dump(root);
	cJSON_Delete(root);
	return 0;
}
