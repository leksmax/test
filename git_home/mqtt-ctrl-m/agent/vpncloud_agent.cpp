#include <stdio.h>
#include <string.h>
#include <string>

#include "vpn_cloud.h"

using namespace std;

void printUsage()
{
	printf("Usage:\n");
	printf("cloud_agent uri request\n");
	return;
}

int main(int argc, char** argv)
{
	char* uri = NULL;
	char* req_str = NULL;
	if (argc < 3)
	{
		return -1;
	}
	uri = argv[1];
	req_str = argv[2];
	
	cJSON* req = cJSON_Parse(req_str);
	if (req)
	{
		cJSON* ret = vpn_cloud_tool2(uri, req);
		if (ret)
		{
			cJSON_Dump(ret);
			cJSON_Delete(ret);
		}
		else
		{
			printf("\n");
		}
		cJSON_Delete(req);
	}

	return 0;
}
