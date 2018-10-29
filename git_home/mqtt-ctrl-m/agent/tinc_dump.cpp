#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <tinctool.h>
#include "cJSON.h"

void printUsage()
{
	printf("Usage:\n");
	printf(" tinc_dump command ...\n");
	printf("\n");
	printf("Available commands:\n");
	printf(" traffic\n");
}

int main(int argc, char **argv)
{
	if (argc != 2)
	{
		printUsage();
		return -1;
	}
	if (strcmp(argv[1], "traffic") == 0)
	{
		cJSON* dump = tinctool_dump_traffic((char*)"/etc/tinc/site0", (char*)"/var/run/site0.pid");
		if (dump)
		{
			cJSON_Dump(dump);
			cJSON_Delete(dump);
		}
		else
		{
			printf("unknown json\n");
		}
	}
	return 0;
}
