
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "utils.h"

void show_usage(char *name)
{
	printf("%s\n"
		"	[set [limit_size name size | zero_time name time]] set paramter of table\n"
		"	[get name] get data of table\n"
		"	[clear name] clear all data of table\n"
		"	[clearall] clear all data of all table\n"
		,name);
	return ;
}

int main(int argc, char *argv[])
{
	int ch = 0, ret = 0;
	struct ipt_account_context ctx;

	if(argc < 2)
	{
		show_usage(argv[0]);
		return -1;
	}

	if(init_sockopt(&ctx) < 0)
	{
		printf("init sockopt failed!\n");
		return -1;
	}
	
	if(strcmp(argv[1], "set") == 0)
	{
		if(argc < 5)
		{
			show_usage(argv[0]);
			goto cleanup_ok;
		}
		if(strcmp(argv[2], "limit_size") == 0)
		{
			if(argv[3] != NULL)
			{
				strncpy(ctx.handle.name, argv[3], sizeof(ctx.handle.name));
				ctx.handle.data.size = atoll(argv[4]);
			}
			ret = ipt_account_set_limit_size_of_table(&ctx);
			goto cleanup_ok;
		}
		else if(strcmp(argv[2], "zero_time") == 0)
		{
			if(argv[3] != NULL)
			{
				strncpy(ctx.handle.name, argv[3], sizeof(ctx.handle.name));
				ctx.handle.data.size = atoll(argv[4]);
			}			
			ret = ipt_account_set_zero_time_of_table(&ctx);
			goto cleanup_ok;
		}
		goto cleanup_ok;
	}
	else if(strcmp(argv[1], "get") == 0)
	{
		if(argc < 4)
		{
			show_usage(argv[0]);
			goto cleanup_ok;
		}
		
		if(strcmp(argv[2], "table_name") == 0)
		{
			ret = ipt_account_get_name_of_table(&ctx);
		}
		else if(strncmp(argv[2], "table_data", 10) == 0)
		{
			ret = ipt_account_get_data_of_table(&ctx);
		}
		goto cleanup_ok;
	}
	else if(strcmp(argv[1], "clear") == 0)
	{
		if(argc < 3)
		{
			show_usage(argv[0]);
			goto cleanup_ok;
		}
		ret = ipt_account_clear_data_of_table(ctx.sockfd, argv[2]);
		goto cleanup_ok;
	}
	else if(strcmp(argv[1], "clearall") == 0)
	{
		ret = ipt_account_clear_data_of_all_table(ctx.sockfd);
		goto cleanup_ok;
	}

cleanup_ok:
	destory_sockopt(&ctx);
	return ret;		

}
