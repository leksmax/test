#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "nvram-op.h"
#include "nvram-common.h"

void skip_crlf(char *str)
{
	int len = strlen(str);
	int i;
	for(i = 0; i < len; i++)
	{
		if (str[i] == '\n' || str[i] == '\r')
		{
			str[i] = 0;
			break;
		}
	}
	return;
}

void SetConfig(const char *name, char *value)
{
	FILE *file = NULL;
	char *cmd_buf;
	char read_buf[100];
	int cmd_buf_len = strlen(name) + strlen(value) + 100;
	cmd_buf = malloc(cmd_buf_len);
	if (cmd_buf)
	{
		sprintf(cmd_buf, NVRAM_BIN" set %s=\"%s\"", name, value);
		//printf("%s\n", cmd_buf);
		file = popen(cmd_buf, "r");
		if (file)
		{    
			while(fgets(read_buf, sizeof(read_buf), file))
			{
				usleep(100);
			}
			pclose(file);
		}
		free(cmd_buf);
	}
	//system(NVRAM_BIN" commit");
	return;
}

void UnsetConfig(const char *name)
{
	FILE *file = NULL;
	char cmd_buf[4000];
	char read_buf[100];
	sprintf(cmd_buf, NVRAM_BIN" unset %s", name);
	printf("%s\n", cmd_buf);
	file = popen(cmd_buf, "r");
	if (file)
	{    
		while(fgets(read_buf, sizeof(read_buf), file))
		{    
			usleep(1000);
		}    
		pclose(file);
	}    
	//system(NVRAM_BIN" commit");
	return;
}

char* GetConfig(const char *name)
{
	FILE *file = NULL;
	char cmd_buf[4000];
	char read_buf[4000];
	char *ret_ptr = NULL;
	sprintf(cmd_buf, NVRAM_BIN " get %s", name);
	file = popen(cmd_buf, "r");
	if (file)
	{
		int last_len = 0;
		while(fgets(read_buf, sizeof(read_buf), file))
		{
			skip_crlf(read_buf);
			if (!ret_ptr)
			{
				last_len = strlen(read_buf) + 1;
				ret_ptr = realloc(ret_ptr, last_len);
				ret_ptr[0] = 0;
			}
			else
			{
				last_len = strlen(read_buf) + strlen(ret_ptr) + 1;
				ret_ptr = realloc(ret_ptr, last_len);
			}
			strcat(ret_ptr, read_buf);
		}
		pclose(file);
	}
	return ret_ptr;
}

