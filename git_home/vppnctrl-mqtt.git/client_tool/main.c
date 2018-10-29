#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "cJSON.h"
#include "net_tool.h"
#include "file_tool.h"
#include "tinctool.h"

int cgi_mode=0;

unsigned char get_char_from_utf8(unsigned char *utf8)
{
    unsigned char ret = 0xff;
    if (*utf8 >= '0' && *utf8 <= '9')
    {
        ret = *utf8 - '0';
    }
    else if (*utf8 >= 'a' && *utf8 <= 'f')
    {
        ret = *utf8 - 'a' + 10;
    }
    else if (*utf8 >= 'A' && *utf8 <= 'F')
    {
        ret = *utf8 - 'A' + 10;
    }
    return ret;
}

unsigned char decode_utf8_char(unsigned char *utf8)
{
    unsigned char tmp1 = 0;
    unsigned char tmp2 = 0;
    unsigned char ret = 0;
    tmp1 = get_char_from_utf8(utf8);
    tmp2 = get_char_from_utf8(utf8 + 1);
    ret = tmp1 * 16 + tmp2;
    return ret;
}

unsigned char *decode_utf8_str(unsigned char *str)
{
    //char *ptr = NULL;
    //char *ptr_tmp = NULL;
    int len = strlen((const char*)str);
    unsigned char *tmp_str = (unsigned char *)malloc(len + 1);
	if (tmp_str)
	{
		memset(tmp_str, 0, len + 1);
		int i = 0, j = 0;
		//char tmp;
		while(i < len)
		{
			unsigned char tmp;
			if (str[i] == '%')
			{
				tmp = decode_utf8_char(str + i + 1);
				i += 3;
			}
			else
			{
				tmp = str[i];
				i++;
			}
			tmp_str[j] = tmp;
			j++;
		}
	}
    return tmp_str;
}

char* getcgidata(FILE* fp, char* requestmethod)
{
	char* input;
	char *get_input;
	int len;
	int i = 0;
	char *ret = NULL;

	if (!strcmp(requestmethod, "GET"))
	{
		get_input = getenv("QUERY_STRING");
		if (get_input)
		{
			input = strdup(get_input);
		}
		else
		{
			input = NULL;
		}
		ret = input;
	}
	else if (!strcmp(requestmethod, "POST"))
	{
		len = atoi(getenv("CONTENT_LENGTH"));
		if (len > 0)
		{
			input = (char*)malloc(len + 1);

			int remain_len = len;
			while(remain_len--)
			{
				if (feof(fp))
				{
					break;
				}
				input[i++] = (char)fgetc(fp);
			}
			input[len] = 0;
			ret = input;
		}
	}
	return ret;
}

void dump_JSON(cJSON *obj)
{
    char *payload = cJSON_Print(obj);
    if (payload)
    {    
        printf("%s\n", payload);
        free(payload);
    }    
    return;
}

void output_json(cJSON *obj)
{
	if (cgi_mode)
	{
		printf("Content-type: text/plain\r\n\r\n");
	}
    if (obj)
    {    
        dump_JSON(obj);
    }    
    else 
    {    
        printf("null\n");
    }    
    return;
}

#define VPNCTRL_SERVER_BASE (4100)
#define VPNCTRL_MAX_TUNNELS (5)

void handle_get_vport_on()
{
	cJSON *ctrl_response = cJSON_CreateArray();
	int i;
	for(i = 0; i < VPNCTRL_MAX_TUNNELS; i++)
	{
		char file[200];
		sprintf(file, "/etc/site/site%d.conf", i);
		cJSON *item = read_json_from_file(file);
		if (!item)
		{
			item = cJSON_CreateObject();
		}
		else
		{
			char if_name[100];
			sprintf(if_name, "site%d", i);
			char buf[100] = "";
			int ret = net_tool_get_if_ip(if_name, buf);
			if (ret == 0)
			{
				cJSON_AddStringToObject(item, "vip", buf);
			}
		}
		cJSON_AddItemToArray(ctrl_response, item);
	}
	output_json(ctrl_response);
	cJSON_Delete(ctrl_response);
	return;
}

int main(int argc, char **argv)
{
	int ret = 0;
	
#if 0
	char *action = NULL;
	char *target_host = NULL;;
	if (argc == 2)
	{
		action = argv[1];
		if (strcmp(action, "vport_on") == 0)
		{
			handle_get_vport_on();
		}
	}
	else
	{
		ret = -1;
	}
#endif
	cJSON* traffic = tinctool_dump_traffic("/etc/tinc/site0", "/var/run/site0.pid");
	if (traffic)
	{
		output_json(traffic);
		cJSON_Delete(traffic);
	}
	return ret;
}
