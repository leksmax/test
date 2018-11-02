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
#include "process-input.h"

int cgi_mode=1;

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

int main(int argc, char **argv)
{
	char *req_method = NULL;
	char *input = NULL;
    char *decode_str = NULL;
	cJSON* ctrl_response = NULL;
	//int	 reload_config = 0;
	
	//memset(&g_config, 0, sizeof(g_config));

	/*output_oui("cgi setting\n");*/
	if (argc < 2)
	{
		req_method = getenv("REQUEST_METHOD");
		if (req_method)
		{
			input = getcgidata(stdin, req_method);
		}
	}
	else
	{
		cgi_mode = 0;
		input = strdup(argv[1]);
	}
	if (input)
	{
		decode_str = (char*)decode_utf8_str((unsigned char*)input);
		if (decode_str)
		{
			ctrl_response = process_input(decode_str);
			free(decode_str);
		}
		free(input);
	}
	if (!ctrl_response)
	{
		ctrl_response = cJSON_CreateObject();
		cJSON_AddStringToObject(ctrl_response, "code", "201");
	}
	output_json(ctrl_response);
	cJSON_Delete(ctrl_response);
	return 0;
}