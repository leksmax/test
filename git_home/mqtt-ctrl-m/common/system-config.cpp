#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "system-config.h"

#define NVRAM_BIN "config"

/* System config interfaces
 *
 *	--> config get
 *	--> config set
 *	--> config commit
 *   
 *     Note: each config item'len should be less than 40 bytes
 */

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

void system_config_get(const char *name, char *value)
{   
    FILE *file = NULL;
    char cmd_buf[4000];
    char read_buf[4000];
    sprintf(cmd_buf, NVRAM_BIN" get %s", name);
    file = popen(cmd_buf, "r");
    if (file)
    {   
        while(fgets(read_buf, sizeof(read_buf), file))
        {
            //output_oui(read_buf);
			skip_crlf(read_buf);
            strcpy(value, read_buf);
            usleep(1000);
        }
        pclose(file);
    }
    return;
}

void system_config_set(const char *name, char *value)
{
    FILE *file = NULL;
    char *cmd_buf;
    char read_buf[100];
    int cmd_buf_len = strlen(name) + strlen(value) + 100;
    cmd_buf = (char*)malloc(cmd_buf_len);
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

void system_config_unset(const char *name)
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

void system_config_commit()
{
	system(NVRAM_BIN" commit");
}
