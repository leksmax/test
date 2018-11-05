
/*
 * 仿DNI固件config命令修改
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"

void usages()
{
    fprintf(stderr,
		"Usages: ---------------------\n"
		"       config show\n"
		"       config commit\n"
		"       config uncomit\n"
		"       config default\n"
		"       config get name\n"
		"       config set name=value\n"
		"       config unset name\n"		
		"       config backup output-file-name\n"
		"       config restore input-file-name\n"
		"       config list name-prefix(name as name1 name2 ...)\n"
		"\n"
	);
    exit(1);
}

int main(int argc, char *argv[])
{
    int i;
    int ret = 0;
    char *name = NULL; 
    char *value = NULL;
    char buff[CONFIG_MAX_VALUE_LEN] = {0};

    if (argc < 2) 
    {
        usages();
    }

	for (i = 1; i < argc; i ++) 
    {
        if (!strcmp(argv[i], "show"))
        {
            ret = config_show();
            break;
        }
        else if (!strcmp(argv[i], "commit"))
        {
            ret = config_commit();
            break;
        }
        else if (!strcmp(argv[i], "uncommit"))
        {
            ret = config_uncommit();
            break;
        }
        else if (!strcmp(argv[i], "default"))
        {
            break;
        }
        else if (!strcmp(argv[i], "get") || !strcmp(argv[i], "unset") || !strcmp(argv[i], "set"))
        {
            if ((i + 1) < argc)
            {
                switch(argv[i ++][0])
                {
                    case 'g':
                        if ((value = config_get(argv[i])))
                        {
                            puts(value);
                        }
                        break;
                    case 'u':
                        ret = config_unset(argv[i]);
                        break;
                    case 's':
                        strncpy(value = buff, argv[i], sizeof(buff) - 1);
                        name = strsep(&value, "=");
                        ret = config_set(name, value);
                        break;
                }
            }
            else
            {
                usages();
            }
        }
        else if (!strcmp(argv[i], "backup"))
        {
            break;
        }
        else if (!strcmp(argv[i], "restore"))
        {
            break;
        }
        else if (!strcmp(argv[i], "list"))
        {
            break;
        }
        else
        {
            usages();
        }
    }
    
    return ret;
}
