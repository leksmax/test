
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h> /* basename */

#include "utils.h"
#include "network.h"

typedef struct {
    const char *name;
    int (*cgi_main)(char *cmd, char *param);
} applet_cgi_t;

static const applet_cgi_t applets_cgi[]= {
//    { "vlan", vlan_main },
//    { "switch", switch_main },
//    { "system", system_main },
    { "network", network_main },
//    { "firewall", firewall_main },
//    { "statistic", statistic_main },
    { NULL, NULL}
};

int main(int argc, char *argv[])
{
    int ret = 0;
    char *base = NULL;
    char *cmd = NULL;
    char tmp[128] = {0};
    long inLen = 0;
    char *inStr = NULL;
    const applet_cgi_t *cgi = NULL;

    base = basename(argv[0]);

    if(strstr(base, CLI_SUFFIX))
    {
        if(argc > 1)
        {  
            /* cli 接口 */
            cmd = strdup(argv[1]);
            if(argc == 3)
            {
                inStr = strdup(argv[2]);
            }
            cgi_type = CGI_CLI;
        }
        else
        {
            fprintf(stderr, "Usages:\n");
            fprintf(stderr, "     %s <cmd> [parameter]\n", base);
            exit(0);
        }
    }
    else
    {
        char *method = NULL; 
        char *queryStr = NULL;
        char *contentStr = NULL;

        /* cgi 接口 */
        method = getenv("REQUEST_METHOD");
        queryStr = getenv("QUERY_STRING");
        contentStr = getenv("CONTENT_LENGTH");

        if(!method || !queryStr)
        {
            return -1;
        }

        cmd = web_get("cmd", queryStr, 0);
        if(!cmd)
        {
            return -1;
        }
        
        if(strcmp(method, "GET") == 0)
        {

        }
        else if(strcmp(method, "POST") == 0)
        {
            if(!contentStr)
            {
                return -1;
            }

            inLen = strtol(contentStr, NULL, 10);
            if(inLen <= 0)
            {
                cgi_debug("no data!\n");
                goto end_proc;
            }

            inStr = malloc(inLen + 1);
            if(!inStr)
            {
                cgi_debug("malloc data!\n");
                goto end_proc;            
            }
            memset(inStr, 0, sizeof(inStr) + 1);
            fread(inStr, 1, inLen, stdin);
        }
    }

    if(cgi_type == CGI_HTTP)
    {
        webs_text_header(stdout);
    }
        
    /* start cgi */
    for(cgi = applets_cgi; cgi->name; cgi ++)
    {
        if(cgi_type == CGI_HTTP)
        {
            snprintf(tmp, sizeof(tmp), "%s%s", cgi->name, CGI_SUFFIX);
        }
        else if(cgi_type == CGI_CLI)
        {
            snprintf(tmp, sizeof(tmp), "%s%s", cgi->name, CLI_SUFFIX);   
        }
        
        if(strcmp(base, tmp) == 0)
        {
            ret = cgi->cgi_main(cmd, inStr);
            break;
        }
    }

    if(cgi_type == CGI_CLI)
    {
        webs_write(stdout, "\n");
    }

end_proc:

    if(inStr)
    {
        free(inStr);
    }

    return ret;
}
