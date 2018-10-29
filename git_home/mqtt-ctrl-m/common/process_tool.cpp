#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "process_tool.h"
#include "my_debug.h"

static char *read_fp_data(FILE *fp)
{
	char *ret = NULL;
	char line_buf[1024];
	memset(line_buf, 0, sizeof (line_buf));
	while(fgets(line_buf, sizeof(line_buf) - 1, fp))
	{
		int old_str_len = ret?(strlen(ret)):0;
		int new_str_len = strlen(line_buf) + old_str_len;
		ret = (char*)realloc(ret, new_str_len + 1);
		if (old_str_len == 0)
		{
			ret[0] = 0;
		}
		strcat(ret, line_buf);
		memset(line_buf, 0, sizeof (line_buf));
	}
	return ret;
}

char *process_tool_run_cmd(char *cmd_buf)
{
	char *ret = NULL;
	FILE *fp = popen(cmd_buf, "r");
	if (fp)
	{
		ret = read_fp_data(fp);
		pclose(fp);
	}
	return ret;
}

/* return pid */
int process_tool_ps(char *program_name, char *match_str)
{
	int ret_pid = 0;
	char cmd_buf[200];
#if 0
	sprintf(cmd_buf, "ps ax| grep %s|grep -v grep", program_name);
#else
	sprintf(cmd_buf, "ps | grep %s |grep -v grep", program_name);
#endif
	FILE *fp = popen(cmd_buf, "r");
	if (fp)
	{
		char buf[1000];
		while(fgets(buf, sizeof(buf), fp))
		{
			if(strstr(buf, match_str))
			{
				char *ptr = buf;
				while(*ptr == ' ')
				{
					ptr++;
				}
				ret_pid = atoi(ptr);
				break;
			}
		}
		pclose(fp);
	}
	return ret_pid;
}

void process_tool_kill(char *program_name, char *match_str, int sig)
{
	int pid = process_tool_ps(program_name, match_str);
	if (pid)
	{
		kill(pid, sig);
	}
	return;
}

#define MAX_ARGS_NUM (30)
#define MAX_LINE_LEN (2048)

static void close_all_fd()
{
    int fd;
    for(fd = 0; fd < 255; fd++)
    {
        close(fd);
    }
    return;
}

static int parse_cmd_args(char *cmd, char *ret_args[], int max_args_num)
{
    int args_cnt = 0;
    int ret = -1;
    char *save_ptr1 = NULL;
    char *str;
    char *token;
    printf("cmd = %s\n", cmd);
    printf("cmd = %p\n", cmd);
    if (cmd)
    {
        ret = 0;
        for(str = cmd, args_cnt = 0; ;str = NULL)
        {
            token = strtok_r(str, " \t", &save_ptr1);
            if (token == NULL)
            {
                break;
            }
            ret_args[args_cnt++] = token;
            if (args_cnt > max_args_num)
            {
                ret = -1;
                break;
            }
        }
    }

    return ret;
}

int process_tool_system(const char *cmd)
{
    int ret = -1;
    char *args[MAX_ARGS_NUM] = {0};
    char dup_cmd[MAX_LINE_LEN] = {0};
    int status;
    if (cmd && strlen(cmd) < MAX_LINE_LEN)
    {
        strcpy(dup_cmd, cmd);
        if (parse_cmd_args(dup_cmd, args, MAX_ARGS_NUM - 1) == 0)
        {
        	//MY_DEBUG_INFO("arg[0] = %s, arg[1] = %s\n", args[0], args[1]);
            pid_t pid = fork();
            if (pid == 0)
            {
                close_all_fd();
                int exe_ret = execvp(args[0], args);
                if (exe_ret < 0)
                {
                	MY_DEBUG_ERR("execvp error\n");
                	exit(-1);
                }
            }
            else if(pid > 0)
            {
                MY_DEBUG_INFO("pid = %d\n", pid);
                ret = waitpid(pid, &status, 0);
            }
            else
            {

            }
        }
        else
        {

        }
    }
    return ret;
}
