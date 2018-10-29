#ifndef _PROCESS_TOOL_H_
#define _PROCESS_TOOL_H_

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

char *process_tool_run_cmd(char *cmd_buf);
int process_tool_ps(char *program_name, char *match_str);
void process_tool_kill(char *program_name, char *match_str, int sig);
int process_tool_system(const char *cmd);

#ifdef __cplusplus
}
#endif

#endif
