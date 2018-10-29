#ifndef _FILE_TOOL_H_
#define _FILE_TOOL_H_

#include <stdio.h>
#include "cJSON.h"

#ifdef __cplusplus
extern "C" {
#endif

int get_file_len(char *file_name);
char *read_text(char *file_name);
void write_text(char *file_name, char *content);
void write_shell(char *file_name, char *content);
void append_line(char *file_name, char *line);


void write_json_to_file(char *file_name, cJSON *json);
cJSON *read_json_from_file(char *file_name);

void file_tool_create_dir(char *path, int mode);
void file_tool_remove_dir(char *path);

#ifdef __cplusplus
}
#endif
#endif
