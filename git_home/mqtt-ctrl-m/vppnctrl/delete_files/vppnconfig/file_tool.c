#include <stdio.h>
#include <stdlib.h>
#include <linux/ioctl.h>
#include <linux/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include "file_tool.h"

int get_file_len(char *file_name)
{
	int ret = -1;
	struct stat file_stat;
	ret = stat(file_name, &file_stat);
	if (ret == 0)
	{
		ret = file_stat.st_size;
	}
	return ret;
}

char *read_text(char *file_name)
{
	char *ret_ptr = NULL;
	int file_len = get_file_len(file_name);
	if (file_len > 0)
	{
		int fd = open(file_name, O_RDONLY);
		if (fd > 0)
		{
			ret_ptr = malloc(file_len + 1);
			read(fd, ret_ptr, file_len);
			ret_ptr[file_len] = 0;
			close(fd);
		}
	}
	return ret_ptr;
}

void write_file(char *file_name, int mode, void *buf, int size)
{
	int fd = open(file_name, O_CREAT | O_WRONLY | O_TRUNC, mode);
	if (fd > 0)
	{
		write(fd, buf, size);
		close(fd);
	}
	return;
}

void write_text(char *file_name, char *content)
{
	write_file(file_name, 0644, content, strlen(content));
	return;
}

cJSON *read_json_from_file(char *file_name)
{
	cJSON *ptr = NULL;
	char *text = read_text(file_name);
	if (text)
	{
		ptr = cJSON_Parse(text);
		free(text);
	}
	return ptr;
}

void write_json_to_file(char *file_name, cJSON *json)
{
	char *str = cJSON_Print(json);
	if (str)
	{
		write_text(file_name, str);
		free(str);
	}
	return;
}

void write_shell(char *file_name, char *content)
{
	write_file(file_name, 0755, content, strlen(content));
	return;
}

void append_line(char *file_name, char *line)
{
	int fd = open(file_name, O_CREAT | O_APPEND | O_WRONLY);
	if (fd > 0)
	{   
		write(fd, line, strlen(line));
		close(fd);
	}   
	return;
}

/* return 0:find no dir */
/* return 1:find dir */
/* return -1:find a file but a dir */
int file_tool_find_dir(char *path)
{
	int ret = 0;
	struct stat file_stat;
	int stat_ret = stat(path, &file_stat);
	if (stat_ret == 0)
	{
		mode_t path_mode = file_stat.st_mode;
		if (S_ISDIR(path_mode))
		{
			ret = 1;
		}
		else
		{
			ret = -1;
		}
	}
	return ret;

}

void file_tool_create_dir(char *path, int mode)
{
	int find = file_tool_find_dir(path);
	if (find == 0)
	{
		mkdir(path, mode);
	}
	return;
}

void file_tool_remove_dir(char *path)
{
	int find = file_tool_find_dir(path);
	if (find == 1)
	{
		/* rm an empty dir, Can't rm non-empty dir */
		rmdir(path);
	}
	return;
}
