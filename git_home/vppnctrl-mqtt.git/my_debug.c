#include <stdio.h>
#include <stdarg.h>
#include "my_debug.h"

int default_dbg_level = DEBUG_LEVEL_NO;

int my_debug(int debug_level, const char *file_name, const char *func_name, int line, const char *fmt, ...) 
{
	int ret = 0;
	va_list ap;
	if (default_dbg_level != DEBUG_LEVEL_NO)
	{
		char *prefix_line = NULL;
		if (debug_level <= default_dbg_level)
		{
			switch (debug_level)
			{
				case DEBUG_LEVEL_ERR:
					prefix_line = "\033[4m\033[47;31m[ERROR] \033[0m\n";
					break;
				case DEBUG_LEVEL_WARN:
					prefix_line = "\033[4m\033[47;33m[WARN] \033[0m\n";
					break;
				case DEBUG_LEVEL_INFO:
					prefix_line = "\033[4m\033[47;32m[INFO] \033[0m\n";
					break;
				default:
					break;
			}
			if (prefix_line)
			{
				printf("%s", prefix_line);
			}
			printf("<%s - %s: %d> ", file_name, func_name, line);
			va_start(ap, fmt);
			ret = vprintf(fmt, ap);
			va_end(ap);
		}
	}

	return ret;
}

void my_debug_set_level(int level)
{
	default_dbg_level = level;
	return;
}
