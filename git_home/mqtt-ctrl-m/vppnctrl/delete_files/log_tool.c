#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <stdarg.h>
#include <string.h>
#include "log_tool.h"

char log_prefix[40] = "[syslog]";

/*
 * for netgear, the id must be "0", and prefix must be "[xxxx]" format, and length must be less than 40
 * */
void log_tool_init(const char* id, const char* prefix)
{
	openlog(id, 0, 0);
	if (prefix)
	{
		if (strlen(prefix) < sizeof(log_prefix) - 1)
		{
			strcpy(log_prefix, prefix);
		}
	}
	return;
}

void log_tool_exit()
{
	closelog();
	return;
}

void log_tool_log(const char* fmt, ...)
{
	va_list ap;
	char fmt_buf[1000];
	char log_line[2000];
	strcpy(fmt_buf, log_prefix);
	strcat(fmt_buf, fmt);
	va_start(ap, fmt);
	vsnprintf(log_line, sizeof(log_line) - 1, fmt_buf, ap);
	va_end(ap);
	syslog(LOG_USER | LOG_NOTICE, "%s", log_line);
	return;
}
