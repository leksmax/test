#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <stdarg.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <time.h>
#include "system-config.h"
#include "log_tool.h"

char log_prefix[40] = "[vpnlog]";
int log_fd = -1;
char syslog_prefix[40] = "[syslog]";

/*
 * for netgear, the id must be "0", and prefix must be "[xxxx]" format, and length must be less than 40
 * prefix is process name
 * */
void log_tool_init(const char* id, const char* prefix)
{
#if 0
	openlog(id, 0, 0);
#else
	char log_host[100] = "127.0.0.1";
	short log_port = 7172;
	if (prefix)
	{
		if (strlen(prefix) < sizeof(log_prefix) - 1)
		{
			strcpy(log_prefix, prefix);
		}
	}
	log_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (log_fd >= 0)
	{
		struct sockaddr_in saddr;
		bzero(&saddr, sizeof(saddr));
		saddr.sin_family = AF_INET;
		saddr.sin_port = htons(log_port);
		inet_aton(log_host, &saddr.sin_addr);
		connect(log_fd, (struct sockaddr*)&saddr, sizeof(saddr));
	}
	return;
#endif
}

void log_tool_exit()
{
#if 0
	closelog();
#else
	if (log_fd >= 0)
	{
		close(log_fd);
	}
#endif
	return;
}

void get_log_time(char* buf)
{
	struct tm *tmp;
	char tmpbuf[100];

	struct timeval tv;
	struct timezone tz;
	
	gettimeofday(&tv, &tz);

	char ntp_timezone[100];
	system_config_get("ntpserver_select", ntp_timezone);
	int flag = 0;
	if (ntp_timezone[3] == '+')
	{
		flag = 1;
	}
	else
	{
		flag = 0;
	}
	int timezone_offset = atoi(ntp_timezone + 4);

	struct timeval diff_tv = {0, 0};
	struct timeval disp_tv;
	diff_tv.tv_sec = 3600 * 8;
	timeradd(&tv, &diff_tv, &disp_tv);
	diff_tv.tv_sec = 3600 * timezone_offset;
	if (flag == 1)
	{
		timersub(&disp_tv, &diff_tv, &disp_tv);
	}
	else
	{
		timeradd(&disp_tv, &diff_tv, &disp_tv);
	}
	tmp = localtime(&disp_tv.tv_sec);
	strftime(tmpbuf, sizeof(tmpbuf) - 1, "%Y-%m-%dT%T", tmp);
	sprintf(buf, "%s.%d%c%02d:00Z", tmpbuf, (int)disp_tv.tv_usec, flag?'+':'-', timezone_offset);
}

void log_tool_log(int log_fac, int log_level, const char* fmt, ...)
{
	va_list ap;
	char log_line[2000];

	//get log_fac level
	char log_level_buf[100];
	sprintf(log_level_buf, "<%d>%d", log_fac, log_level);
	//get time
	char log_time[100];
	get_log_time(log_time);
	//get Model
	char module_name[100];
	system_config_get("Device_name", module_name);
	//get process
	char process[100];
	strcpy(process, log_prefix);
	//get message
	char message[1000];
	va_start(ap, fmt);
	vsnprintf(message, sizeof(message) - 1, fmt, ap);
	va_end(ap);

	char line_prefix[200];
	sprintf(line_prefix, "%s %s %s %s: ", log_level_buf, log_time, module_name, process);

	strcpy(log_line, line_prefix);
	strcat(log_line, message);

#if 0
	syslog(LOG_USER | LOG_NOTICE, "%s", log_line);
#else
	send(log_fd, log_line, strlen(log_line), 0);
#endif
	return;
}

/*
 * for netgear, the id must be "0", and prefix must be "[xxxx]" format, and length must be less than 40
 * prefix is process name
 * */
void syslog_tool_init(const char* id, const char* prefix)
{
	openlog(id, 0, 0);

	if (prefix)
	{
		if (strlen(prefix) < sizeof(syslog_prefix) - 1)
		{
			strcpy(syslog_prefix, prefix);
		}
	}
	return;
}

void syslog_tool_log(const char* fmt, ...)
{
    va_list ap;
    char fmt_buf[1000];
    char log_line[2000];
    strcpy(fmt_buf, syslog_prefix);
    strcat(fmt_buf, fmt);
    va_start(ap, fmt);
    vsnprintf(log_line, sizeof(log_line) - 1, fmt_buf, ap);
    va_end(ap);
    syslog(LOG_USER | LOG_NOTICE, "%s", log_line);
	return;
}

void syslog_tool_exit()
{
	closelog();
	return;
}
