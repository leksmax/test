#include <mongoose.h>
#include "file_tool.h"

#define VPNLOGD_TMPFILE "/tmp/vpnlogd-tmp.log"
#define VPNLOGD_FILE "/tmp/vpnlogd.log"
#define LINE_SIZE	(1000)

int file_limit = 16000;
int del_lines = 40;

int trunc_headerlines(const char* file_name, const char* tmp_file_name, int lines)
{
	int ret = -1;
	FILE* orig_fp = NULL;
	FILE* tmp_fp = NULL;
	orig_fp = fopen(file_name, "r");
	tmp_fp = fopen(tmp_file_name, "w");
	char line[LINE_SIZE];
	if (orig_fp && tmp_fp)
	{
		int i;
		for(i = 0; i < del_lines; i++)
		{
			fgets(line, sizeof(line) - 1, orig_fp);
		}
		while(fgets(line, sizeof(line) - 1, orig_fp))
		{
			fputs(line, tmp_fp);
		}
		ret = 0;
	}
	if (orig_fp)
		fclose(orig_fp);
	if (tmp_fp)
		fclose(tmp_fp);
	if (ret == 0)
	{
		remove(file_name);
		rename(tmp_file_name, file_name);
		remove(tmp_file_name);
	}
	return ret;
}

void log2file(const char* file_name, char* data, size_t len)
{
#if 1
	int file_size = get_file_len((char*)file_name);
	if (file_size >= file_limit)
	{
		printf("need trunc file\n");
		trunc_headerlines(file_name, VPNLOGD_TMPFILE, del_lines);
	}
#endif
	char line[LINE_SIZE] = "";
	size_t copy_len = sizeof(line) - 2;
	if (len < copy_len)
	{
		copy_len = len;
	}
	strncpy(line, data, copy_len);
	line[copy_len] = 0;
	strcat(line, "\n");
	append_line((char*)file_name, line);
	return;
}

void dump_str(char* data, int len)
{
	char line[LINE_SIZE] = "";
	int copy_len = sizeof(line) - 2;
	if (len < copy_len)
	{
		copy_len = len;
	}
	strncpy(line, data, copy_len);
	line[copy_len] = 0;
	strcat(line, "\n");
	printf("%s", line);
	return;
}

static int create_udp_listen_socket(const char *host, u_short port)
{
	int listen_fd = -1;
	struct  sockaddr_in     addr;

	listen_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (listen_fd > 0)
	{
		int sock_opt = 1;
		if ((setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, (void *) &sock_opt,
			sizeof (sock_opt))) == -1) {
		}
		bzero(&addr, sizeof addr);
		addr.sin_family = AF_INET;
		if (!host)
		{
			//addr.sin_addr.s_addr = htonl(INADDR_ANY);
			addr.sin_addr.s_addr = inet_addr("0.0.0.0");
		}
		else
		{
			addr.sin_addr.s_addr = inet_addr(host);
		}
		addr.sin_port = htons((u_short)port);
		int bind_ret = bind(listen_fd, (struct sockaddr *)&addr,sizeof(addr));
		if (bind_ret < 0)
		{
			close(listen_fd);
			listen_fd = -1;
		}
		else
		{
			listen(listen_fd, 80);
		}
	}
	return listen_fd;
}

int logd_init(const char* host, short port)
{
	int sock = create_udp_listen_socket(host, port);

	return sock;
}

void logd_select(int sock)
{	
	struct sockaddr_in	addr;
	socklen_t addr_len = sizeof(addr);
	fd_set			read_fds;
	int			select_ret;

	FD_ZERO(&read_fds);
	FD_SET(sock, &read_fds);
	struct timeval select_timeout;
	select_timeout.tv_sec = 3;
	select_timeout.tv_usec = 0;
	//MY_DEBUG_INFO("select_fd = %d\n", server->listen_fd);
	select_ret = select(sock + 1, &read_fds, 0, 0, &select_timeout);
	if (select_ret > 0)
	{
		char line[LINE_SIZE];
		ssize_t len = recvfrom(sock, line, sizeof(line) - 2, 0, (struct sockaddr*)&addr, (socklen_t*)&addr_len);
		if (len > 0)
		{
			log2file(VPNLOGD_FILE, line, len);
		}
	}
}

void logd_run(int sock)
{
	while(1)
	{
		logd_select(sock);
	}
}

int main()
{
	int ret = 0;
	daemon(1, 0);
	int sock= logd_init("127.0.0.1", 7172);
	if (sock < 0)
	{
		ret = -1;
		return ret;
	}
	logd_run(sock);
	return ret;
}
