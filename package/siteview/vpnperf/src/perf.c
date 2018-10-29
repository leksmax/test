
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>

#include "log.h"
#include "perf.h"

int do_perf_server()
{
    pid_t pid;

    pid = fork();
    if(pid < 0)
    {
        return -1;
    }
    else if(pid == 0)
    {
        if(execl("/usr/bin/iperf", "iperf", "-s", "-p", "5001", NULL) < 0)
        {
            log_error("execl: %s\n", strerror(errno));
        }
    }

    return pid;
}

int do_perf_client(char *ip, int *band)
{
    int ret = 0;
    FILE *fp = NULL;
    char cmd[256] = {0};
    char line[128] = {0};
    int result = 0;

    snprintf(cmd, sizeof(cmd), "/usr/bin/iperf -c %s -p %d -t %d -y C 2>&1", ip, IPERF_TCP_PORT, IPERF_TEST_TIME);
    fp = popen(cmd, "r");
    if(!fp)
    {
        log_error("popen failed!\n");
        return -1;
    }

    fgets(line, sizeof(line), fp);

    //log_debug("line = %s\n", line);

    ret = sscanf(line, "%*[^,],%*[^,],%*[^,],%*[^,],%*[^,],%*[^,],%*[^,],%*[^,],%d", &result);
    if(ret != 1)
    {
        *band = 0;
        log_warn("iperf failed!\n");
    }
    else
    {
        *band = result / 1024;
        log_debug("iperf ok! band = %d kbps\n", *band);
    }
    
    pclose(fp);

    return 0;
}

#if 0
int g_debug_level = LOG_ALL;

int main(int argc, char *argv[])
{
    int pid_iperfd;

    pid_iperfd = do_perf_server();

    do_perf_client("192.168.246.1");

    if(pid_iperfd > 0)
    {
        kill(pid_iperfd, SIGKILL);
    }

    return 0;
}
#endif
