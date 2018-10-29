
#ifndef __PERF_H_
#define __PERF_H_

#define IPERF_TCP_PORT 5001
#define IPERF_TEST_TIME 10
#define IPERF_RESULT_FILE "/tmp/iperf.result"

int do_perf_server();
int do_perf_client(char * ip, int * band);

#endif
