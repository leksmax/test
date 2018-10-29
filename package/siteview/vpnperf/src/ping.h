
#ifndef __PING_H_
#define __PING_H_

/* 仅支持ipv4 ping */
int ping_rtt_avg(char *ip, int count, int timeout, int *rtt, int *loss);

#endif
