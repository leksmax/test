
#ifndef __RPCD_H_
#define __RPCD_H_

#define UDP_SERVER_PORT 9999
#define UDS_SERVER_PATH "/var/run/vpnperf.sock"

#define UDS_BACKLOG 10
#define MAX_UDS_CLIENT 10

typedef struct {
    int sockfd;
} uds_client_t;

typedef struct {
    int udpfd;
    int udsfd;
    int uds_backlog;
} rpcd_t;

void rpcd_loop();

#endif
