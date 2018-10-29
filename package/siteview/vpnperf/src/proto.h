
#ifndef __PROTO_H_
#define __PROTO_H_

#include <stdint.h>

#define MEMBER_DISCOVERY 0x0
//#define MEMBER_DISCOVERY 0x1
#define MEMBER_PING_REQ  0x02
#define MEMBER_PING_RESP 0x04
#define MEMBER_PERF_REQ  0x08
#define MEMBER_PERF_RESP 0x16

typedef struct {
    uint8_t type;
    uint8_t data[0];
}__attribute__((packed)) proto_msg_t;

typedef struct {
    uint8_t type;
    uint8_t mode;       /* client/server */
    uint8_t running;    /* 0/1 stop/running */
    uint32_t time;
    uint32_t src_ip;
    uint16_t src_port;
    uint32_t dst_ip;
    uint16_t dst_port;
    uint64_t transfer;
    uint32_t bandwidth;
}__attribute__((packed)) perf_proto_t;

#endif
