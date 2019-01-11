
#ifndef __STATUS_H_
#define __STATUS_H_

enum {
    LINK_DOWN = 0,
    LINK_UP
};

enum {
    DUPLEX_HALF = 0,
    DUPLEX_FULL
};

enum {
    SPEED_10 = 1,
    SPEED_100,
    SPEED_1000
};

typedef struct port_info {
    unsigned int port;
    unsigned int link;
    unsigned int speed;
    unsigned int duplex;
} port_info_t;

int get_attached_devices(cgi_request_t *req, cgi_response_t *resp);

#endif
