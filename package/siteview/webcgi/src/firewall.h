
#ifndef __FIREWALL_H_
#define __FIREWALL_H_

#include "utils.h"
#include "servlet.h"

int port_forward_list(cgi_request_t *req, cgi_response_t *resp);
int port_forward_config(cgi_request_t *req, cgi_response_t *resp);

int port_trigger_list(cgi_request_t *req, cgi_response_t *resp);
int port_trigger_config(cgi_request_t *req, cgi_response_t *resp);

#endif
