
#ifndef __SERVICES_H_
#define __SERVICES_H_

int get_ddns_services(cgi_request_t * req, cgi_response_t * resp);
int get_ddns_config(cgi_request_t * req, cgi_response_t * resp);
int set_ddns_config(cgi_request_t * req, cgi_response_t * resp);

int get_upnpd_rules(cgi_request_t * req, cgi_response_t * resp);
int del_upnpd_rules(cgi_request_t * req, cgi_response_t * resp);
int get_upnpd_config(cgi_request_t * req, cgi_response_t * resp);
int set_upnpd_config(cgi_request_t * req, cgi_response_t * resp);

#endif
