
#ifndef __VLAN_H_
#define __VLAN_H_

int get_vlan_entry(cgi_request_t * req, cgi_response_t * resp);
int vlan_entry_config(cgi_request_t * req, cgi_response_t * resp);

int port_vlan_list(cgi_request_t * req, cgi_response_t * resp);
int port_vlan_config(cgi_request_t * req, cgi_response_t * resp);

#endif
