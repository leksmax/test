
#ifndef __IPFW_H_
#define __IPFW_H_

#define CHAIN_NAT		"traffic_meter"
#define IPSET_WHITEIP   "portal_whiteip"

void ipfw_init(char *gw_address, int gw_port);
void ipfw_destroy();

void ipfw_allow_user(char *ip);
void ipfw_deny_user(char *ip);

#endif

