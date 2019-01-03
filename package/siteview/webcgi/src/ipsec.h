
#ifndef __IPSEC_H_
#define __IPSEC_H_

#define MAX_IPSEC_RULE 4

/* ipsec策略基础配置 */
typedef struct ipsec_policy {
    int enabled;
    char name[33];
    char mode[20];
    char local_subnet[16];
    char local_netmask[16];
    char remote_host[128];
    char remote_subnet[16];
    char remote_netmask[16];
    char psk[65];
    char ike_proposal_1[32];
    char ike_proposal_2[32];
    char ike_proposal_3[32];
    char ike_proposal_4[32];
    char exchange_mode[16];
    char negotiate_mode[16];
    int ikelifetime;
    int dpd_enable;
    int dpd_interval;
    char protocol[10];
    char encap_mode[16];
    char ph2_proposal_1[32];
    char ph2_proposal_2[32];
    char ph2_proposal_3[32];    
    char ph2_proposal_4[32];
    char pfs[10];
    int salifetime;
} ipsec_policy_t;

int get_ipsec_policy(cgi_request_t * req, cgi_response_t * resp);
int ipsec_policy_config(cgi_request_t * req, cgi_response_t * resp);

#endif
