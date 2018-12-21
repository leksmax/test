#ifndef __IPT_MATCH_ACCOUNT_H
#define __IPT_MATCH_ACCOUNT_H

#define IPT_ACCOUNT_NAME_LEN		64

struct xt_match_ipt_account{
	uint32_t network;
	uint32_t netmask;
	unsigned char name[IPT_ACCOUNT_NAME_LEN + 1];
};

#endif // __IPT_MATCH_ACCOUNT_H
