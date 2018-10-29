#ifndef _SRC_CTRL_CONFIG_H_
#define _SRC_CTRL_CONFIG_H_

#include "cJSON.h"

#ifdef __cplusplus
	extern "C" {
#endif

void config_get_sn(char *buf);
cJSON* config_get_members();
void config_add_member(cJSON* add_member);
void config_del_member(cJSON* del_member);

#ifdef __cplusplus
	}
#endif

#endif
