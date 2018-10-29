#ifndef _SRC_VLAN_TOPIC_H_
#define _SRC_VLAN_TOPIC_H_

#include <stdio.h>
#include "cJSON.h"

#define TOPIC_ACT_NONE (0)
#define TOPIC_ACT_ADD (1)
#define TOPIC_ACT_DEL (2)

#ifdef __cplusplus
extern "C" {
#endif

char* handle_mqtt_topic(char* req_str, int req_len, char* req_topic, char* ret_topic, char* add_topic, char* del_topic);


#ifdef __cplusplus
}
#endif

#endif
