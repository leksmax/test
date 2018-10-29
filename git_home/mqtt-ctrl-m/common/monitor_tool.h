#ifndef _SRC_MONITOR_TOOL_H_
#define _SRC_MONITOR_TOOL_H_


#include "cJSON.h"

#ifdef __cplusplus
extern "C" {
#endif

cJSON* monitor_tool_cpu();
cJSON* monitor_tool_memory();
cJSON* monitor_tool_vpntraffic();
cJSON* monitor_tool_vpnping();
cJSON* monitor_tool_vpnband(char* ip);
cJSON* monitor_tool_link();
cJSON* monitor_tool_equipment_info();
cJSON* monitor_tool_temprature();
cJSON* monitor_tool_nmap();

#ifdef __cplusplus
}
#endif

#endif
