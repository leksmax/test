#ifndef _SRC_VPN_TOOL_H_
#define _SRC_VPN_TOOL_H_

#include "cJSON.h"

#ifdef __cplusplus
extern "C" {
#endif

cJSON* vpn_tool_stop_vpn(char* team_id);
cJSON* vpn_tool_start_vpn(char* team_id);
cJSON* vpn_tool_reload_member(int reconnect_flag, char* proxyIp);
cJSON* vpn_tool_get_vpn_traffic();

cJSON* vpn_tool_get_direct_list(char* team_id);

cJSON* vpn_tool_add_whitelist(char* team_id, cJSON* list_item);

cJSON* vpn_tool_del_whitelist(char* team_id, cJSON* list_item);
cJSON* vpn_tool_get_whitelist(char* team_id);
cJSON* vpn_tool_get_members_traffic();
cJSON* vpn_tool_get_members_ping();
cJSON* vpn_tool_get_connectInfo();
int vpn_tool_get_member_bandwidth(char* ip, int *upload, int *download);

#ifdef __cplusplus
}
#endif
#endif
