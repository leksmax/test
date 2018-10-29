#ifndef _SRC_CTRL_SERVER_JSON_H_
#define _SRC_CTRL_SERVER_JSON_H_

#include "ctrl_server.h"
#include "cJSON.h"

#define ACT_AskNeighbor 1
#define ACT_StartVpn 2
#define ACT_StopVpn 3
#define ACT_AddVpathList 4
#define ACT_DelVpathList 5
#define ACT_AddVpath 6
#define ACT_DelVpath 7
#define ACT_GetRoute 8
#define ACT_AddPeer 9
#define ACT_DelPeer 10
#define ACT_AddManager 11
#define ACT_AddPublicVpathList 12
#define ACT_DelPublicVpathList 13
#define ACT_GetVpnStatus 14
#define ACT_GetServerList 15
#define	ACT_GetDeviceInfo	16
#define	ACT_GetAttachDevice 17
#define	ACT_GetPackage 18
#define	ACT_GetVportOn 19
#define ACT_GetTraffic 20
#define ACT_DelManager 21
#define ACT_TurnOnVpnLog 22
#define ACT_TurnOffVpnLog 23
#define ACT_GetVpathList 24
#define ACT_ReloadMember 25
#define ACT_DumpNodes 26
#define ACT_DumpMembers 27
#define ACT_PingMembers 28
#define ACT_GetConnectInfo 29
#define ACT_SetDebugLevel 100

#ifdef __cplusplus
extern "C" {
#endif
cJSON *new_vpn_jsonreq(ctrl_request_t *request);
void delete_vpn_jsonreq(cJSON *jsonreq);
void handle_vpn_jsonreq(cJSON *jsonreq, ctrl_request_t *request);

#ifdef __cplusplus
}
#endif

#endif
