/*
 * Copyright (c) 2017 Qualcomm Technologies, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 */

#ifndef _CFG80211_NL_H
#define _CFG80211_NL_H

#include "wlanif_cmn.h"
#include "nl80211_copy.h"
#include "cfg80211_nlwrapper_pvt.h"
#include "qca-vendor.h"
#include "ieee80211_ioctl.h"

extern int finish_handler(struct nl_msg *msg, void *arg);
extern int error_handler(struct sockaddr_nl *nla, struct nlmsgerr *err, void *arg);
extern int valid_handler(struct nl_msg *msg, void *arg);
extern int ack_handler(struct nl_msg *msg, void *arg);

#define MAX_CMD_LEN 128
static const unsigned NL80211_ATTR_MAX_INTERNAL = 256;

struct wdev_info {
    int wiphy_idx;
    enum nl80211_iftype nlmode;
    char macaddr[ETH_ALEN];
    char essid[64];
    char name[IFNAMSIZ];
    int freq;
};

struct wlanif_cfg80211_cmn {
    struct nl_sock *gen_sock;
    int drv_id;
};

/*Structure for private and public ioctls*/
struct wlanif_cfg80211_priv {
    /* QCA Context for all vendor specfic nl80211 message */
    wifi_cfg80211_context cfg80211_ctx_qca;
    /* Generic nl80211 context */
    struct wlanif_cfg80211_cmn cfg80211_ctx_cmn;
};



enum qca_nl80211_vendor_subcmds_internals {
	QCA_NL80211_VENDOR_SUBCMD_SET_PARAMS = 200,
	QCA_NL80211_VENDOR_SUBCMD_GET_PARAMS = 201,
	QCA_NL80211_VENDOR_SUBCMD_NAWDS_PARAMS = 203,
	QCA_NL80211_VENDOR_SUBCMD_HMWDS_PARAMS = 204,
	QCA_NL80211_VENDOR_SUBCMD_ALD_PARAMS = 205,
	QCA_NL80211_VENDOR_SUBCMD_ATF = 206,
	QCA_NL80211_VENDOR_SUBCMD_WNM = 207,
	QCA_NL80211_VENDOR_SUBCMD_HMMC = 208,
	QCA_NL80211_VENDOR_SUBCMD_SET_MAXRATE = 209,
	QCA_NL80211_VENDOR_SUBCMD_VENDORIE = 210,
	QCA_NL80211_VENDOR_SUBCMD_NAC = 211,
	QCA_NL80211_VENDOR_SUBCMD_LIST_SCAN = 212,
	QCA_NL80211_VENDOR_SUBCMD_LIST_CAP = 213,
	QCA_NL80211_VENDOR_SUBCMD_LIST_STA = 214,
	QCA_NL80211_VENDOR_SUBCMD_ACTIVECHANLIST = 215,
	QCA_NL80211_VENDOR_SUBCMD_LIST_CHAN = 216,
	QCA_NL80211_VENDOR_SUBCMD_LIST_CHAN160 = 217,
	QCA_NL80211_VENDOR_SUBCMD_DBGREQ     = 218,
	QCA_NL80211_VENDOR_SUBCMD_PHYSTATS = 219,
	QCA_NL80211_VENDOR_SUBCMD_ATHSTATS = 220,
	QCA_NL80211_VENDOR_SUBCMD_PHYSTATSCUR = 221,
	QCA_NL80211_VENDOR_SUBCMD_EXTENDEDSTATS = 222,
	QCA_NL80211_VENDOR_SUBCMD_80211STATS = 223,
	QCA_NL80211_VENDOR_SUBCMD_STA_STATS = 224,
	QCA_NL80211_VENDOR_SUBCMD_CLONEPARAMS = 225,

	QCA_NL80211_VENDORSUBCMD_ADDMAC = 226,
	QCA_NL80211_VENDORSUBCMD_DELMAC = 227,
	QCA_NL80211_VENDORSUBCMD_KICKMAC = 228,
	QCA_NL80211_VENDORSUBCMD_CHAN_WIDTHSWITCH = 229,
	QCA_NL80211_VENDORSUBCMD_WIRELESS_MODE = 230,
	QCA_NL80211_VENDORSUBCMD_AC_PARAMS = 231,
	QCA_NL80211_VENDORSUBCMD_RC_PARAMS = 232,
	QCA_NL80211_VENDORSUBCMD_SETFILTER = 233,
	QCA_NL80211_VENDORSUBCMD_MAC_COMMANDS = 234,
	QCA_NL80211_VENDORSUBCMD_WMM_PARAMS = 235,
	QCA_NL80211_VENDORSUBCMD_COUNTRY_CONFIG = 236,
	QCA_NL80211_VENDORSUBCMD_HWADDR_CONFIG = 237,
	QCA_NL80211_VENDORSUBCMD_AGGR_BURST_CONFIG = 238,
	QCA_NL80211_VENDORSUBCMD_ATF_SCHED_DURATION_CONFIG = 239,
	QCA_NL80211_VENDORSUBCMD_TXRX_PEER_STATS = 240,
	QCA_NL80211_VENDORSUBCMD_CHANNEL_CONFIG = 241,
	QCA_NL80211_VENDORSUBCMD_SSID_CONFIG = 242,
	QCA_NL80211_VENDORSUBCMD_SEND_MGMT = 243,
};

/*Attr list for Setparam */
enum qca_wlan_set_params {
    QCA_WLAN_VENDOR_ATTR_SETPARAM_INVALID = 0,
    QCA_WLAN_VENDOR_ATTR_SETPARAM_COMMAND,
    QCA_WLAN_VENDOR_ATTR_SETPARAM_VALUE,

    /* keep last */
    QCA_WLAN_VENDOR_ATTR_SETPARAM_LAST,
    QCA_WLAN_VENDOR_ATTR_SETPARAM_MAX =
    QCA_WLAN_VENDOR_ATTR_SETPARAM_LAST - 1
};

int getName_cfg80211(void *,const char *ifname, char *name );
int isAP_cfg80211(void *, const char * ifname, uint32_t *result);
int getBSSID_cfg80211(void *, const char *ifname, struct ether_addr *BSSID );
int getESSID_cfg80211(void *ctx, const const char * ifname, void *buf, uint32_t *len );
int getFreq_cfg80211(void *, const char * ifname, int32_t * freq);
int getChannelWidth_cfg80211(void *, const char *ifname, int * chwidth);
int getChannelExtOffset_cfg80211(void *, const char *ifname, int * choffset);
int getChannelBandwidth_cfg80211(void *, const char *ifname, int * bandwidth);
int getAcsState_cfg80211(void *, const char *ifname, int * acsstate);
int getCacState_cfg80211(void *, const char *ifname, int * cacstate);
int getParentIfindex_cfg80211(void *, const char *ifname, int * cacstate);
int getSmartMonitor_cfg80211(void *, const char *ifname, int * smartmonitor);
int getGenericInfoAtf_cfg80211(void *, const char *ifname, int cmd, void * chanInfo, int chanInfoSize);
int getGenericInfoAld_cfg80211(void *, const char *ifname, void * chanInfo, int chanInfoSize);
int getGenericInfoHmwds_cfg80211(void *, const char *ifname, void * chanInfo, int chanInfoSize);
int getGenericNac_cfg80211(void *, const char *ifname, void * config, int configSize);
int getCfreq2_cfg80211(void *, const char * ifname, int32_t * cfreq2);
int getChannelInfo_cfg80211(void *, const char *ifname, void * chanInfo, int chanInfoSize);
int getChannelInfo160_cfg80211(void *, const char *ifname, void * chanInfo, int chanInfoSize);
int getStationInfo_cfg80211(void *, const char *ifname, void *buf, int* len);
int getDbgreq_cfg80211(void * , const char *ifname, void *data , uint32_t data_len);
int getExtended_cfg80211(void * , const char *ifname, void *data , uint32_t data_len);
int addDelKickMAC_cfg80211(void *, const char *ifname, int operation, void *data, uint32_t len);
int setFilter_cfg80211(void *, const char *ifname, void *data, uint32_t len);
int getWirelessMode_cfg80211(void * ctx , const char *ifname, void *data, uint32_t len);
int sendMgmt_cfg80211(void *, const char *ifname, void *data, uint32_t len);
int setParamMaccmd_cfg80211(void *, const char *ifname, void *data, uint32_t len);
int setParam_cfg80211(void *, const char *ifname,int cmd, void *data, uint32_t len);
int getStaStats_cfg80211(void *, const char *ifname, void *data, uint32_t len);

#endif
