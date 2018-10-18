/*
 * Copyright (c) 2017 Qualcomm Technologies, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 */

#include <net/if.h>
#include <net/ethernet.h>
#include <asm/types.h>
#define _LINUX_IF_H /* Avoid redefinition of stuff */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>

struct ucred {
    __u32   pid;
    __u32   uid;
    __u32   gid;
};

#include <ieee80211_external.h>
#include "wlanif_cfg80211.h"

#define DEBUG

#ifdef DEBUG
#define TRACE_ENTRY() fprintf(stderr, "%s: Enter \n",__func__)
#define TRACE_EXIT() fprintf(stderr, "%s: Exit \n",__func__)
#define TRACE_EXIT_ERR() fprintf(stderr, "%s: Exit with err %d\n",__func__,ret)
#else
#define TRACE_ENTRY()
#define TRACE_EXIT()
#endif

/* nl handler for IW based ioctl*/
static int wdev_info_handler(struct nl_msg *msg, void *arg)
{
    struct nlattr *nl_msg[NL80211_ATTR_MAX + 1];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct wdev_info *info = arg;

    nla_parse(nl_msg, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

    if (nl_msg[NL80211_ATTR_WIPHY])
    {
        info->wiphy_idx = nla_get_u32(nl_msg[NL80211_ATTR_WIPHY]);
    } else {
        fprintf(stderr, "NL80211_ATTR_WIPHY not found\n");
        return -EINVAL;
    }

    if (nl_msg[NL80211_ATTR_IFTYPE])
    {
        info->nlmode = nla_get_u32(nl_msg[NL80211_ATTR_IFTYPE]);
    } else {
        fprintf(stderr, "NL80211_ATTR_IFTYPE not found\n");
        return -EINVAL;
    }

    if (nl_msg[NL80211_ATTR_MAC])
    {
        memcpy(info->macaddr, nla_data(nl_msg[NL80211_ATTR_MAC]), ETH_ALEN);
    } else {
        fprintf(stderr, "NL80211_ATTR_MAC not found\n");
        return -EINVAL;
    }

    if (nl_msg[NL80211_ATTR_SSID])
    {
        memcpy(info->essid, nla_data(nl_msg[NL80211_ATTR_SSID]), nla_len(nl_msg[NL80211_ATTR_SSID]));
        info->essid[nla_len(nl_msg[NL80211_ATTR_SSID])] = '\0';
    } else {
        fprintf(stderr, "NL80211_ATTR_SSID not found\n");
        return -EINVAL;
    }

    if(nl_msg[NL80211_ATTR_IFNAME])
    {
        memcpy(info->name, nla_data(nl_msg[NL80211_ATTR_IFNAME]), nla_len(nl_msg[NL80211_ATTR_IFNAME]));
        info->name[nla_len(nl_msg[NL80211_ATTR_IFNAME])] = '\0';
    } else {
        fprintf(stderr, "NL80211_ATTR_IFNAME not found\n");
        return -EINVAL;
    }

    if(nl_msg[NL80211_ATTR_WIPHY_FREQ])
    {
        info->freq = nla_get_u32(nl_msg[NL80211_ATTR_WIPHY_FREQ]);
        fprintf(stderr, "NL80211_ATTR_WIPHY_FREQ freq %d\n",info->freq);
    }

    return NL_SKIP;
}

/*allocate and send nlmsg to handle IW based ioctl*/
int send_nlmsg_wdev_info ( const char *ifname, wifi_cfg80211_context *cfgCtx, struct wdev_info *dev_info)
{
    struct nl_msg *nlmsg;
    struct nl_cb *cb;
    int ret, err;

    nlmsg = nlmsg_alloc();
    if (!nlmsg) {
        fprintf(stderr, "ERROR: Failed to allocate netlink message for msg.\n");
        return -ENOMEM;
    }

    cb = nl_cb_alloc(NL_CB_DEFAULT);
    if (!cb) {
        fprintf(stderr, "ERROR: Failed to allocate netlink callbacks.\n");
        nlmsg_free(nlmsg);
        return -ENOMEM;
    }

    /* Prepare nlmsg get the Interface attributes */
    genlmsg_put(nlmsg, 0, 0, cfgCtx->nl80211_family_id , 0, 0, NL80211_CMD_GET_INTERFACE, 0);
    nla_put_u32(nlmsg, NL80211_ATTR_IFINDEX, if_nametoindex(ifname));

    err = 1;

    nl_cb_err(cb, NL_CB_CUSTOM, error_handler, &err);
    nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &err);
    nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &err);

    nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM,wdev_info_handler , dev_info);

    /* send message */
    ret = nl_send_auto_complete(cfgCtx->cmd_sock, nlmsg);
    if (ret < 0) {
        goto out;
    }

    /*   wait for reply */
    while (err > 0) {  /* error will be set by callbacks */
        ret = nl_recvmsgs(cfgCtx->cmd_sock, cb);
        if (ret) {
            fprintf(stderr, "nl80211: %s->nl_recvmsgs failed: %d\n", __func__, ret);
        }
    }

out:
    if (cb) {
        nl_cb_put(cb);
        free(nlmsg);
    }
    return err;
}

/*Function to send nl message through wrapper*/
static int send_command_cfg80211 (wifi_cfg80211_context *cfgCtx, const char *ifname, int cmd, void *buf, size_t buflen)
{
    int msg=0;
    struct cfg80211_data buffer;
    buffer.data = buf;
    buffer.length = buflen;
    buffer.callback = NULL;
    fprintf(stderr,"Inside %s \n",__func__);
    msg = wifi_cfg80211_sendcmd(cfgCtx ,cmd, ifname, (char *)&buffer, buflen);
    if (msg < 0) {
        fprintf(stderr,"Couldn't send NL command\n");
        return -1;
    }
    return 0;
}

/*cfg80211 command for getparam parameter policy */
static struct nla_policy
wlan_cfg80211_get_params_policy[QCA_WLAN_VENDOR_ATTR_GETPARAM_MAX + 1] = {

    [QCA_WLAN_VENDOR_ATTR_GETPARAM_COMMAND] = {.type = NLA_U32 },
};

/*Function to parse the params obtained from driver */
static void cfg80211_parse_param(struct cfg80211_data *buffer)
{
    u_int32_t temp;
    u_int32_t *value = (u_int32_t *)buffer->data;
    struct nlattr *attr_vendor[NL80211_ATTR_MAX_INTERNAL];
    nla_parse(attr_vendor, QCA_WLAN_VENDOR_ATTR_GETPARAM_MAX,
            (struct nlattr *)buffer->nl_vendordata,
            buffer->nl_vendordata_len, wlan_cfg80211_get_params_policy);

    if (attr_vendor[QCA_WLAN_VENDOR_ATTR_GETPARAM_COMMAND]) {
        temp = nla_get_u32(attr_vendor[QCA_WLAN_VENDOR_ATTR_GETPARAM_COMMAND]);
        *value = temp;
    } else {
        fprintf(stderr,"\n Invalid value.Failed to get the value form driver!");
        *value = -EINVAL;
    }

    return;
}

/*cfg80211 command for getwificonfiguration parameter policy */
static struct nla_policy
wlan_cfg80211_get_wificonfiguration_policy[QCA_WLAN_VENDOR_ATTR_CONFIG_MAX + 1] = {

    [QCA_WLAN_VENDOR_ATTR_PARAM_DATA] = {.type = NLA_STRING },
};

/*Function to parse the generic params obtained from driver */
static void cfg80211_generic_parse_param(struct cfg80211_data *buffer)
{
    char temp[30];
    char *value = (char *)buffer->data;
    struct nlattr *attr_vendor[QCA_WLAN_VENDOR_ATTR_CONFIG_MAX];
    nla_parse(attr_vendor, QCA_WLAN_VENDOR_ATTR_PARAM_MAX,
            (struct nlattr *)buffer->nl_vendordata, buffer->nl_vendordata_len,
            wlan_cfg80211_get_wificonfiguration_policy);

    if(attr_vendor[QCA_WLAN_VENDOR_ATTR_PARAM_DATA]) {
        char *data = (char *) nla_data(attr_vendor[QCA_WLAN_VENDOR_ATTR_PARAM_DATA]);
        size_t length = strlen(data);
        fprintf(stderr,"%s: Wificonfiguration value %s and length %zu \n",__func__,data,length);
        memcpy(temp,data,length);
    }
    else {
        fprintf(stderr,"\n Invalid value.Failed to get the value form driver!");
        *value = -EINVAL;
    }
    return;
}

/* cfg80211 command to get param from driver */
int send_command_get_cfg80211( wifi_cfg80211_context *cfgCtx, const char *ifname, int op, int *data)
{
    int res = 0;
    struct cfg80211_data buffer;
    struct nl_msg *nlmsg;
    u_int32_t value = 0;
    struct nlattr *nl_venData = NULL;
    buffer.data = &value;
    buffer.length = sizeof(u_int32_t);
    buffer.parse_data = 1;
    buffer.callback = &cfg80211_parse_param;
    fprintf(stderr,"Inside %s \n",__func__);
    nlmsg = (struct nl_msg *)wifi_cfg80211_prepare_command(cfgCtx,QCA_NL80211_VENDOR_SUBCMD_GET_PARAMS, ifname);
    if(nlmsg)
    {
        nl_venData = (struct nlattr *)start_vendor_data(nlmsg);
        if (!nl_venData)
        {
            fprintf(stderr,"failed to start vendor data\n");
            nlmsg_free(nlmsg);
            return -EIO;
        }
        if(nla_put_u32(nlmsg, QCA_WLAN_VENDOR_ATTR_GETPARAM_COMMAND, op ))
        {
            fprintf(stderr, "\n Failed nla_put, \n");
            nlmsg_free(nlmsg);
            return -EIO;
        }
        else
        {
            if (nl_venData)
                end_vendor_data(nlmsg, nl_venData);
            res = send_nlmsg(cfgCtx, nlmsg, &buffer);
            if(res < 0)
            {
                fprintf(stderr, "\n Send nlmsg failed \n");
                return -EIO;
            }
            *data = value;
            return res;
        }
    }
    else
    {
        return -EIO;
    }
    return 0;
}

int wifi_cfg80211_get_generic_command(wifi_cfg80211_context *cfgctx, const char *ifname, int cmdid, char *buf, int len)
{
    struct nl_msg *nlmsg = NULL;
    int res;
    struct nlattr *nl_venData = NULL;
    struct cfg80211_data *buffer = (struct cfg80211_data *) buf;
    buffer->data = buf;
    buffer->length = len;
    buffer->parse_data = 1;
    buffer->callback = &cfg80211_generic_parse_param;
    fprintf(stderr,"Inside %s \n",__func__);
    nlmsg = wifi_cfg80211_prepare_command(cfgctx, QCA_NL80211_VENDOR_SUBCMD_GET_WIFI_CONFIGURATION, ifname);

    if (nlmsg) {
        nl_venData = (struct nlattr *)start_vendor_data(nlmsg);
        if (!nl_venData) {
            fprintf(stderr, "failed to start vendor data\n");
            nlmsg_free(nlmsg);
            return -EIO;
        }
        if (nla_put_u32(nlmsg, QCA_WLAN_VENDOR_ATTR_CONFIG_GENERIC_COMMAND, cmdid)) {
            nlmsg_free(nlmsg);
            return -EIO;
        }
        else
        {
            if (nl_venData) {
                end_vendor_data(nlmsg, nl_venData);
            }
            res = send_nlmsg(cfgctx, nlmsg, buffer);

            if (res < 0) {
                fprintf(stderr, "\n Send nlmsg failed... \n");
                return -EIO;
            }
            return res;
        }

    } else {
        return -EIO;
    }
    return res;
}

/*cfg80211 command to set param in driver*/
int send_command_set_cfg80211(wifi_cfg80211_context *cfgCtx, const char *ifname, int op, int *data, int data_len)
{
    int res = 0;
    struct cfg80211_data buffer;
    struct nl_msg *nlmsg;
    struct nlattr *nl_venData = NULL;
    buffer.data = &data;
    buffer.length = data_len;

    nlmsg = (struct nl_msg *)wifi_cfg80211_prepare_command(cfgCtx,QCA_NL80211_VENDOR_SUBCMD_SET_PARAMS, ifname);

    if(nlmsg)
    {
        nl_venData = (struct nlattr *)start_vendor_data(nlmsg);
        if (!nl_venData)
        {
            fprintf(stderr,"failed to start vendor data\n");
            nlmsg_free(nlmsg);
            return -EIO;
        }

        if(nla_put_u32(nlmsg, QCA_WLAN_VENDOR_ATTR_SETPARAM_COMMAND, op ))
        {
            fprintf(stderr, "\n Failed nla_put, \n");
            nlmsg_free(nlmsg);
            return -EIO;
        }
        if(nla_put_u32(nlmsg, QCA_WLAN_VENDOR_ATTR_SETPARAM_VALUE, *data))
        {
            fprintf(stderr, "\n Failed nla_put, \n");
            nlmsg_free(nlmsg);
            return -EIO;
        }

        end_vendor_data(nlmsg, nl_venData);

        res = send_nlmsg(cfgCtx, nlmsg, &buffer);
        if(res < 0)
        {
            fprintf(stderr, "\n Send nlmsg failed \n");
            return -EIO;
        }
        return res;
    }
    else
    {
        return -EIO;
    }
    return 0;
}

/* Cfg80211 command to send genric commands to driver*/
int send_generic_command_cfg80211(wifi_cfg80211_context *cfgCtx, const char *ifname, int cmd, char *data, int data_len)
{
    int res;
    struct cfg80211_data buffer;
    buffer.data = (void *)data;
    buffer.length = data_len;
    res = wifi_cfg80211_send_generic_command(cfgCtx, QCA_NL80211_VENDOR_SUBCMD_SET_WIFI_CONFIGURATION, cmd, ifname, (char *)&buffer, data_len);
    if (res < 0) {
        fprintf(stderr,"Couldn't send NL command\n");
        return res;
    }
    return 0;
}

/* Function to get name of the dev */
int getName_cfg80211(void *ctx, const char * ifname, char *name )
{

    int ret;
    struct wlanif_cfg80211_priv * cfgPriv;
    struct wdev_info devinfo = {0};

    TRACE_ENTRY();

    cfgPriv = (struct wlanif_cfg80211_priv *) ctx;
    assert(cfgPriv != NULL);

    if ((ret = send_nlmsg_wdev_info(ifname, &(cfgPriv->cfg80211_ctx_qca), &devinfo)) < 0) {
        goto err;
    }

    strcpy( name, devinfo.name );

    TRACE_EXIT();

    return 0;

err:
    TRACE_EXIT_ERR();
    return ret;
}

/* Function to check whether the current device is AP */
int isAP_cfg80211(void *ctx, const char * ifname, uint32_t *result)
{
    int ret;
    struct wlanif_cfg80211_priv * cfgPriv;
    struct wdev_info devinfo = {0};

    TRACE_ENTRY();

    cfgPriv = (struct wlanif_cfg80211_priv *) ctx;
    assert(cfgPriv != NULL);

    if ((ret = send_nlmsg_wdev_info(ifname, &(cfgPriv->cfg80211_ctx_qca), &devinfo)) < 0) {
        goto err;
    }

    *result = ( devinfo.nlmode == NL80211_IFTYPE_AP ? 1 : 0 );

    TRACE_EXIT();
    return 0;

err:
    TRACE_EXIT_ERR();
    return ret;
}

/* Function to get BSSID address */
int getBSSID_cfg80211(void *ctx, const char * ifname, struct ether_addr *BSSID )
{
    int ret;
    struct wlanif_cfg80211_priv * cfgPriv;
    struct wdev_info devinfo = {0};

    TRACE_ENTRY();

    cfgPriv = (struct wlanif_cfg80211_priv *) ctx;
    assert(cfgPriv != NULL);


    if ((ret = send_nlmsg_wdev_info(ifname, &(cfgPriv->cfg80211_ctx_qca), &devinfo)) < 0) {
        goto err;
    }
    memcpy( BSSID, &devinfo.macaddr, ETH_ALEN );

    TRACE_EXIT();
    return 0;

err:
    TRACE_EXIT_ERR();
    return ret;
}

/* Funtion to get ESSID info */
int getESSID_cfg80211(void *ctx, const const char * ifname, void *buf, uint32_t *len )
{
    int ret;
    struct wlanif_cfg80211_priv * cfgPriv;
    struct wdev_info devinfo = {0};

    TRACE_ENTRY();

    cfgPriv = (struct wlanif_cfg80211_priv *) ctx;
    assert(cfgPriv != NULL);


    if ((ret = send_nlmsg_wdev_info(ifname, &(cfgPriv->cfg80211_ctx_qca), &devinfo)) < 0) {
        goto err;
    }

    strlcpy((char*)buf , devinfo.essid , IFNAMSIZ);

    *len = strlen(devinfo.essid);

    TRACE_EXIT();
    return 0;

err:
    TRACE_EXIT_ERR();
    return ret;
}

/* Function to get frequency info*/
int getFreq_cfg80211(void *ctx, const char * ifname, int32_t * freq)
{
    int ret;
    struct wlanif_cfg80211_priv * cfgPriv;
    struct wdev_info devinfo = {0};

    TRACE_ENTRY();

    cfgPriv = (struct wlanif_cfg80211_priv *) ctx;
    assert(cfgPriv != NULL);


    if ((ret = send_nlmsg_wdev_info(ifname, &(cfgPriv->cfg80211_ctx_qca), &devinfo)) < 0) {
        goto err;
    }

    *freq = (devinfo.freq * 100000);
    fprintf(stderr, "%s freq %d\n",__func__,*freq);

    TRACE_EXIT();
    return 0;

err:
    TRACE_EXIT_ERR();
    return ret;
}

/* Function to get channel width*/
int getChannelWidth_cfg80211(void *ctx, const char * ifname, int * chwidth)
{
    int ret;
    struct wlanif_cfg80211_priv * cfgPriv;

    TRACE_ENTRY();

    cfgPriv = (struct wlanif_cfg80211_priv *) ctx;
    assert(cfgPriv != NULL);

    fprintf(stderr, "%s: %p\n",__func__,&(cfgPriv->cfg80211_ctx_qca));
    if ((ret = send_command_get_cfg80211(&(cfgPriv->cfg80211_ctx_qca),ifname, IEEE80211_PARAM_CHWIDTH, chwidth)) < 0)
    {
        fprintf(stderr,"send_command_cfg80211 Failed\n");
        goto err;
    }

    TRACE_EXIT();
    return 0;

err:
    TRACE_EXIT_ERR();
    return ret;
}

/* Function to get channel extoffset */
int getChannelExtOffset_cfg80211(void *ctx, const char * ifname, int * choffset)
{
    int ret;
    struct wlanif_cfg80211_priv * cfgPriv;

    TRACE_ENTRY();

    cfgPriv = (struct wlanif_cfg80211_priv *) ctx;
    assert(cfgPriv != NULL);

    if ((ret = send_command_get_cfg80211(&(cfgPriv->cfg80211_ctx_qca),ifname, IEEE80211_PARAM_CHEXTOFFSET, choffset)) < 0) {
        goto err;
    }

    TRACE_EXIT();
    return 0;

err:
    TRACE_EXIT_ERR();
    return ret;

}

/*Function to get ACS info*/
int getAcsState_cfg80211(void *ctx, const char * ifname, int * acsstate)
{
    int ret;
    struct wlanif_cfg80211_priv * cfgPriv;

    TRACE_ENTRY();

    cfgPriv = (struct wlanif_cfg80211_priv *) ctx;
    assert(cfgPriv != NULL);

    if ((ret = send_command_get_cfg80211(&(cfgPriv->cfg80211_ctx_qca),ifname, IEEE80211_PARAM_GET_ACS, acsstate)) < 0) {
        goto err;
    }

    TRACE_EXIT();
    return 0;

err:
    TRACE_EXIT_ERR();
    return ret;
}

/* Function to get CAC info*/
int getCacState_cfg80211(void *ctx, const char * ifname, int * cacstate)
{
    int ret;
    struct wlanif_cfg80211_priv * cfgPriv;

    TRACE_ENTRY();

    cfgPriv = (struct wlanif_cfg80211_priv *) ctx;
    assert(cfgPriv != NULL);

    if ((ret = send_command_get_cfg80211(&(cfgPriv->cfg80211_ctx_qca),ifname, IEEE80211_PARAM_GET_CAC, cacstate)) < 0) {
        goto err;
    }

    TRACE_EXIT();
    return 0;

err:
    TRACE_EXIT_ERR();
    return ret;
}

/* Function to get ParentIndex info*/
int getParentIfindex_cfg80211(void *ctx, const char * ifname, int * parentIndex)
{
    int ret;
    struct wlanif_cfg80211_priv * cfgPriv;

    TRACE_ENTRY();

    cfgPriv = (struct wlanif_cfg80211_priv *) ctx;
    assert(cfgPriv != NULL);

    if ((ret = send_command_get_cfg80211(&(cfgPriv->cfg80211_ctx_qca),ifname, IEEE80211_PARAM_PARENT_IFINDEX, parentIndex)) < 0) {
        goto err;
    }

    TRACE_EXIT();
    return 0;

err:
    TRACE_EXIT_ERR();
    return ret;
}

/*Function to get smart monitor info*/
int getSmartMonitor_cfg80211(void *ctx, const char * ifname, int * smartmonitor)
{
    int ret;
    struct wlanif_cfg80211_priv * cfgPriv;

    TRACE_ENTRY();

    cfgPriv = (struct wlanif_cfg80211_priv *) ctx;
    assert(cfgPriv != NULL);

    if ((ret = send_command_get_cfg80211(&(cfgPriv->cfg80211_ctx_qca),ifname, IEEE80211_PARAM_RX_FILTER_SMART_MONITOR, smartmonitor)) < 0) {
        goto err;
    }

    TRACE_EXIT();
    return 0;

err:
    TRACE_EXIT_ERR();
    return ret;
}

/*Function to get channel bandwidth*/
int getChannelBandwidth_cfg80211(void *ctx, const char * ifname, int * bandwidth)
{
    int ret;
    struct wlanif_cfg80211_priv * cfgPriv;

    TRACE_ENTRY();

    cfgPriv = (struct wlanif_cfg80211_priv *) ctx;
    assert(cfgPriv != NULL);

    if ((ret = send_command_get_cfg80211(&(cfgPriv->cfg80211_ctx_qca),ifname, IEEE80211_PARAM_BANDWIDTH, bandwidth)) < 0) {
        goto err;
    }

    TRACE_EXIT();
    return 0;

err:
    TRACE_EXIT_ERR();
    return ret;

}

/* Function to get Atf related generic info*/
int getGenericInfoAtf_cfg80211(void *ctx, const char * ifname, int cmd ,void * chanInfo, int chanInfoSize)
{
    int ret;
    struct wlanif_cfg80211_priv * cfgPriv;

    TRACE_ENTRY();

    cfgPriv = (struct wlanif_cfg80211_priv *) ctx;
    assert(cfgPriv != NULL);

    if(cmd == IEEE80211_IOCTL_ATF_SHOWATFTBL)
    {
        struct atf_data atfdata;
        memset(&atfdata, 0, sizeof(atfdata));
        atfdata.id_type = IEEE80211_IOCTL_ATF_SHOWATFTBL;
        atfdata.buf = chanInfo;
        atfdata.len = chanInfoSize;
        ret = send_command_cfg80211(&(cfgPriv->cfg80211_ctx_qca), ifname, QCA_NL80211_VENDOR_SUBCMD_ATF, &atfdata, sizeof(atfdata));
    }
    else
    {
        ret = send_command_cfg80211(&(cfgPriv->cfg80211_ctx_qca), ifname, QCA_NL80211_VENDOR_SUBCMD_ATF, chanInfo, chanInfoSize);
    }

    if (ret < 0) {
        goto err;
    }

    TRACE_EXIT();
    return 0;

err:
    TRACE_EXIT_ERR();
    return ret;
}

/* Function to get Ald related generic info*/
int getGenericInfoAld_cfg80211(void *ctx, const char * ifname,void * chanInfo, int chanInfoSize)
{
    int ret;
    struct wlanif_cfg80211_priv * cfgPriv;

    TRACE_ENTRY();

    cfgPriv = (struct wlanif_cfg80211_priv *) ctx;
    assert(cfgPriv != NULL);

    if ((ret = send_command_cfg80211(&(cfgPriv->cfg80211_ctx_qca), ifname, QCA_NL80211_VENDOR_SUBCMD_ALD_PARAMS, chanInfo, chanInfoSize)) < 0) {
        goto err;
    }

    TRACE_EXIT();
    return 0;

err:
    TRACE_EXIT_ERR();
    return ret;
}

/* Function to hmwds related generic info*/
int getGenericInfoHmwds_cfg80211(void *ctx, const char * ifname,void * chanInfo, int chanInfoSize)
{
    int ret;
    struct wlanif_cfg80211_priv * cfgPriv;

    TRACE_ENTRY();

    cfgPriv = (struct wlanif_cfg80211_priv *) ctx;
    assert(cfgPriv != NULL);

    if ((ret = send_command_cfg80211(&(cfgPriv->cfg80211_ctx_qca), ifname, QCA_NL80211_VENDOR_SUBCMD_HMWDS_PARAMS, chanInfo, chanInfoSize)) < 0) {
        goto err;
    }

    TRACE_EXIT();
    return 0;

err:
    TRACE_EXIT_ERR();
    return ret;
}

/* Function to Nac related generic info*/
int getGenericNac_cfg80211(void *ctx, const char * ifname,void * config, int configSize)
{
    int ret;
    struct wlanif_cfg80211_priv * cfgPriv;

    TRACE_ENTRY();

    cfgPriv = (struct wlanif_cfg80211_priv *) ctx;
    assert(cfgPriv != NULL);

    if ((ret = send_command_cfg80211(&(cfgPriv->cfg80211_ctx_qca), ifname, QCA_NL80211_VENDOR_SUBCMD_NAC, config, configSize)) < 0) {
        goto err;
    }

    TRACE_EXIT();
    return 0;

err:
    TRACE_EXIT_ERR();
    return ret;
}

/* Function to get centre frequency*/
int getCfreq2_cfg80211(void *ctx, const char * ifname, int32_t * cfreq2)
{
    int ret;
    struct wlanif_cfg80211_priv * cfgPriv;

    TRACE_ENTRY();

    cfgPriv = (struct wlanif_cfg80211_priv *) ctx;
    assert(cfgPriv != NULL);

    if ((ret = send_command_get_cfg80211(&(cfgPriv->cfg80211_ctx_qca),ifname, IEEE80211_PARAM_SECOND_CENTER_FREQ,cfreq2)) < 0) {
        goto err;
    }

    TRACE_EXIT();
    return 0;

err:
    TRACE_EXIT_ERR();
    return ret;
}

/* Function to setparam in the driver*/
int setParam_cfg80211(void *ctx, const char *ifname, int cmd, void *data, uint32_t len)
{
    int ret;
    struct wlanif_cfg80211_priv * cfgPriv;

    TRACE_ENTRY();

    cfgPriv = (struct wlanif_cfg80211_priv *) ctx;
    assert(cfgPriv != NULL);

    if((ret = send_command_set_cfg80211(&(cfgPriv->cfg80211_ctx_qca), ifname, cmd, data, len)) < 0) {
        goto err;
    }

    TRACE_EXIT();
    return 0;

err:
    TRACE_EXIT_ERR();
    return ret;
}

/*Functin to set maccmd, special case in argument handling*/
int setParamMaccmd_cfg80211(void *ctx, const char *ifname, void *data, uint32_t len)
{
    int ret,temp[2];
    struct wlanif_cfg80211_priv * cfgPriv;
    memcpy(temp, data, len);

    TRACE_ENTRY();

    cfgPriv = (struct wlanif_cfg80211_priv *) ctx;
    assert(cfgPriv != NULL);

    if((ret = send_command_set_cfg80211(&(cfgPriv->cfg80211_ctx_qca), ifname, temp[0], &temp[1], sizeof(temp[1]))) < 0) {
        goto err;
    }

    TRACE_EXIT();
    return 0;

err:
    TRACE_EXIT_ERR();
    return ret;

}

/* Function to get channel info*/
int getChannelInfo_cfg80211(void *ctx, const char * ifname, void * chanInfo, int chanInfoSize)
{
    int ret;
    struct wlanif_cfg80211_priv * cfgPriv;

    TRACE_ENTRY();

    cfgPriv = (struct wlanif_cfg80211_priv *) ctx;
    assert(cfgPriv != NULL);

    if ((ret = send_command_cfg80211(&(cfgPriv->cfg80211_ctx_qca), ifname, QCA_NL80211_VENDOR_SUBCMD_LIST_CHAN, chanInfo, chanInfoSize)) < 0) {
        goto err;
    }


    TRACE_EXIT();
    return 0;

err:
    TRACE_EXIT_ERR();
    return ret;

}

/* Function to get channel info160*/
int getChannelInfo160_cfg80211(void *ctx, const char * ifname, void * chanInfo, int chanInfoSize)
{
    int ret;
    struct wlanif_cfg80211_priv * cfgPriv;

    TRACE_ENTRY();

    cfgPriv = (struct wlanif_cfg80211_priv *) ctx;
    assert(cfgPriv != NULL);

    if ((ret = send_command_cfg80211(&(cfgPriv->cfg80211_ctx_qca), ifname, QCA_NL80211_VENDOR_SUBCMD_LIST_CHAN160, chanInfo, chanInfoSize)) < 0) {
        goto err;
    }


    TRACE_EXIT();
    return 0;

err:
    TRACE_EXIT_ERR();
    return ret;

}

/* Function to get station info*/
int getStationInfo_cfg80211(void * ctx , const char *ifname, void *data , int * data_len)
{

#define LIST_STA_MAX_CFG80211_LENGTH (3*1024)

    int ret;
    struct wlanif_cfg80211_priv * cfgPriv;
    struct cfg80211_data buffer;

    TRACE_ENTRY();

    cfgPriv = (struct wlanif_cfg80211_priv *) ctx;
    assert(cfgPriv != NULL);

    buffer.data = data;
    buffer.length = *data_len;
    buffer.callback = NULL;

    fprintf(stderr,"Inside %s \n",__func__);

    ret = wifi_cfg80211_sendcmd(&(cfgPriv->cfg80211_ctx_qca) ,QCA_NL80211_VENDOR_SUBCMD_LIST_STA, ifname, (char *)&buffer, *data_len);
    if (ret < 0) {
        fprintf(stderr,"Couldn't send NL command\n");
        goto err;
    }

    fprintf(stderr, "in buf 0x%p len %d cfg buf 0x%p len %d\n",data,*data_len,buffer.data,buffer.length);

    *data_len = buffer.length;

    TRACE_EXIT();
    return 0;
err:
    TRACE_EXIT_ERR();
    return ret;
}

/* Function to get dbreq info*/
int getDbgreq_cfg80211(void * ctx , const char *ifname, void *data , uint32_t data_len)
{

    int ret;
    struct wlanif_cfg80211_priv * cfgPriv;

    TRACE_ENTRY();

    cfgPriv = (struct wlanif_cfg80211_priv *) ctx;
    assert(cfgPriv != NULL);

    fprintf(stderr, "%s: %p\n",__func__,&(cfgPriv->cfg80211_ctx_qca));
    if ((ret = send_command_cfg80211(&(cfgPriv->cfg80211_ctx_qca),ifname, QCA_NL80211_VENDOR_SUBCMD_DBGREQ, data, data_len) < 0))
    {
        fprintf(stderr,"send_command_cfg80211 Failed\n");
        goto err;
    }

    TRACE_EXIT();
    return 0;
err:
    TRACE_EXIT_ERR();
    return ret;
}

/*Funtion to get extended subcommands */
int getExtended_cfg80211(void * ctx , const char *ifname, void *data , uint32_t data_len)
{

    int ret;
    struct wlanif_cfg80211_priv * cfgPriv;

    TRACE_ENTRY();

    cfgPriv = (struct wlanif_cfg80211_priv *) ctx;
    assert(cfgPriv != NULL);

    fprintf(stderr, "%s: %p\n",__func__,&(cfgPriv->cfg80211_ctx_qca));
    if ((ret = send_command_cfg80211(&(cfgPriv->cfg80211_ctx_qca),ifname, QCA_NL80211_VENDOR_SUBCMD_EXTENDEDSTATS, data, data_len) < 0))
    {
        fprintf(stderr,"send_command_cfg80211 Failed\n");
        goto err;
    }

    TRACE_EXIT();
    return 0;
err:
    TRACE_EXIT_ERR();
    return ret;
}

/* Funtion to get station stats*/
int getStaStats_cfg80211(void * ctx , const char *ifname, void *data , uint32_t data_len)
{

    int ret;
    struct wlanif_cfg80211_priv * cfgPriv;

    TRACE_ENTRY();

    cfgPriv = (struct wlanif_cfg80211_priv *) ctx;
    assert(cfgPriv != NULL);

    fprintf(stderr, "%s: %p\n",__func__,&(cfgPriv->cfg80211_ctx_qca));
    if ((ret = send_command_cfg80211(&(cfgPriv->cfg80211_ctx_qca),ifname, QCA_NL80211_VENDOR_SUBCMD_STA_STATS, data, data_len)) < 0)
    {
        fprintf(stderr,"send_command_cfg80211 Failed\n");
        goto err;
    }

    TRACE_EXIT();
    return 0;
err:
    TRACE_EXIT_ERR();
    return ret;
}

/*Funtion to handle Add/Del/Kick Mac commands*/
int addDelKickMAC_cfg80211(void * ctx , const char *ifname, int operation, void *data, uint32_t len)
{
    int ret;
    struct wlanif_cfg80211_priv * cfgPriv;
    int cfg_id=-1;

    TRACE_ENTRY();

    switch (operation)
    {
        case IO_OPERATION_ADDMAC:
            cfg_id = QCA_NL80211_VENDORSUBCMD_ADDMAC;
            break;
        case IO_OPERATION_DELMAC:
            cfg_id = QCA_NL80211_VENDORSUBCMD_DELMAC;
            break;
        case IO_OPERATION_KICKMAC:
            cfg_id = QCA_NL80211_VENDORSUBCMD_KICKMAC;
            break;
        default:
            /*Unsupported operation*/
            return -1;
    }

    cfgPriv = (struct wlanif_cfg80211_priv *) ctx;
    assert(cfgPriv != NULL);

    if(( ret = send_generic_command_cfg80211 (&(cfgPriv->cfg80211_ctx_qca), ifname, cfg_id, data, len)) < 0 )
    {
        goto err;
    }

    TRACE_EXIT();
    return 0;
err:
    TRACE_EXIT_ERR();
    return ret;
}

/*Function to set filter command */
int setFilter_cfg80211(void * ctx , const char *ifname, void *data, uint32_t len)
{
    int ret;
    struct wlanif_cfg80211_priv * cfgPriv;
    TRACE_ENTRY();

    cfgPriv = (struct wlanif_cfg80211_priv *) ctx;
    assert(cfgPriv != NULL);
    if(( ret = send_generic_command_cfg80211 (&(cfgPriv->cfg80211_ctx_qca), ifname, QCA_NL80211_VENDORSUBCMD_SETFILTER, data, len)) < 0 )
    {
        goto err;
    }

    TRACE_EXIT();
    return 0;
err:
    TRACE_EXIT_ERR();
    return ret;
}

/*Function to get Wireless mode from driver*/
int getWirelessMode_cfg80211(void * ctx , const char *ifname, void *data, uint32_t len)
{
    int ret;
    struct wlanif_cfg80211_priv * cfgPriv;
    TRACE_ENTRY();

    cfgPriv = (struct wlanif_cfg80211_priv *) ctx;
    assert(cfgPriv != NULL);
    if(( ret =  wifi_cfg80211_get_generic_command(&(cfgPriv->cfg80211_ctx_qca), ifname, QCA_NL80211_VENDORSUBCMD_WIRELESS_MODE, data, len)) < 0 )
    {
        goto err;
    }

    TRACE_EXIT();
    return 0;
err:
    TRACE_EXIT_ERR();
    return ret;
}

/* Function to send mgmt packet*/
int sendMgmt_cfg80211(void * ctx , const char *ifname, void *data, uint32_t len)
{
    int ret;
    struct wlanif_cfg80211_priv * cfgPriv;
    TRACE_ENTRY();

    cfgPriv = (struct wlanif_cfg80211_priv *) ctx;
    assert(cfgPriv != NULL);
    if(( ret = send_generic_command_cfg80211 (&(cfgPriv->cfg80211_ctx_qca), ifname, QCA_NL80211_VENDORSUBCMD_SEND_MGMT, data, len)) < 0 )
    {
        goto err;
    }

    TRACE_EXIT();
    return 0;
err:
    TRACE_EXIT_ERR();
    return ret;
}

/* Init Fucnction to handle private ioctls*/
int wlanif_cfg80211_init(struct wlanif_config *cfg80211_conf)
{
    struct wlanif_cfg80211_priv * cfgPriv;

    int ret;

    assert(cfg80211_conf != NULL);

    cfg80211_conf->IsCfg80211 = 1;
    cfg80211_conf->ctx = malloc(sizeof(struct wlanif_cfg80211_priv));

    if (cfg80211_conf->ctx == NULL)
    {
        printf("%s: Failed\n",__func__);
        return -ENOMEM;
    }

    cfgPriv = (struct wlanif_cfg80211_priv *) cfg80211_conf->ctx;

    assert(cfgPriv != NULL);

    ret = wifi_init_nl80211(&(cfgPriv->cfg80211_ctx_qca));
    if (ret) {
        fprintf(stderr, "unable to create NL socket\n") ;
        return -EIO;
    }

    return 0;
}

/* Destroy the intialized context for cfg80211*/
void wlanif_cfg80211_deinit(struct wlanif_config *cfg80211_conf)
{
    struct wlanif_cfg80211_priv * cfgPriv;

    assert(cfg80211_conf != NULL);

    cfgPriv = (struct wlanif_cfg80211_priv *) cfg80211_conf->ctx;

    wifi_destroy_nl80211(&(cfgPriv->cfg80211_ctx_qca));

    free(cfg80211_conf->ctx);
}

/*ops table listing the supported commands*/
static struct wlanif_config_ops wlanif_cfg80211_ops = {
    .init = wlanif_cfg80211_init,
    .deinit = wlanif_cfg80211_deinit,
    .getName = getName_cfg80211,
    .isAP = isAP_cfg80211,
    .getBSSID = getBSSID_cfg80211,
    .getESSID = getESSID_cfg80211,
    .getFreq = getFreq_cfg80211,
    .getChannelWidth = getChannelWidth_cfg80211,
    .getChannelExtOffset = getChannelExtOffset_cfg80211,
    .getChannelBandwidth = getChannelBandwidth_cfg80211,
    .getAcsState = getAcsState_cfg80211,
    .getCacState = getCacState_cfg80211,
    .getParentIfindex = getParentIfindex_cfg80211,
    .getSmartMonitor = getSmartMonitor_cfg80211,
    .getGenericInfoAtf = getGenericInfoAtf_cfg80211,
    .getGenericInfoAld = getGenericInfoAld_cfg80211,
    .getGenericHmwds = getGenericInfoHmwds_cfg80211,
    .getGenericNac = getGenericNac_cfg80211,
    .getCfreq2 = getCfreq2_cfg80211,
    .getChannelInfo = getChannelInfo_cfg80211,
    .getChannelInfo160 = getChannelInfo160_cfg80211,
    .getStationInfo = getStationInfo_cfg80211,
    .getWirelessMode = getWirelessMode_cfg80211,
    .getDbgreq = getDbgreq_cfg80211,
    .getExtended = getExtended_cfg80211,
    .addDelKickMAC = addDelKickMAC_cfg80211,
    .setFilter = setFilter_cfg80211,
    .sendMgmt = sendMgmt_cfg80211,
    .setParamMaccmd = setParamMaccmd_cfg80211,
    .setParam = setParam_cfg80211,
    .getStaStats = getStaStats_cfg80211,
};

struct wlanif_config_ops * wlanif_cfg80211_get_ops()
{
    return &wlanif_cfg80211_ops;
}
