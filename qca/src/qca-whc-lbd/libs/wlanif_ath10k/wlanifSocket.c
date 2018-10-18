/*
 * @File: lbdSocket.c
 *
 * @Abstract: Load balancing daemon communication with hostapd via socket
 *
 * @Notes:
 *
 * @@-COPYRIGHT-START-@@
 *
 * Copyright (c) 2017 Qualcomm Technologies, Inc.
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 *
 * @@-COPYRIGHT-END-@@
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>

#include <dbg.h>
#include <evloop.h>
#include <module.h>
#include <profile.h>
#include <split.h>
#include <lb_common.h>
#include <lbd_types.h>
#include <diaglog.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <sys/un.h>
#include <wlanifSocket.h>
#include "wlanifBSteerEvents.h"
#include "wlanifCommandParser.h"
#include "wlanifBSteerControlCmn.h"
#include<wlanifLinkEventsCmn.h>
#include <net/if.h>
#include "wlanifPrivate.h"

#define AP_STA_CONNECTED "AP-STA-CONNECTED"
#define AP_STA_DISCONNECTED "AP-STA-DISCONNECTED"
#define PROBE_REQ "RX-PROBE-REQUEST"
#define STA_WIDTH_MODIFIED "STA-WIDTH-MODIFIED"
#define STA_SMPS_MODE_MODIFIED "STA-SMPS-MODE-MODIFIED"
#define AP_CSA_FINISHED "AP_CSA_FINISHED"
#define CHAN_UTIL "AP-BSS-LOAD"
#define TX_AUTH_FAIL "Ignoring auth from"
#define STA_RX_NSS_MODIFIED "STA-RX-NSS-MODIFIED"
#define RSSI_CROSSING "nl80211: CQM RSSI"
#define RATE_CROSSING "nl80211: CQM TXRATE"
#define RSSI_CROSSING_LOW "CQM RSSI LOW event for"
#define RSSI_CROSSING_HIGH "CQM RSSI HIGH event for"
#define RATE_CROSSING_LOW "CQM TXRATE LOW event for"
#define RATE_CROSSING_HIGH "CQM TXRATE HIGH event for"

#define BSS_TM_RESP "BSS-TM-RESP"
#define BCN_RESP_RX "BEACON-RESP-RX"

#define os_strlen(s) strlen(s)
#define os_strncmp(s1, s2, n) strncmp((s1), (s2), (n))

/**
  * @brief string compare
  *
  * @param [in] str input string
  * @param [in] start input string
  */
int wlanif_str_starts(const char *str, const char *start)
{
    return os_strncmp(str, start, os_strlen(start)) == 0;
}

/**
  * @brief added for debugging enabled when required
  *
  * @param [in] txt msg sent to be parsed
  */
void wlanif_printmsg(const char *txt)
{
    //dbgf(NULL, DBGINFO,"Text is %s \n",txt);
    return;
}

/**
  * @brief parse message received from hostapd
  *
  * @param [in] msg message received from hostapd
  * @param [in] vap vap structure handle
  *
  * @return parsed end string
  *
  */
const char * wlanif_parseMsg(const char *msg, struct wlanifBSteerControlVapInfo *vap)
{
    const char *start , *s = NULL;
    const char *signal = NULL;
    const char *rate = NULL;
    const char *smpsMode = NULL;
    char *statusCode = NULL;
    char *bssTermDelay = NULL;
    const char *targetBssid = NULL;
    const char *bandwidth = NULL;
    const char *nss = NULL;
    char *macaddr = NULL;
    char *bssid = NULL;
    char *channelChanged = NULL;
    int rssi, value = 0;
    LBD_BOOL isBandwidth = LBD_FALSE;
    macaddr = (char *)malloc(20*sizeof(char));
    bssid = (char *)calloc(20,sizeof(char));
    statusCode = (char *)malloc(2*sizeof(char));
    bssTermDelay = (char *)malloc(2*sizeof(char));
    ath_netlink_bsteering_event_t *event = calloc(1, sizeof(ath_netlink_bsteering_event_t));

    start = strchr(msg, '>');
    if (start == NULL){
        start = strchr(msg,':');
        if (start == NULL){
            start = msg;
            //return NULL;
        }
    }

    start++;
    event->sys_index = if_nametoindex(vap->ifname);
    if (wlanif_str_starts(start, AP_STA_CONNECTED)) {
        int freq;
        s = strchr(start, ' ');
        if (s == NULL)
            return NULL;
        s++;
        dbgf(NULL, DBGINFO,"Sta connected is %s \n", s);
        strlcpy(macaddr,s,18);
        freq = wlanif_getVapFreq(vap);
        wlanif_getNodeAssocEventData(vap->sock,macaddr,freq, event);
        wlanifBSteerEventsMsgRx(vap->state,event);
    }
    else if (wlanif_str_starts(start, AP_STA_DISCONNECTED)) {
        s = strchr(start, ' ');
        if (s == NULL)
            return NULL;
        s++;
        dbgf(NULL, DBGINFO,"Sta disconnected is %s \n", s);
        strlcpy(macaddr,s,18);
        wlanif_getNodeDisassocEventData(macaddr,event);
        wlanifLinkEventsCmnGenerateDisassocEvent(vap->state->bsteerControlHandle,event);

    }
    else if (wlanif_str_starts(start, AP_CSA_FINISHED)) {
        s = strchr(start , ' ');
        if (s == NULL)
            return NULL;
        s++;
        if (wlanif_str_starts(s,"freq")){
            s = strchr(s, '=');
            s++;

            strlcpy(channelChanged,s,4);
        }
        event->data.bs_channel_change.channelChanged = atoi(channelChanged);
        wlanif_band_e band =
            wlanifBSteerControlResolveBandFromSystemIndex(vap->state->bsteerControlHandle,
                    event->sys_index);
        wlanifLinkEventsCmnProcessChannelChange(
                vap->state->bsteerControlHandle, event, band);
        wlanifLinkEventsProcessChannelChange(event->sys_index, event->data.bs_channel_change.channelChanged);
    }
    else if (wlanif_str_starts(start, PROBE_REQ)) {
        s = strchr(start , ' ');
        if (s == NULL)
            return NULL;
        s++;
        if(wlanif_str_starts(s,"sa")){
            s = strchr(s, '=');
            s++;
            strlcpy(macaddr,s,18);
        }
        s=s+18;
        while(*s != '\n') {
            if(wlanif_str_starts(s,"signal")){
                signal = strchr(s, '=');
                if (signal == NULL)
                    return NULL;
                signal++;
                break;
            }
            s=strchr(s, ' ');
        }
        //Convertion from rssi to SNR
        rssi = atoi(signal)+95;
        dbgf(NULL, DBGINFO,"Probe request for sta %s rssi %d \n",macaddr,rssi);
        wlanif_getProbeReqInd(macaddr, event,rssi);
        wlanifBSteerEventsMsgRx(vap->state,event);
    }
    else if ((wlanif_str_starts(start,STA_WIDTH_MODIFIED)) || (wlanif_str_starts(start,STA_RX_NSS_MODIFIED))) {
        s = strchr (start, ' ');
        if (s == NULL)
            return NULL;
        s++;

        strlcpy(macaddr,s,18);
        dbgf(NULL, DBGINFO,"opmode change for sta %s \n",macaddr);
        s = s+18;
        while(*s != '\n') {
            if(wlanif_str_starts(s,"width")){
                bandwidth = strchr(s, '=');
                if (bandwidth == NULL)
                    return NULL;
                bandwidth++;
                value = atoi(bandwidth);
                isBandwidth = LBD_TRUE;
                break;
            }
            else if (wlanif_str_starts(s,"rx_nss")){
                nss = strchr(s, '=');
                if (nss == NULL)
                    return NULL;
                nss++;
                value = atoi(nss);
                break;
            }

            s=strchr(s, ' ');
        }

        wlanif_getOpModeChangeInd(macaddr, event,value,isBandwidth);
        wlanifBSteerEventsMsgRx(vap->state,event);
    }
    else if (wlanif_str_starts(start,STA_SMPS_MODE_MODIFIED)) {
        s = strchr (start, ' ');
        if (s == NULL)
            return NULL;
        s++;
        strlcpy(macaddr,s,18);
        s = s+18;
        dbgf(NULL, DBGINFO,"opmode change for sta %s \n",macaddr);
        while(*s != '\n') {
            if(wlanif_str_starts(s,"smps mode")){
                smpsMode = strchr(s, '=');
                if (smpsMode == NULL)
                    return NULL;
                smpsMode++;
                break;
            }
            s=strchr(s, ' ');
        }
        dbgf(NULL, DBGINFO,"SMPS mode change  is %d \n",atoi(smpsMode));
        wlanif_getSmpsChangeInd(macaddr, event,atoi(smpsMode));
        wlanifBSteerEventsMsgRx(vap->state,event);
    }
    if (wlanif_str_starts(start,BSS_TM_RESP)) {
        s = strchr (start, ' ');
        if (s == NULL)
            return NULL;
        s++;
        strlcpy(macaddr,s,18);
        s = s+18;
        dbgf(NULL, DBGERR,"wnm event for sta %s length of s %d \n",macaddr,strlen(s));
        while(s != NULL) {
            if(wlanif_str_starts(s,"status_code")){
                statusCode = (char *)malloc(2*sizeof(char));
                s = strchr(s, '=');
                if (s == NULL)
                    return NULL;
                s++;
                strlcpy(statusCode,s,2);
            }
            else if (wlanif_str_starts(s," bss_termination_delay")){
                bssTermDelay = (char *)malloc(2*sizeof(char));
                s = strchr(s, '=');
                if (s == NULL)
                    return NULL;
                s++;
                strlcpy(bssTermDelay,s,2);
            }
            else if (wlanif_str_starts(s," target_bssid")){
                targetBssid = strchr(s, '=');
                if (targetBssid == NULL)
                    return NULL;
                targetBssid++;
                strlcpy(bssid,targetBssid,18);
                s = s+19;
            }
            s=strchr(s, ' ');
        }
        wlanif_getWnmEventInd(macaddr, event,atoi(statusCode),atoi(bssTermDelay),bssid);
        wlanifBSteerEventsMsgRx(vap->state,event);
    }

    else if(wlanif_str_starts(start,TX_AUTH_FAIL)){
        s = strchr(start, ' ');
        if (s == NULL)
            return NULL;
        s++;
        dbgf(NULL, DBGINFO,"Sta with Auth failure is %s \n", s);
        strlcpy(macaddr,s,18);
        wlanif_getTxAuthFailInd(macaddr,event);
        wlanifBSteerEventsMsgRx(vap->state,event);
    }
    else if (wlanif_str_starts(start,CHAN_UTIL)){
        const char *chan_util=NULL;
        const char *charfreq=NULL;
        int band = 0,chanUtil=0;
        s= strchr(start, ' ');
        if (s == NULL)
            return NULL;
        s++;
        while(*s != '\n') {
            if(wlanif_str_starts(s,"freq")){
                char *frequency = malloc(5*sizeof(char));
                charfreq = strchr(s, '=');
                if(charfreq == NULL)
                    return NULL;
                charfreq++;
                strlcpy(frequency,charfreq,5);
                band=wlanifMapFreqToBand(atoi(frequency));
                dbgf(NULL, DBGINFO,"charfreq is %s FREQ is %d  and band is %d \n",frequency,atoi(frequency),band);
            }
            else if(wlanif_str_starts(s,"chan_util")){
                chan_util = strchr(s, '=');
                if (chan_util == NULL)
                    return NULL;
                chan_util++;
                chanUtil=atoi(chan_util);
                if ((vap->ChanUtilCount) == vap->state->bsteerControlHandle->bandInfo[band].configParams.utilization_average_num_samples)
                {
                    chanUtil=((vap->ChanUtilAvg)+chanUtil)/vap->state->bsteerControlHandle->bandInfo[band].configParams.utilization_average_num_samples;
                    /*Channel utilization is sent between the value of 0 and 255, so converting to percentage*/
                    chanUtil=(chanUtil*100)/255;
                    wlanif_getChanUtilInd(event, chanUtil);
                    wlanifBSteerEventsMsgRx(vap->state,event);
                    vap->ChanUtilCount=1;
                    vap->ChanUtilAvg=0;
                    break;
                }
                else {
                    vap->ChanUtilAvg+=chanUtil;
                    vap->ChanUtilCount++;
                    break;
                }
            }
            s=strchr(s, ' ');
            s++;
        }
    }
    if(wlanif_str_starts(start,RSSI_CROSSING)) {
        LBD_BOOL isrssilow;
        int rssi = 0;
        s = strchr(start, ' ');
        if (s == NULL)
            return NULL;
        s++;
        if(wlanif_str_starts(s,RSSI_CROSSING_LOW)) {
            s = strchr(s, ':');
            s--;
            s--;
            strlcpy(macaddr,s,18);
            isrssilow = LBD_TRUE;
            s=s+18;
            while(*s != '\n') {
                if(wlanif_str_starts(s,"RSSI")){
                    signal = strchr(s, ':');
                    if (signal == NULL)
                        return NULL;
                    signal++;
                    break;
                }
                s=strchr(s, ' ');
            }
            //Convertion from rssi to SNR
            rssi = atoi(signal)+95;

            wlanif_getRSSICrossingEvent(macaddr,event,rssi,isrssilow);
        }
        else if (wlanif_str_starts(s,RSSI_CROSSING_HIGH)) {
            s = strchr(s,':');
            s--;
            s--;
            strlcpy(macaddr,s,18);
            isrssilow = LBD_FALSE;
            s=s+18;
            while(*s != '\n') {
                if(wlanif_str_starts(s,"RSSI")){
                    signal = strchr(s, ':');
                    if (signal == NULL)
                        return NULL;
                    signal++;
                    break;
                }
                s=strchr(s, ' ');
            }
            //Convertion from rssi to SNR
            rssi = atoi(signal)+95;
            wlanif_getRSSICrossingEvent(macaddr,event,rssi,isrssilow);
        }
        wlanifBSteerEventsMsgRx(vap->state,event);
    }
    if(wlanif_str_starts(start,RATE_CROSSING)) {
        LBD_BOOL isratelow;
        int rateValue = 0;
        s = strchr(start, ' ');
        if (s == NULL)
            return NULL;
        s++;
        if(wlanif_str_starts(s,RATE_CROSSING_LOW)) {
            s = strchr(s,':');
            s--;
            s--;
            strlcpy(macaddr,s,18);
            isratelow = LBD_TRUE;
            s=s+18;
            while(*s != '\n') {
                if(wlanif_str_starts(s,"txrate ")){
                    rate = strchr(s, ':');
                    if (rate == NULL)
                        return NULL;
                    rate++;
                    break;
                }
                s=strchr(s, ' ');
            }
            rateValue = atoi(rate)*100;
            wlanif_getRateCrossingEvent(macaddr,event,rateValue,isratelow);
        }
        else if (wlanif_str_starts(s,RATE_CROSSING_HIGH)) {
            printf("Inside high event  %s\n",s);
            s = strchr(s,':');
            s--;
            s--;
            strlcpy(macaddr,s,18);
            isratelow = LBD_FALSE;
            s=s+18;
            while(*s != '\n') {
                if(wlanif_str_starts(s,"txrate ")){
                    rate = strchr(s, ':');
                    if (rate == NULL)
                        return NULL;
                    rate++;
                    break;
                }
                s=strchr(s, ' ');
            }
            rateValue = atoi(rate);
            printf("Rate value is %d \n",rateValue);
            wlanif_getRateCrossingEvent(macaddr,event,rateValue*100,isratelow);
        }
        wlanifBSteerEventsMsgRx(vap->state,event);
    }
    if (wlanif_str_starts(start, BCN_RESP_RX)) {
        s = strchr(start, ' ');
        if (s == NULL)
            return NULL;
        s++;
        strlcpy(macaddr,s,18);
        s = s+18;
        wlanif_getBSteerRRMRptEventData(vap->sock,macaddr,s,event);
        wlanifBSteerEventsMsgRx(vap->state,event);
    }
    wlanif_printmsg(s);
    return s;
}

/**
  * @brief callback function for msg received in hostapd socket
  *
  * @param [in] cookie vap handle in which the socket is associated
  */
static void wlanif_bufferRead(void *cookie)
{
    u_int32_t numBytes;
    char *msg = NULL;
    struct wlanifBSteerControlVapInfo *vap = (struct wlanifBSteerControlVapInfo *)cookie;
    numBytes = bufrdNBytesGet(&vap->state->readBuf);
    msg = bufrdBufGet(&vap->state->readBuf);
    msg[numBytes] = '\0';
    do {
        if (!numBytes) {
            return;
        }
        dbgf(NULL, DBGINFO," Msg is %s and numBytes is %d for vap %s \n",msg, numBytes, vap->ifname);
    }while(0);

    bufrdConsume(&vap->state->readBuf, numBytes);
    wlanif_parseMsg(msg,vap);
}

/**
  * @brief create socket when vap structure is not defined yet
  *
  * @param [in] radio_ifname radio interface name
  * @param [in] ifname interface name
  *
  * @return hostapd socket
  *
  */
int wlanif_create_sock(const char* radio_ifname, const char* ifname)
{
    static char command[120], reply[1028];
    int sk, command_len, reply_len, rcv, snd;
    char dest_path[60] = "/var/run/hostapd";
    char sun_path[60] = "/var/run/ctrl_";
    const int trueFlag = 1;

    struct sockaddr_un local, dest;
    sk = socket(PF_UNIX, SOCK_DGRAM, 0);
    if (sk < 0) {
        dbgf(NULL, DBGERR,"socket creation %d\n", errno);
        goto out;
    }

    local.sun_family = AF_UNIX;
    strcat(sun_path,ifname);
    strcpy(local.sun_path, sun_path);
    if (setsockopt(sk, SOL_SOCKET, SO_REUSEADDR, &trueFlag, sizeof(int)) < 0)
        dbgf(NULL, DBGERR,"%s Failure \n",__func__);
    if (setsockopt(sk, SOL_SOCKET, SO_REUSEPORT, &trueFlag, sizeof(int)) < 0)
        dbgf(NULL, DBGERR,"%s Failure \n",__func__);
    snd = bind(sk, (struct sockaddr *)&local, sizeof(local));
    if (snd < 0) {
        dbgf(NULL, DBGERR,"%s socket bind %d\n",__func__,errno);
        goto close_and_out;
    }
    strcat(dest_path,"/");
    strcat(dest_path,ifname);
    strcpy(dest.sun_path, dest_path);
    dest.sun_family = AF_UNIX;
    rcv = connect(sk, (struct sockaddr *)&dest, sizeof(dest));
    if (rcv < 0) {
        dbgf(NULL, DBGERR,"%s socket connect %d\n",__func__, errno);
        goto close_and_out;
    }

    memcpy(command, "ATTACH", sizeof("ATTACH"));
    command_len = strlen(command);
    snd = send(sk, command, command_len, 0);
    if (snd < 0) {
        dbgf(NULL, DBGERR,"%s socket send %d\n",__func__, errno);
        goto close_and_out;
    }
    command[command_len] = '\0';

    reply_len = sizeof(reply) - 1;

    rcv = recv(sk, reply, reply_len, 0);
    if (rcv < 0) {
        dbgf(NULL, DBGERR,"%s socket receive %d\n",__func__, errno);
        goto close_and_out;
    }
    reply[rcv] = '\0';

    return sk;
close_and_out:
    close(sk);

out:
    unlink(sun_path);
    return 0;
}

/**
  * @brief create socket with vap structure
  *
  * @param [in] state lbd state handle
  * @param [in] vap vap structure handle
  * @param [in] radio_ifname radio interface name
  * @param [in] ifname interface name
  * @param [in] dbgModule debug module
  *
  * @return hostapd socket
  *
  */
int wlanif_createSocket(wlanifBSteerControlHandle_t State,struct wlanifBSteerControlVapInfo *vap,const char* radio_ifname, const char* ifname, struct dbgModule *dbgModule)
{
    static char command[120], reply[1028], event[1028];
    int sk, command_len, reply_len, rcv, snd, bufferSize;
    char dest_path[60] = "/var/run/hostapd";
    char sun_path[60] = "/var/run/ctrl_1_";
    const int trueFlag = 1;

    struct sockaddr_un local, dest;
    vap->state = calloc(1, sizeof(struct wlanifBSteerEventsPriv_t));
    vap->state->bsteerControlHandle = State;
    vap->state->dbgModule = dbgModule;
    sk = socket(PF_UNIX, SOCK_DGRAM, 0);
    if (sk < 0) {
        dbgf(NULL, DBGERR,"%s socket creation %d\n",__func__, errno);
        goto out;
    }

    local.sun_family = AF_UNIX;
    strcat(sun_path,ifname);
    strcpy(local.sun_path, sun_path);
    if (setsockopt(sk, SOL_SOCKET, SO_REUSEADDR, &trueFlag, sizeof(int)) < 0)
        dbgf(NULL, DBGERR,"%s Failure \n",__func__);
    if (setsockopt(sk, SOL_SOCKET, SO_REUSEPORT, &trueFlag, sizeof(int)) < 0)
        dbgf(NULL, DBGERR,"%s Failure \n",__func__);
    snd = bind(sk, (struct sockaddr *)&local, sizeof(local));
    if (snd < 0) {
        dbgf(NULL, DBGERR,"%s socket bind %d\n",__func__, errno);
        goto close_and_out;
    }

    strcat(dest_path,"/");
    strcat(dest_path,ifname);
    strcpy(dest.sun_path, dest_path);
    dest.sun_family = AF_UNIX;
    rcv = connect(sk, (struct sockaddr *)&dest, sizeof(dest));
    if (rcv < 0) {
        dbgf(NULL, DBGERR,"%s socket connect %d\n",__func__, errno);
        goto close_and_out;
    }

    memcpy(command, "ATTACH", sizeof("ATTACH"));
    command_len = strlen(command);
    snd = send(sk, command, command_len, 0);
    if (snd < 0) {
        dbgf(NULL, DBGERR,"%s socket send %d\n",__func__, errno);
        goto close_and_out;
    }
    command[command_len] = '\0';

    reply_len = sizeof(reply) - 1;

    rcv = recv(sk, reply, reply_len, 0);
    if (rcv < 0) {
        dbgf(NULL, DBGERR,"%s socket receive %d\n",__func__, errno);
        goto close_and_out;
    }
    reply[rcv] = '\0';
    bufferSize = sizeof(event);
    bufrdCreate(&vap->state->readBuf, "wlanifHostapdEvents-rd",
            sk, bufferSize,
            wlanif_bufferRead, vap);

    return sk;
close_and_out:
    close(sk);

out:
    unlink(sun_path);
    return 0;
}

/**
  * @brief unregister all hostapd events
  *
  * @param [in] vap vap structure handle
  */
void wlanifHostapdEventsUnregister(struct wlanifBSteerControlVapInfo *vap)
{
    if (close(vap->sock) != 0)
    {
        dbgf(NULL, DBGERR,"%s Close socket failed \n",__func__);
        return;
    }
    bufrdDestroy(&vap->state->readBuf);
}

/**
  * @brief disable all hostapd events
  *
  * @param [in] state lbd state handle
  * @param [in] band operating band
  */
void wlanifBSteerHostapdEventsDisable(wlanifBSteerControlHandle_t state,wlanif_band_e band)
{
    size_t vap;
    char sun_path[60] = "/var/run/ctrl_1_";
    for (vap = 0; vap < MAX_VAP_PER_BAND; ++vap) {
        if (!state->bandInfo[band].vaps[vap].valid) {
            // No more valid VAPs, can exit the loop
            break;
        }
        strcat(sun_path,state->bandInfo[band].vaps[vap].ifname);
        unlink(sun_path);
        bufrdDestroy(&state->bandInfo[band].vaps[vap].state->readBuf);
        close(state->bandInfo[band].vaps[vap].sock);
    }
}

/**
  * @brief send command to hostapd through socket
  *
  * @param [in] sock hostapd socket
  * @param [in] command command to be sent
  * @param [in] command_len command length
  * @param [out] command_reply reply received for the command sent
  * @param [in] reply_len length of the reply received
  * @param [out] rcv number of character received
  *
  * @return 1 on successful; otherwise -1
  *
  */
int wlanif_sendCommand( int sock, char *command,int command_len,char *command_reply,int reply_len, int *rcv)
{
    int snd;
    snd = send(sock, command, command_len, 0);
    if (snd < 0) {
        dbgf(NULL, DBGERR,"%s socket send %d\n",__func__, errno);
        return -1;
    }
    *rcv = recv(sock, command_reply, reply_len, 0);
    if (*rcv < 0) {
        dbgf(NULL, DBGERR,"%s socket receive %d\n",__func__, errno);
        return -1;
    }
    return 1;
}
