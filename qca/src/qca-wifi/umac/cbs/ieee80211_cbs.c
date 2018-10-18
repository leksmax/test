/*
 * Copyright (c) 2017 Qualcomm Innovation Center, Inc.
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Innovation Center, Inc.
 *
 */

/* Contineous Background Scan (CBS) */

#include <osdep.h>

#include <ieee80211_var.h>
#include <ieee80211_scan.h>
#include <ieee80211_channel.h>
#include <ieee80211_acs.h>
#include <ieee80211_cbs.h>
#include <ieee80211_ucfg.h>

#define CBS_DWELL_TIME_25MS 25
#define CBS_DWELL_TIME_50MS 50
#define CBS_DWELL_TIME_75MS 75

int ieee80211_cbs_event(ieee80211_cbs_t cbs, enum ieee80211_cbs_event event);

#if UMAC_SUPPORT_CBS

void ieee80211_cbs_post_event (ieee80211_cbs_t cbs, enum ieee80211_cbs_event event)
{
    if (cbs->cbs_event != 0) {
        printk("%s: pending event %d, new event %d can't be processed\n",
               __FUNCTION__, cbs->cbs_event, event);
        return;
    }

    cbs->cbs_event = event;
    qdf_sched_work(NULL, &cbs->cbs_work);
}

void cbs_work(void *arg)
{
    ieee80211_cbs_t cbs = (ieee80211_cbs_t)arg ;
    enum ieee80211_cbs_event event = cbs->cbs_event;

    cbs->cbs_event = 0;
    ieee80211_cbs_event(cbs, event);
}

static OS_TIMER_FUNC(cbs_timer)
{
    ieee80211_cbs_t cbs ;

    OS_GET_TIMER_ARG(cbs, ieee80211_cbs_t );

    switch (cbs->cbs_state) {
    case IEEE80211_CBS_REST:
        if (cbs->dwell_split_cnt < 0){
            ieee80211_cbs_post_event(cbs, IEEE80211_CBS_SCAN_CONTINUE);
        }
        else {
            ieee80211_cbs_post_event(cbs, IEEE80211_CBS_DWELL_SPLIT);
        }
        break;
    case IEEE80211_CBS_WAIT:
        ieee80211_cbs_post_event(cbs, IEEE80211_CBS_SCAN_START);
        break;
    default:
        break;
    }
}

/*
 * scan handler used for scan events
 */
static void ieee80211_cbs_scan_evhandler(struct ieee80211vap *originator, ieee80211_scan_event *event, void *arg)
{
    struct ieee80211com *ic;
    ieee80211_cbs_t cbs;

    ic = originator->iv_ic;
    cbs = (ieee80211_cbs_t) arg;

    IEEE80211_DPRINTF(originator, IEEE80211_MSG_CBS,
                      "scan_id %08X event %d reason %d \n",
                      event->scan_id, event->type, event->reason);

#if ATH_SUPPORT_MULTIPLE_SCANS
    /*
     * Ignore notifications received due to scans requested by other modules
     * and handle new event IEEE80211_SCAN_DEQUEUED.
     */
    ASSERT(0);

    /* Ignore events reported by scans requested by other modules */
    if (cbs->cbs_scan_id != event->scan_id) {
        return;
    }
#endif    /* ATH_SUPPORT_MULTIPLE_SCANS */

    switch (event->type) {
    case IEEE80211_SCAN_FOREIGN_CHANNEL:
    case IEEE80211_SCAN_FOREIGN_CHANNEL_GET_NF: /* notice fallthrough */
        ieee80211_acs_api_update(ic, event->type, event->chan);
        break;
    case IEEE80211_SCAN_COMPLETED:
        if (event->reason != IEEE80211_REASON_COMPLETED) {
            break;
        }
        if (cbs->dwell_split_cnt < 0) {
            ieee80211_cbs_post_event(cbs, IEEE80211_CBS_SCAN_NEXT);
        }
        else {
            ieee80211_cbs_post_event(cbs, IEEE80211_CBS_DWELL_SPLIT);
        }
        break;
    default:
        break;
    }
}

/*
 * Function to pre-fill the dwell-split & dwell-rest time for different
 * iterations on the same channel. This is used within the scan state machine
 * to scan the complete dwell time by resting between scans
 */
#define TOTAL_DWELL_TIME 200
#define DEFAULT_BEACON_INTERVAL 100
static void ieee80211_cbs_init_dwell_params(ieee80211_cbs_t cbs,
                                  int dwell_split_time, int dwell_rest_time)
{
    int i;

    switch (dwell_split_time) {
    case CBS_DWELL_TIME_25MS:
        cbs->max_arr_size_used = 8;
        cbs->dwell_split_cnt = cbs->max_arr_size_used - 1;
        cbs->max_dwell_split_cnt = cbs->max_arr_size_used - 1;
        if (dwell_rest_time % TOTAL_DWELL_TIME == 0) {
            cbs->scan_dwell_rest[0] = dwell_rest_time;
            cbs->scan_dwell_rest[1] = dwell_rest_time;
            cbs->scan_dwell_rest[2] = dwell_rest_time;
            cbs->scan_dwell_rest[3] = dwell_rest_time;
            cbs->scan_dwell_rest[4] = dwell_rest_time + TOTAL_DWELL_TIME - DEFAULT_BEACON_INTERVAL;
            cbs->scan_dwell_rest[5] = dwell_rest_time + TOTAL_DWELL_TIME - DEFAULT_BEACON_INTERVAL;
            cbs->scan_dwell_rest[6] = dwell_rest_time;
            cbs->scan_dwell_rest[7] = dwell_rest_time;
            cbs->scan_offset[0] = 0;
            cbs->scan_offset[1] = 0;
            cbs->scan_offset[2] = dwell_split_time;
            cbs->scan_offset[3] = dwell_split_time;
            cbs->scan_offset[4] = 2*dwell_split_time;
            cbs->scan_offset[5] = 2*dwell_split_time;
            cbs->scan_offset[6] = 3*dwell_split_time;
            cbs->scan_offset[7] = 3*dwell_split_time;
        }
        else {
            for(i = 0; i < cbs->max_arr_size_used - 1; i++){
                cbs->scan_dwell_rest[i] = dwell_rest_time;
            }
            cbs->scan_offset[0] = 0;
            cbs->scan_offset[1] = dwell_split_time;
            cbs->scan_offset[2] = 2*dwell_split_time;
            cbs->scan_offset[3] = 3*dwell_split_time;
            cbs->scan_offset[4] = 0;
            cbs->scan_offset[5] = dwell_split_time;
            cbs->scan_offset[6] = 2*dwell_split_time;
            cbs->scan_offset[7] = 3*dwell_split_time;
        }
        break;
    case CBS_DWELL_TIME_50MS:
        cbs->max_arr_size_used = 4;
        cbs->dwell_split_cnt = cbs->max_arr_size_used - 1;
        cbs->max_dwell_split_cnt = cbs->max_arr_size_used - 1;
        if (dwell_rest_time % TOTAL_DWELL_TIME == 0) {
            cbs->scan_dwell_rest[0] = dwell_rest_time;
            cbs->scan_dwell_rest[1] = dwell_rest_time;
            cbs->scan_dwell_rest[2] = dwell_rest_time + TOTAL_DWELL_TIME - DEFAULT_BEACON_INTERVAL;
            cbs->scan_dwell_rest[3] = dwell_rest_time + TOTAL_DWELL_TIME - DEFAULT_BEACON_INTERVAL;
            cbs->scan_dwell_rest[4] = 0;
            cbs->scan_dwell_rest[5] = 0;
            cbs->scan_dwell_rest[6] = 0;
            cbs->scan_dwell_rest[7] = 0;
            cbs->scan_offset[0] = 0;
            cbs->scan_offset[1] = 0;
            cbs->scan_offset[2] = dwell_split_time;
            cbs->scan_offset[3] = dwell_split_time;
            cbs->scan_offset[4] = 0;
            cbs->scan_offset[5] = 0;
            cbs->scan_offset[6] = 0;
            cbs->scan_offset[7] = 0;
        }
        else {
            cbs->scan_dwell_rest[0] = dwell_rest_time;
            cbs->scan_dwell_rest[1] = dwell_rest_time;
            cbs->scan_dwell_rest[2] = dwell_rest_time;
            cbs->scan_dwell_rest[3] = dwell_rest_time;
            cbs->scan_dwell_rest[4] = 0;
            cbs->scan_dwell_rest[5] = 0;
            cbs->scan_dwell_rest[6] = 0;
            cbs->scan_dwell_rest[7] = 0;
            cbs->scan_offset[0] = 0;
            cbs->scan_offset[1] = dwell_split_time;
            cbs->scan_offset[2] = 0;
            cbs->scan_offset[3] = dwell_split_time;
            cbs->scan_offset[4] = 0;
            cbs->scan_offset[5] = 0;
            cbs->scan_offset[6] = 0;
            cbs->scan_offset[7] = 0;
        }
        break;
    case CBS_DWELL_TIME_75MS:
        cbs->max_arr_size_used = 4;
        cbs->dwell_split_cnt = cbs->max_arr_size_used - 1;
        cbs->max_dwell_split_cnt = cbs->max_arr_size_used - 1;
        if (dwell_rest_time % TOTAL_DWELL_TIME == 0) {
            cbs->scan_dwell_rest[0] = dwell_rest_time;
            cbs->scan_dwell_rest[1] = dwell_rest_time;
            cbs->scan_dwell_rest[2] = dwell_rest_time + TOTAL_DWELL_TIME - DEFAULT_BEACON_INTERVAL;
            cbs->scan_dwell_rest[3] = dwell_rest_time + TOTAL_DWELL_TIME - DEFAULT_BEACON_INTERVAL;
            cbs->scan_dwell_rest[4] = 0;
            cbs->scan_dwell_rest[5] = 0;
            cbs->scan_dwell_rest[6] = 0;
            cbs->scan_dwell_rest[7] = 0;
            cbs->scan_offset[0] = 0;
            cbs->scan_offset[1] = 0;
            cbs->scan_offset[2] = DEFAULT_BEACON_INTERVAL - dwell_split_time;
            cbs->scan_offset[3] = DEFAULT_BEACON_INTERVAL - dwell_split_time;
            cbs->scan_offset[4] = 0;
            cbs->scan_offset[5] = 0;
            cbs->scan_offset[6] = 0;
            cbs->scan_offset[7] = 0;
        }
        else {
            cbs->scan_dwell_rest[0] = dwell_rest_time;
            cbs->scan_dwell_rest[1] = dwell_rest_time;
            cbs->scan_dwell_rest[2] = dwell_rest_time;
            cbs->scan_dwell_rest[3] = dwell_rest_time;
            cbs->scan_dwell_rest[4] = 0;
            cbs->scan_dwell_rest[5] = 0;
            cbs->scan_dwell_rest[6] = 0;
            cbs->scan_dwell_rest[7] = 0;
            cbs->scan_offset[0] = 0;
            cbs->scan_offset[1] = DEFAULT_BEACON_INTERVAL - dwell_split_time;
            cbs->scan_offset[2] = 0;
            cbs->scan_offset[3] = DEFAULT_BEACON_INTERVAL - dwell_split_time;
            cbs->scan_offset[4] = 0;
            cbs->scan_offset[5] = 0;
            cbs->scan_offset[6] = 0;
            cbs->scan_offset[7] = 0;
        }
        break;
    default:
        cbs_trace("Dwell time not supported\n");
        break;
        return;
    }
}

static void ieee80211_cbs_cancel(ieee80211_cbs_t cbs)
{
    int rc;
    struct ieee80211com *ic = cbs->cbs_ic;

    /* unregister scan event handler */
    rc = wlan_scan_unregister_event_handler(cbs->cbs_vap,
                    ieee80211_cbs_scan_evhandler,
                    (void *) cbs);
    if (rc != EOK) {
        IEEE80211_DPRINTF(cbs->cbs_vap, IEEE80211_MSG_CBS,
                          "%s: wlan_scan_unregister_event_handler() failed handler=%08p,%08p rc=%08X\n",
                          __func__, ieee80211_cbs_scan_evhandler, cbs, rc);
    }
    wlan_scan_clear_requestor_id(cbs->cbs_vap, cbs->cbs_scan_requestor);

    ieee80211_acs_api_complete(ic->ic_acs);
    cbs->cbs_state = IEEE80211_CBS_INIT;

    return;
}

/* main CBS state machine */
int ieee80211_cbs_event(ieee80211_cbs_t cbs, enum ieee80211_cbs_event event)
{
    struct ieee80211com *ic = NULL;
    int rc;
    int scan_offset;
    ieee80211_scan_params *scan_params;
    struct ieee80211vap *vap;
    enum ieee80211_cbs_state cur_state;

    ic = cbs->cbs_ic;
    vap = cbs->cbs_vap;

    cur_state = cbs->cbs_state;

    IEEE80211_DPRINTF(vap, IEEE80211_MSG_CBS,
                      "%s: CBS state %d Event %d\n", __func__, cur_state, event);
    scan_params = &cbs->scan_params;

    switch (event) {
    case IEEE80211_CBS_SCAN_START:
        switch (cur_state) {
        case IEEE80211_CBS_INIT:
        case IEEE80211_CBS_WAIT: /* notice fallthrough */
            if(wlan_autoselect_in_progress(vap)) {
                cbs_trace("ACS in progress, try later\n");
                return -EINPROGRESS;
            }
            /* Enable ACS Ranking */
            ieee80211_acs_set_param(ic->ic_acs, IEEE80211_ACS_RANK , 1);
            /* Prepare ACS */
            rc = ieee80211_acs_api_prepare(vap, ic->ic_acs, IEEE80211_MODE_AUTO, cbs->chan_list, &cbs->nchans);
            if (rc != EOK)
                return rc;

            cbs->chan_list_idx = 0;
            /* register scan event handler */
            rc = wlan_scan_register_event_handler(vap, ieee80211_cbs_scan_evhandler, (void *) cbs);
            if (rc != EOK) {
                IEEE80211_DPRINTF(vap, IEEE80211_MSG_CBS,
                    "%s: wlan_scan_register_event_handler() failed handler=%08p,%08p rc=%08X\n",
                    __func__, ieee80211_cbs_scan_evhandler, (void *) cbs, rc);
                ieee80211_acs_api_complete(ic->ic_acs);
                cbs->cbs_state = IEEE80211_CBS_INIT;
                return -EINVAL;
            }
            wlan_scan_get_requestor_id(vap,(u_int8_t*)"cbs", &cbs->cbs_scan_requestor);

            /* Fill scan parameter */
            OS_MEMZERO(scan_params,sizeof(ieee80211_scan_params));
            wlan_set_default_scan_parameters(vap,scan_params,IEEE80211_M_HOSTAP,true,true,true,true,0,NULL,0);
            scan_params->flags = IEEE80211_SCAN_PASSIVE | IEEE80211_SCAN_ALLBANDS;
            scan_params->flags |= IEEE80211_SCAN_OFFCHAN_MGMT_TX | IEEE80211_SCAN_OFFCHAN_DATA_TX | IEEE80211_SCAN_CHAN_EVENT;
            scan_params->type = IEEE80211_SCAN_BACKGROUND;
            scan_params->min_dwell_time_passive = CBS_DEFAULT_DWELL_TIME;
            scan_params->max_dwell_time_passive = CBS_DEFAULT_DWELL_TIME +5;
            scan_params->min_rest_time = 0;
            scan_params->max_rest_time = 0;

            /*TODO Add min_dwell_rest_time in scan parameter and initinalize it here*/
            /*Setting offsets and dwell rest times*/
            if (cbs->min_dwell_rest_time % DEFAULT_BEACON_INTERVAL) {
                cbs->min_dwell_rest_time =
                    (cbs->min_dwell_rest_time / (2*DEFAULT_BEACON_INTERVAL))
                    *2*DEFAULT_BEACON_INTERVAL +
                    ((cbs->min_dwell_rest_time % 200 < 100) ? 100 : 200);
            }

            /* Pre-fill dwell-split, dwell-rest times for differnet interations */
            ieee80211_cbs_init_dwell_params(cbs, cbs->dwell_split_time, cbs->min_dwell_rest_time);

            /* channel to scan */
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_CBS,
                              "Current Channel for scan is %d \n",
                              cbs->chan_list[cbs->chan_list_idx]);
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_CBS,
                              "Offset for scan is %d \n",
                              cbs->scan_offset[cbs->max_arr_size_used - cbs->dwell_split_cnt - 1]);

            scan_offset = cbs->scan_offset[cbs->max_arr_size_used - cbs->dwell_split_cnt - 1];

            scan_params->num_channels = 1;
            scan_params->chan_list = &cbs->chan_list[cbs->chan_list_idx++];
            scan_params->scan_offset_time = (scan_offset +26);

            ieee80211_acs_api_flush(vap);

            cbs->cbs_state = IEEE80211_CBS_SCAN;

            cbs->dwell_split_cnt--;

            if ((rc = wlan_scan_start(vap,
                                       scan_params,
                                       cbs->cbs_scan_requestor,
                                       IEEE80211_SCAN_PRIORITY_HIGH,
                                       &(cbs->cbs_scan_id))) != EOK) {
                cbs_trace( " Issue a scan fail.\n" );
                ieee80211_cbs_cancel(cbs);
                return -EINVAL;
            }
            break;
        default:
            cbs_trace( " Can't start scan in current state %d.\n", cur_state );
            return -EINVAL;
            break;
        }
        break;
    case IEEE80211_CBS_SCAN_NEXT:
        switch (cur_state) {
        case IEEE80211_CBS_SCAN:
            if (cbs->chan_list_idx < cbs->nchans) {
                cbs->cbs_state = IEEE80211_CBS_REST;
                OS_SET_TIMER(&cbs->cbs_timer, cbs->rest_time);
            } else
                ieee80211_cbs_post_event(cbs, IEEE80211_CBS_SCAN_COMPLETE);
            break;
        default:
            break;
        }
        break;
    case IEEE80211_CBS_DWELL_SPLIT:
        switch (cur_state) {
        case IEEE80211_CBS_SCAN:
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_CBS,
                              " dwell reset %d\n", cbs->scan_dwell_rest[cbs->dwell_split_cnt]);

            if (cbs->scan_dwell_rest[cbs->dwell_split_cnt] == 0) {
                IEEE80211_DPRINTF(vap, IEEE80211_MSG_CBS,
                                  "Current offset for scan is %d \n",
                                  cbs->scan_offset[cbs->max_arr_size_used - cbs->dwell_split_cnt - 1]);

                scan_offset = cbs->scan_offset[cbs->max_arr_size_used - cbs->dwell_split_cnt - 1];
                scan_params->scan_offset_time = (scan_offset +26);
                cbs->dwell_split_cnt--;

                if ((rc = wlan_scan_start(vap,
                                       scan_params,
                                       cbs->cbs_scan_requestor,
                                       IEEE80211_SCAN_PRIORITY_HIGH,
                                       &(cbs->cbs_scan_id))) != EOK) {

                    cbs_trace( " Issue a scan fail." );
                    ieee80211_cbs_cancel(cbs);
                    return -EINVAL;
                }
            }
            else {
                cbs->cbs_state = IEEE80211_CBS_REST;
                IEEE80211_DPRINTF(vap, IEEE80211_MSG_CBS,
                              " dwell rest timer %d\n",
                              cbs->scan_dwell_rest[cbs->max_arr_size_used - cbs->dwell_split_cnt - 1]);

                OS_SET_TIMER(&cbs->cbs_timer,
                             cbs->scan_dwell_rest[cbs->max_arr_size_used - cbs->dwell_split_cnt - 1]);
            }
            break;
        case IEEE80211_CBS_REST:
            cbs->cbs_state = IEEE80211_CBS_SCAN;

            IEEE80211_DPRINTF(vap, IEEE80211_MSG_CBS,
                              "Current offset for scan is %d \n",
                              cbs->scan_offset[cbs->max_arr_size_used - cbs->dwell_split_cnt - 1]);

            scan_offset = cbs->scan_offset[cbs->max_arr_size_used - cbs->dwell_split_cnt - 1];
            scan_params->scan_offset_time = (scan_offset +26);
            cbs->dwell_split_cnt--;
            if ((rc = wlan_scan_start(vap,
                                       scan_params,
                                       cbs->cbs_scan_requestor,
                                       IEEE80211_SCAN_PRIORITY_HIGH,
                                       &(cbs->cbs_scan_id))) != EOK) {

                cbs_trace( " Issue a scan fail." );
                ieee80211_cbs_cancel(cbs);
                return -EINVAL;
                }

            break;
        default:
            break;
        }
        break;
    case IEEE80211_CBS_SCAN_CONTINUE:
        switch (cur_state) {
        case IEEE80211_CBS_REST:
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_CBS,
                              "Current Channel for scan is %d \n", cbs->chan_list[cbs->chan_list_idx]);

            cbs->dwell_split_cnt = cbs->max_dwell_split_cnt;

            scan_params->chan_list = &cbs->chan_list[cbs->chan_list_idx++];

            cbs->cbs_state = IEEE80211_CBS_SCAN;
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_CBS,
                              "Current offset for scan is %d \n",
                              cbs->scan_offset[cbs->max_arr_size_used - cbs->dwell_split_cnt - 1]);

            scan_offset = cbs->scan_offset[cbs->max_arr_size_used - cbs->dwell_split_cnt - 1];
            scan_params->scan_offset_time = (scan_offset +26);
            cbs->dwell_split_cnt--;
            if ((rc = wlan_scan_start(vap,
                                       scan_params,
                                       cbs->cbs_scan_requestor,
                                       IEEE80211_SCAN_PRIORITY_HIGH,
                                       &(cbs->cbs_scan_id))) != EOK) {

                cbs_trace( " Issue a scan fail." );
                ieee80211_cbs_cancel(cbs);
                return -EINVAL;
            }

            break;
        default:
            break;
        }
        break;
    case IEEE80211_CBS_SCAN_CANCEL:
        switch (cur_state) {
        case IEEE80211_CBS_INIT:
            /* do nothing */
            break;
        default:
            qdf_timer_sync_cancel(&cbs->cbs_timer);

            if (wlan_scan_in_progress(cbs->cbs_vap)) {
                wlan_scan_cancel(cbs->cbs_vap, cbs->cbs_scan_requestor,
                                 IEEE80211_VAP_SCAN, 0);
            }
            ieee80211_cbs_cancel(cbs);
            break;
        }
        break;
    case IEEE80211_CBS_SCAN_COMPLETE:
        switch (cur_state) {
        default:
            /* unregister scan event handler */
            rc = wlan_scan_unregister_event_handler(cbs->cbs_vap,
                    ieee80211_cbs_scan_evhandler,
                    (void *) cbs);
            if (rc != EOK) {
                IEEE80211_DPRINTF(cbs->cbs_vap, IEEE80211_MSG_CBS,
                    "%s: wlan_scan_unregister_event_handler() failed handler=%08p,%08p rc=%08X\n",
                    __func__, ieee80211_cbs_scan_evhandler, cbs, rc);
            }
            wlan_scan_clear_requestor_id(cbs->cbs_vap, cbs->cbs_scan_requestor);
            cbs->cbs_state = IEEE80211_CBS_RANK;
            ieee80211_cbs_post_event(cbs, IEEE80211_CBS_RANK_START);
            break;
        }
        break;
    case IEEE80211_CBS_RANK_START:
        switch (cur_state) {
        case IEEE80211_CBS_RANK:
            /* Rank top 2 channels */
            ieee80211_acs_api_rank(ic->ic_acs, 2);
            ieee80211_cbs_post_event(cbs, IEEE80211_CBS_RANK_COMPLETE);
        default:
            break;
        }
        break;
    case IEEE80211_CBS_RANK_COMPLETE:
        switch (cur_state) {
        case IEEE80211_CBS_RANK:
            ieee80211_acs_api_complete(ic->ic_acs);
            if (cbs->wait_time) {
                cbs->cbs_state = IEEE80211_CBS_WAIT;
                OS_SET_TIMER(&cbs->cbs_timer, cbs->wait_time);
            } else {
                cbs->cbs_state = IEEE80211_CBS_INIT;
            }
        default:
            break;
        }
        break;
    case IEEE80211_CBS_DCS_INTERFERENCE:
        switch (cur_state) {
        default:
            break;
        }
        break;
    case IEEE80211_CBS_STATS_COLLECT:
        switch (cur_state) {
        default:
            break;
        }
        break;
    case IEEE80211_CBS_STATS_COMPLETE:
        switch (cur_state) {
        default:
            break;
        }
        break;
    default:
        break;
    }

    return EOK;
}

int ieee80211_cbs_init(ieee80211_cbs_t *cbs, wlan_dev_t devhandle, osdev_t osdev)
{
    OS_MEMZERO(*cbs, sizeof(struct ieee80211_cbs));

    (*cbs)->cbs_ic     = devhandle;
    (*cbs)->cbs_osdev  = osdev;
    (*cbs)->rest_time  = CBS_DEFAULT_RESTTIME;
    (*cbs)->dwell_time = CBS_DEFAULT_DWELL_TIME;
    (*cbs)->wait_time  = CBS_DEFAULT_WAIT_TIME;
    (*cbs)->dwell_split_time = CBS_DEFAULT_DWELL_SPLIT_TIME;
    (*cbs)->min_dwell_rest_time = CBS_DEFAULT_DWELL_REST_TIME;

    spin_lock_init(&((*cbs)->cbs_lock));

    OS_INIT_TIMER(osdev, & (*cbs)->cbs_timer, cbs_timer, (void * )(*cbs), QDF_TIMER_TYPE_WAKE_APPS);

    (*cbs)->cbs_state = IEEE80211_CBS_INIT;

    qdf_create_work(osdev, &((*cbs)->cbs_work), cbs_work, (void *)(*cbs));

    cbs_trace("CBS Inited\n");

    return EOK;
}

void ieee80211_cbs_deinit(ieee80211_cbs_t *cbs)
{
    OS_FREE_TIMER(&(*cbs)->cbs_timer);
    spin_lock_destroy(&((*cbs)->cbs_lock));
}

int ieee80211_cbs_attach(ieee80211_cbs_t *cbs,
        wlan_dev_t          devhandle,
        osdev_t             osdev)
{
    if (*cbs)
        return -EINPROGRESS;

    *cbs = (ieee80211_cbs_t) OS_MALLOC(osdev, sizeof(struct ieee80211_cbs), 0);
    if (*cbs == NULL) {
        return -ENOMEM;
    }

    ieee80211_cbs_init(&(*cbs), devhandle, osdev);
    return EOK;
}

int ieee80211_cbs_detach(ieee80211_cbs_t *cbs)
{
    if (*cbs == NULL)
        return EINPROGRESS;

    qdf_destroy_work(NULL, &(*cbs)->cbs_work);
    ieee80211_cbs_deinit(&(*cbs));
    OS_FREE(*cbs);

    *cbs = NULL;

    return EOK;
}

int ieee80211_cbs_scan(struct ieee80211vap *vap)
{
    struct ieee80211com *ic = vap->iv_ic;
    ieee80211_cbs_t cbs = ic->ic_cbs;

    if (ic->ic_acs == NULL) {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_CBS,
                "%s: CBS Needs ACS to be enabled\n", __func__);
        return -EINVAL;
    }

    cbs->cbs_vap = vap;

    ieee80211_cbs_post_event(cbs, IEEE80211_CBS_SCAN_START);

    return 0;
}

int ieee80211_cbs_set_param(ieee80211_cbs_t cbs, int param , int val)
{
    struct ieee80211com *ic = cbs->cbs_ic;
    int ret = EOK;

    switch(param){
        case IEEE80211_CBS_ENABLE:
            cbs->cbs_enable = val;
            if (val == 0) {
                wlan_bk_scan_stop(ic);
                ret = EOK;
                break;
            }
            ret = wlan_bk_scan(ic);
            break;
        case  IEEE80211_CBS_DWELL_SPLIT_TIME:
            if (val != CBS_DWELL_TIME_25MS && val != CBS_DWELL_TIME_50MS &&
                val != CBS_DWELL_TIME_75MS) {
                qdf_print("Dwell time not supported \n");
                ret = -EINVAL;
                break;
            }
            wlan_bk_scan_stop(ic);
            cbs->dwell_split_time = val;
            if (cbs->cbs_enable)
                ret = wlan_bk_scan(ic);
            break;
        case IEEE80211_CBS_DWELL_REST_TIME:
            if (val < DEFAULT_BEACON_INTERVAL){
                qdf_print("Invalid rest time. Rest time should be non-negative \n");
                ret = -EINVAL;
                break;
            }
            wlan_bk_scan_stop(ic);
            if (val % DEFAULT_BEACON_INTERVAL != 0) {
                val = (val / (2*DEFAULT_BEACON_INTERVAL))
                    * (2*DEFAULT_BEACON_INTERVAL) +
                (((val % (2*DEFAULT_BEACON_INTERVAL)) < DEFAULT_BEACON_INTERVAL)
                      ? DEFAULT_BEACON_INTERVAL : 2*DEFAULT_BEACON_INTERVAL);
            }
            cbs->min_dwell_rest_time = val;
            if (cbs->cbs_enable)
                ret = wlan_bk_scan(ic);
            break;
        case IEEE80211_CBS_WAIT_TIME:
            if (val < 0){
                qdf_print("Wait time cannot be negative \n");
                ret = -EINVAL;
                break;
            }
            wlan_bk_scan_stop(ic);
            if (val % DEFAULT_BEACON_INTERVAL != 0){
                val = (val / (2*DEFAULT_BEACON_INTERVAL))
                    * (2*DEFAULT_BEACON_INTERVAL) +
                (((val % (2*DEFAULT_BEACON_INTERVAL)) < DEFAULT_BEACON_INTERVAL)
                  ? DEFAULT_BEACON_INTERVAL : 2*DEFAULT_BEACON_INTERVAL);
               }
            cbs->wait_time = val;
            if (cbs->cbs_enable)
                ret = wlan_bk_scan(ic);
            break;
        case IEEE80211_CBS_REST_TIME:
            if (val < 0){
                qdf_print("Rest time cannot be negative \n");
                ret = -EINVAL;
                break;
            }
            wlan_bk_scan_stop(ic);
            cbs->rest_time = val;
            if (cbs->cbs_enable)
                ret = wlan_bk_scan(ic);
            break;
       case IEEE80211_CBS_CSA_ENABLE:
           wlan_bk_scan_stop(ic);
           if (val != 0) {
               cbs->cbs_csa = 1;
           } else {
               cbs->cbs_csa = 0;
           }
           if (cbs->cbs_enable)
               ret = wlan_bk_scan(ic);
           break;
    default:
        break;
    }
    return ret;
}

int ieee80211_cbs_get_param(ieee80211_cbs_t cbs, int param)
{
    int val = 0;

    switch (param){
        case  IEEE80211_CBS_ENABLE:
            val = cbs->cbs_enable;
            break;
        case  IEEE80211_CBS_DWELL_SPLIT_TIME:
            val = cbs->dwell_split_time;
            break;
        case  IEEE80211_CBS_DWELL_REST_TIME:
            val = cbs->min_dwell_rest_time;
            break;
        case IEEE80211_CBS_REST_TIME:
            val = cbs->rest_time;
            break;
        case  IEEE80211_CBS_WAIT_TIME:
            val = cbs->wait_time;
            break;
        case  IEEE80211_CBS_CSA_ENABLE:
            val = cbs->cbs_csa;
            break;
    }
    return val;
}

/* List of function APIs used by other modules within the driver */

int ieee80211_cbs_api_change_home_channel(ieee80211_cbs_t cbs)
{
    struct ieee80211com *ic = cbs->cbs_ic;
    struct ieee80211vap *vap;
    int chan, found = 0;

    wlan_bk_scan_stop(ic);

    /* Get the 1st ranked channel from ACS */
    chan = ieee80211_acs_api_get_ranked_chan(cbs->cbs_ic->ic_acs, 1);
    if (!chan)
        return -EINVAL;

    if (ic->ic_curchan->ic_ieee == chan) {
        chan = ieee80211_acs_api_get_ranked_chan(cbs->cbs_ic->ic_acs, 2);
        if (!chan) {
                return -EINVAL;
        }
    }

    /* Loop through and figure the first VAP on this radio */
    TAILQ_FOREACH(vap, &ic->ic_vaps, iv_next) {
        if (vap->iv_opmode == IEEE80211_M_HOSTAP) {
            found = 1;
            break;
        }
    }
    if (!found) {
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_CBS,
                "%s: No VAPs exist\n", __func__);
        return -EINVAL;
    }

    cbs_trace("new home channel %d\n", chan);
    /* switch ASAP, set the CSA TBTT count to 1 */
    ieee80211_ucfg_set_chanswitch(vap, chan, 1, 0);

    return EOK;
}

int wlan_bk_scan(struct ieee80211com *ic)
{
    struct ieee80211vap * vap;
    int found = 0;

    qdf_print("Starting CBS\n");

    /* Loop through and figure the first VAP on this radio */
    TAILQ_FOREACH(vap, &ic->ic_vaps, iv_next) {
        if (vap->iv_opmode == IEEE80211_M_HOSTAP) {
            found = 1;
            break;
        }
    }
    if (found) {
        ieee80211_cbs_scan(vap);
    } else {
        printk(" failed to start CBS. no vap found\n");
        return -EINVAL;
    }
    return EOK;
}

void wlan_bk_scan_stop(struct ieee80211com *ic)
{
    ieee80211_cbs_t cbs = ic->ic_cbs;

    qdf_cancel_work(NULL, &cbs->cbs_work);

    if (cbs->cbs_state != IEEE80211_CBS_INIT ) {
        ieee80211_cbs_event(cbs, IEEE80211_CBS_SCAN_CANCEL);
    }
}

#else /* UMAC_SUPPORT_CBS */
void wlan_bk_scan(wlan_if_t vaphandle)
{
    /* nothing to do */
}
void wlan_bk_scan_stop(struct ieee80211com *ic)
{
    /* nothing to do */
}

#endif /* UMAC_SUPPORT_CBS */
