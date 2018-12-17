
#ifndef __WIRELESS_H_
#define __WIRELESS_H_

#include <stdint.h>

enum WL_INDEX {
    WL2G_IDX = 0,
    WL5G_IDX
};

#define WIFI2G_CHAN         "wireless.wifi1.channel"
#define WIFI2G_COUNTRY      "wireless.wifi1.country"
#define WIFI2G_SSID         "wireless.@wifi-iface[1].ssid"
#define WIFI2G_HIDDEN       "wireless.@wifi-iface[1].hidden"
#define WIFI2G_ENCRYPTION   "wireless.@wifi-iface[1].encryption"
#define WIFI2G_KEY          "wireless.@wifi-iface[1].key"

#define WIFI5G_CHAN         "wireless.wifi0.channel"
#define WIFI5G_COUNTRY      "wireless.wifi0.country"
#define WIFI5G_SSID         "wireless.@wifi-iface[0].ssid"
#define WIFI5G_HIDDEN       "wireless.@wifi-iface[0].hidden"
#define WIFI5G_ENCRYPTION   "wireless.@wifi-iface[0].encryption"
#define WIFI5G_KEY          "wireless.@wifi-iface[0].key"

#define MAX_2G_CHAN 14
#define MAX_5G_CHAN 24

enum REGDMN_INDEX {
    REGDMN_ZA = 0,  /* Africa */
    REGDMN_TH = 1,  /* Asia (Thailand), use Thailand */
    REGDMN_AU = 2,  /* Australia */
    REGDMN_CA = 3,  /* Canada */
    REGDMN_DE = 4,  /* Europe (Germany), use Germany */
    REGDMN_IL = 5,  /* Israel */ 
    REGDMN_JP = 6,  /* Japan */
    REGDMN_KR = 7,  /* Korea */
    REGDMN_MX = 8,  /* Mexico */
    REGDMN_BR = 9,  /* South America (Brazil), use Brazil*/
    REGDMN_US = 10, /* United States */
    REGDMN_CN = 11, /* China */
    REGDMN_IN = 12, /* India */
    REGDMN_MY = 13, /* Malaysia */
    REGDMN_DZ = 14, /* Middle East (Algeria/Syria/Yemen), use Algeria */
    REGDMN_IR = 15, /* Middle East(Iran/Lebanon/Qatar), use Iran */
    REGDMN_TR = 16, /* Middle East(Turkey/Egypt/Tunisia/Kuwait), use Turkey */
    REGDMN_SA = 17, /* Middle East(Saudi Arabia) */
    REGDMN_AE = 18, /* Middle East(United Arab Emirates) */
    REGDMN_RU = 19, /* Russia */
    REGDMN_SG = 20, /* Singapore */
    REGDMN_TW = 21, /* Taiwan */
    REGDMN_MAX
};

struct wl2g_chan {
    uint8_t min_chan;
    uint8_t max_chan;
};

struct wl5g_chan {
    uint8_t chan;
    uint8_t dfs;
};

struct wl_regdmn {
    int region_id;
    char *region_str;
    struct wl2g_chan chan_2g;
    struct wl5g_chan chan_5g[MAX_5G_CHAN];
};

typedef struct {
    char ssid[33];
    int hidden;
    int channel;
    int enctype;
    char key[64];
} wifi_cfg_t;

int get_wifi_config(cgi_request_t * req, cgi_response_t * resp);
int set_wifi_config(cgi_request_t * req, cgi_response_t * resp);

int get_regdmn_list(cgi_request_t * req, cgi_response_t * resp);

#endif
