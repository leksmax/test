
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "servlet.h"
#include "utils.h"
#include "wireless.h"

struct wl_regdmn regdmns[REGDMN_MAX] = {
    [REGDMN_ZA] = {
        .region_str = "ZA", 
        .region_id = 710, 
        .chan_2g = { 1, 13 },
        .chan_5g = {
            {36}, {40}, {44}, {48}, {52, 1}, {56, 1}, {60, 1}, {64, 1}, {100, 1}, 
            {104, 1}, {108, 1}, {112, 1}, {116, 1}, {120, 1}, {124, 1}, {128, 1}, 
            {132, 1}, {136, 1}, {140, 1}, {149}, {153}, {157}, {161}, {165}
        },
    },
    [REGDMN_TH] = {
        .region_str = "TH",
        .region_id = 764,
        .chan_2g= {1, 13},
        .chan_5g = {
            {36}, {40}, {44}, {48}, {52, 1}, {56, 1}, {60, 1}, {64, 1}, {100, 1}, 
            {104, 1}, {108, 1}, {112, 1}, {116, 1}, {120, 1}, {124, 1}, {128, 1}, 
            {132, 1}, {136, 1}, {140, 1}, {149}, {153}, {157}, {161}, {165}
        },
        
    }, 
    [REGDMN_AU] = {
        .region_str = "AU", 
        .region_id = 36, 
        .chan_2g= {1, 13},
        .chan_5g = {
            {36}, {40}, {44}, {48}, {52, 1}, {56, 1}, {60, 1}, {64, 1}, {100, 1}, 
            {104, 1}, {108, 1}, {112, 1}, {116, 1}, {120, 1}, {124, 1}, {128, 1}, 
            {132, 1}, {136, 1}, {140, 1}, {149}, {153}, {157}, {161}, {165}
        }, 
    },
    [REGDMN_CA] = {
        .region_str = "CA", 
        .region_id = 5000, 
        .chan_2g= {1, 11},
        .chan_5g = {
            {36}, {40}, {44}, {48}, {52, 1}, {56, 1}, {60, 1}, {64, 1}, {100, 1}, 
            {104, 1}, {108, 1}, {112, 1}, {116, 1}, {120}, {124}, {128}, {132, 1}, 
            {136, 1}, {140, 1}, {149}, {153}, {157}, {161}, {165}
        },
    },
    [REGDMN_DE] = {
        .region_str = "DE", 
        .region_id = 276, 
        .chan_2g= {1, 13},
        .chan_5g = {
            {36}, {40}, {44}, {48}, {52, 1}, {56, 1}, {60, 1}, {64, 1}, {100, 1}, 
            {104, 1}, {108, 1}, {112, 1}, {116, 1}, {120}, {124}, {128}, {132, 1}, 
            {136, 1}, {140, 1}
        },
    },
    [REGDMN_IL] = {
        .region_str = "IL", 
        .region_id = 376,
        .chan_2g= {1, 13},
        .chan_5g = {
            {36}, {40}, {44}, {48}, {52, 1}, {56, 1}, {60, 1}, {64, 1}
        },
    },
    [REGDMN_JP] = {
        .region_str = "JP", 
        .region_id = 4015, 
        .chan_2g= {1, 13},
        .chan_5g = {
            {36}, {40}, {44}, {48}, {52, 1}, {56, 1}, {60, 1}, {64, 1}, {100, 1}, 
            {104, 1}, {108, 1}, {112, 1}, {116, 1}, {120}, {124}, {128}, {132, 1}, 
            {136, 1}, {140, 1}
        },
    },
    [REGDMN_KR] = {
        .region_str = "KR", 
        .region_id = 412, 
        .chan_2g= {1, 13},
        .chan_5g = {
            {149}, {153}, {157}, {161}
        },
    },
    [REGDMN_MX] = {
        .region_str = "MX", 
        .region_id = 484, 
        .chan_2g= {1, 11},
        .chan_5g = {
            {36}, {40}, {44}, {48}, {52}, {56}, {60}, {64}, {149}, {153}, 
            {157}, {161}, {165}
        },
    },
    [REGDMN_BR] = {
        .region_str = "BR", 
        .region_id = 76, 
        .chan_2g= {1, 13},
        .chan_5g = {
            {36}, {40}, {44}, {48}, {52, 1}, {56, 1}, {60, 1}, {64, 1}, {100, 1}, 
            {104, 1}, {108, 1}, {112, 1}, {116, 1}, {120, 1}, {124, 1}, {128, 1}, 
            {132, 1}, {136, 1}, {140, 1}, {149}, {153}, {157}, {161}, {165}
        },
    },
    [REGDMN_US] = {
        .region_str = "US", 
        .region_id = 843, 
        .chan_2g= {1, 11},
        .chan_5g = {
            {36}, {40}, {44}, {48}, {52, 1}, {56, 1}, {60, 1}, {64, 1}, {100, 1}, 
            {104, 1}, {108, 1}, {112, 1}, {116, 1}, {120, 1}, {124, 1}, {128, 1}, 
            {132, 1}, {136, 1}, {140, 1}, {149}, {153}, {157}, {161}, {165}
        },
    },
    [REGDMN_CN] = {
        .region_str = "CN", 
        .region_id = 156, 
        .chan_2g= {1, 13},
        .chan_5g = {
            {36}, {40}, {44}, {48}, {52, 1}, {56, 1}, {60, 1}, {64, 1}, {149}, 
            {153}, {157}, {161}, {165}
        },
    },
    [REGDMN_IN] = {
        .region_str = "IN", 
        .region_id = 356, 
        .chan_2g= {1, 13},
        .chan_5g = {
            {36}, {40}, {44}, {48}, {52, 1}, {56, 1}, {60, 1}, {64, 1}, {149}, 
            {153}, {157}, {161}, {165}
        },
    },
    [REGDMN_MY] = {
        .region_str = "MY", 
        .region_id = 458, 
        .chan_2g= {1, 13},
        .chan_5g = {
            {52}, {56}, {60}, {64}, {149}, {153}, {157}, {161}, {165}
        },        
    },
    [REGDMN_DZ] = {
        .region_str = "DZ", 
        .region_id = 12, 
        .chan_2g= {1, 13},
        .chan_5g = {
            {36}, {40}, {44}, {48}, {52, 1}, {56, 1}, {60, 1}, {64, 1}, {100, 1}, 
            {104, 1}, {108, 1}, {112, 1}, {116, 1}, {120, 1}, {124, 1}, {128, 1}, 
            {132, 1}, {136, 1}, {140, 1}, {149}, {153}, {157}, {161}, {165}
        },
    },
    [REGDMN_IR] = {
        .region_str = "IR", 
        .region_id = 364, 
        .chan_2g= {1, 13},
        .chan_5g = {
            {149}, {153}, {157}, {161}, {165}
        },
    },
    [REGDMN_TR] = {
        .region_str = "TR", 
        .region_id = 792, 
        .chan_2g= {1, 13},
        .chan_5g = {
            {36}, {40}, {44}, {48}, {52, 1}, {56, 1}, {60, 1}, {64, 1}
        },
    },
    [REGDMN_SA] = {
        .region_str = "SA", 
        .region_id = 682, 
        .chan_2g= {1, 13},
        .chan_5g = {
            {36}, {40}, {44}, {48}, {52}, {56}, {60}, {64}, {149}, 
            {153}, {157}, {161}, {165}
        },
    },
    [REGDMN_AE] = {
        .region_str = "AE", 
        .region_id = 784, 
        .chan_2g= {1, 13},
        .chan_5g = {
            {36}, {40}, {44}, {48}, {52, 1}, {56, 1}, {60, 1}, {64, 1}, {100, 1}, 
            {104, 1}, {108, 1}, {112, 1}, {116, 1}, {120, 1}, {124, 1}, {128, 1}, 
            {132, 1}, {136, 1}, {140, 1}
        },
    },
    [REGDMN_RU] = {
        .region_str = "RU", 
        .region_id = 643, 
        .chan_2g= {1, 13},
        .chan_5g = {
            {36}, {40}, {44}, {48}, {52, 1}, {56, 1}, {60, 1}, {64, 1}, {132, 1}, 
            {136, 1}, {140, 1}, {149}, {153}, {157}, {161}
        },
    },
    [REGDMN_SG] = {
        .region_str = "SG", 
        .region_id = 702, 
        .chan_2g= {1, 13},
        .chan_5g = {
            {36}, {40}, {44}, {48}, {52, 1}, {56, 1}, {60, 1}, {64, 1}, {100}, 
            {104}, {108}, {112}, {116}, {120}, {124}, {128}, {132}, {136}, 
            {140}, {149}, {153}, {157}, {161}, {165}
        },
    },
    [REGDMN_TW] = {
        .region_str = "TW",
        .region_id = 158,
        .chan_2g= {1, 11},
        .chan_5g = {
            {56, 1}, {60, 1}, {64, 1}, {100, 1}, {104, 1}, {108, 1}, {112, 1},
            {116, 1}, {120}, {124}, {128}, {132}, {136, 1}, {140, 1}, {149},
            {153}, {157}, {161}, {165}
        },
    },
};

int libgw_get_wifi_cfg(int wl_index, wifi_cfg_t *cfg)
{
    char strVal[20] = {0};

    if (wl_index == WL2G_IDX)
    {
        strncpy(strVal, config_get(WIFI2G_CHAN), sizeof(strVal) - 1);
        if (strcmp(strVal, "auto") == 0)
        {
            cfg->channel = 0;
        }
        else
        {
            cfg->channel = atoi(strVal);
        }

        strncpy(cfg->ssid, config_get(WIFI2G_SSID), sizeof(cfg->ssid) - 1);

        cfg->hidden = config_get_int(WIFI2G_HIDDEN);

        strncpy(strVal, config_get(WIFI2G_ENCRYPTION), sizeof(strVal) - 1);
        if (strcmp(strVal, "none") == 0)
        {
            cfg->enctype = 0;
        }
        else if (strcmp(strVal, "psk2") == 0)
        {
            cfg->enctype = 3;
        }
        else if (strcmp(strVal, "psk-mixed") == 0)
        {
            cfg->enctype = 4;
        }

        if (cfg->enctype != 0)
        {
            strncpy(cfg->key, config_get(WIFI2G_KEY), sizeof(cfg->key) - 1);
        }

    }
    else if (wl_index == WL5G_IDX)
    {
        strncpy(strVal, config_get(WIFI5G_CHAN), sizeof(strVal) - 1);
        if (strcmp(strVal, "auto") == 0)
        {
            cfg->channel = 0;
        }
        else
        {
            cfg->channel = atoi(strVal);
        }

        strncpy(cfg->ssid, config_get(WIFI5G_SSID), sizeof(cfg->ssid) - 1);

        cfg->hidden = config_get_int(WIFI5G_HIDDEN);

        strncpy(strVal, config_get(WIFI5G_ENCRYPTION), sizeof(strVal) - 1);
        if (strcmp(strVal, "none") == 0)
        {
            cfg->enctype = 0;
        }
        else if (strcmp(strVal, "psk2") == 0)
        {
            cfg->enctype = 3;
        }
        else if (strcmp(strVal, "psk-mixed") == 0)
        {
            cfg->enctype = 4;
        }

        if (cfg->enctype != 0)
        {
            strncpy(cfg->key, config_get(WIFI5G_KEY), sizeof(cfg->key) - 1);
        }
    }
    
    return 0;
}

int libgw_set_wifi_cfg(int wl_index, wifi_cfg_t *cfg)
{
    if (wl_index == WL2G_IDX)
    {    
        if (cfg->channel == 0)
        {
            config_set(WIFI2G_CHAN, "auto");
        }
        else
        {
            config_set_int(WIFI2G_CHAN, cfg->channel);
        }

        config_set(WIFI2G_SSID, cfg->ssid);
        config_set_int(WIFI2G_HIDDEN, cfg->hidden);

        if (cfg->enctype == 0)
        {
            config_set(WIFI2G_ENCRYPTION, "none");
        }
        else if (cfg->enctype == 3)
        {
            config_set(WIFI2G_ENCRYPTION, "psk2");

        }
        else if (cfg->enctype == 4)
        {
            config_set(WIFI2G_ENCRYPTION, "psk-mixed");
        }

        if (cfg->enctype != 0)
        {
            config_set(WIFI2G_KEY, cfg->key);
        }
    }
    else if (wl_index == WL5G_IDX)
    {
        if (cfg->channel == 0)
        {
            config_set(WIFI5G_CHAN, "auto");
        }
        else
        {
            config_set_int(WIFI5G_CHAN, cfg->channel);
        }

        config_set(WIFI5G_SSID, cfg->ssid);
        config_set_int(WIFI5G_HIDDEN, cfg->hidden);

        if (cfg->enctype == 0)
        {
            config_set(WIFI5G_ENCRYPTION, "none");
        }
        else if (cfg->enctype == 3)
        {
            config_set(WIFI5G_ENCRYPTION, "psk2");

        }
        else if (cfg->enctype == 4)
        {
            config_set(WIFI5G_ENCRYPTION, "psk-mixed");
        }

        if (cfg->enctype != 0)
        {
            config_set(WIFI5G_KEY, cfg->key);
        }
    }
    
    return 0;
}

int libgw_get_wl_region_id(int *region)
{
    int intVal;
    FILE *fp = NULL;

    fp = popen("nvram get wl_country", "r");
    if (!fp)
    {
        return -1;
    }

    if ((fscanf(fp, "%d", &intVal)) != 1)
    {
        pclose(fp);
        return -1;
    }

    pclose(fp);

    *region = intVal;

    return 0;
}

int parse_wifi_config(int wl_index, cJSON *params, wifi_cfg_t *cfg)
{
    int ret = 0;
    cJSON *wifi = NULL;
    int intVal = 0;
    char *strVal = 0;

    if (wl_index == WL2G_IDX)
    {
        wifi = cJSON_GetObjectItem(params, "wl2g");
        if (!wifi)
        {
            return -1;
        }
    }
    else if (wl_index == WL5G_IDX)
    {
        wifi = cJSON_GetObjectItem(params, "wl5g");
        if (!wifi)
        {
            return -1;
        }        
    }
    
    strVal = cjson_get_string(wifi, "ssid");
    if (!strVal)
    {
        return -1;
    }
    strncpy(cfg->ssid, strVal, sizeof(cfg->ssid) - 1);

    ret = cjson_get_int(wifi, "hidden", &cfg->hidden);
    if (ret < 0)
    {
        return -1;
    }
    
    ret = cjson_get_int(wifi, "channel", &cfg->channel);
    if (ret < 0)
    {
        return -1;
    }
    
    ret = cjson_get_int(wifi, "enctype", &cfg->enctype);
    if (ret < 0)
    {
        return -1;
    }

    if (cfg->enctype != 0)
    {
        strVal = cjson_get_string(wifi, "key");
        if (!strVal)
        {
            return -1;
        }    
        strncpy(cfg->key, strVal, sizeof(cfg->key) - 1);
    }
    
    return 0;
}

char *get_regdmn_wl2g_list(int region)
{
    int i = 0;
    int ret = 0, cnt = 0;
    static char chan2g_str[128];
    struct wl_regdmn *regdmn = NULL;
    
    memset(chan2g_str, 0x0, sizeof(chan2g_str));

    regdmn = &regdmns[region];

    for (i = 0; i <= regdmn->chan_2g.max_chan; i ++)
    {
        ret += snprintf(chan2g_str + ret, sizeof(chan2g_str) - ret, "%s%d", ((cnt > 0) ? "," : ""), i);
        cnt ++;
    }

    return chan2g_str;
}

char *get_regdmn_wl5g_list(int region)
{
    int i = 0;
    int ret = 0, cnt = 0;
    static char chan5g_str[128];
    struct wl_regdmn *regdmn = NULL;
    
    memset(chan5g_str, 0x0, sizeof(chan5g_str));

    regdmn = &regdmns[region];

    for (i = 0, cnt = 0; i < MAX_5G_CHAN; i ++)
    {
        if (regdmn->chan_5g[i].chan <= 0)
        {
            break;
        }
        ret += snprintf(chan5g_str + ret, sizeof(chan5g_str) - ret, "%s%hhu", 
            ((cnt > 0) ? "," : ""), regdmn->chan_5g[i].chan);
        cnt ++;
    }

    return chan5g_str;
}

char *get_regdmn_wl5g_dfs_list(int region)
{
    int i = 0;
    int ret = 0, cnt = 0;
    static char dfs_str[128];
    struct wl_regdmn *regdmn = NULL;
    
    memset(dfs_str, 0x0, sizeof(dfs_str));

    regdmn = &regdmns[region];

    for (i = 0, cnt = 0; i < MAX_5G_CHAN; i ++)
    {
        if (regdmn->chan_5g[i].chan <=0)
        {
            break;
        }
        
        if (regdmn->chan_5g[i].dfs)
        {
            ret += snprintf(dfs_str + ret, sizeof(dfs_str) - ret, "%s%hhu",
                    ((cnt > 0) ? "," : ""), regdmn->chan_5g[i].chan);
            cnt ++;
        }
    }

    return dfs_str;
}

int get_regdmn_list(cgi_request_t *req, cgi_response_t *resp)
{
    int ret = 0;
    int method = 0;
    int region_id = 0;
    cJSON *params = NULL;
    
    ret = param_init(req->post_data, &method, &params);
    if (ret < 0)
    {
        cgi_errno = CGI_ERR_PARAM;
        goto out;
    }

    ret = cjson_get_int(params, "region", &region_id);
    if (ret < 0)
    {
        cgi_errno = CGI_ERR_CFG_PARAM;
        goto out;
    }

    if (region_id < 0 || region_id >= REGDMN_MAX)
    {
        cgi_errno = CGI_ERR_CFG_PARAM;
        goto out;
    }

    webs_json_header(req->out);
    webs_write(req->out, "{\"code\":%d,\"data\":{", cgi_errno);
    webs_write(req->out, "\"wl2g\":{\"chan_list\":[%s]},", get_regdmn_wl2g_list(region_id));
    webs_write(req->out, "\"wl5g\":{\"chan_list\":[%s],", get_regdmn_wl5g_list(region_id));
    webs_write(req->out, "\"chan_dfs\":[%s]", get_regdmn_wl5g_dfs_list(region_id));
    webs_write(req->out, "}}}");

out:
    param_free();

    if (cgi_errno != CGI_ERR_OK)
    {
        webs_json_header(req->out);
        webs_write(req->out, "{\"code\":%d,\"data\":{}}", cgi_errno);
    }

    return 0;
}

int get_wifi_config(cgi_request_t *req, cgi_response_t *resp)
{
    int ret = 0;
    int region = 0;
    wifi_cfg_t wl2g_cfg;
    wifi_cfg_t wl5g_cfg;

    memset(&wl2g_cfg, 0x0, sizeof(wifi_cfg_t));
    memset(&wl5g_cfg, 0x0, sizeof(wifi_cfg_t));

    ret = libgw_get_wl_region_id(&region);
    if (ret < 0)
    {
        cgi_errno = CGI_ERR_PARAM;
        goto out;
    }
        
    ret = libgw_get_wifi_cfg(WL2G_IDX, &wl2g_cfg);
    ret += libgw_get_wifi_cfg(WL5G_IDX, &wl5g_cfg);
    if (ret < 0)
    {    
        cgi_errno = CGI_ERR_CFG_PARAM;
        goto out;
    }

    webs_json_header(req->out);
    webs_write(req->out, "{\"code\":%d,\"data\":{", cgi_errno);
    webs_write(req->out, "\"region\":%d", region);
    webs_write(req->out, ",\"wl2g\":{\"ssid\":\"%s\",\"hidden\":%d,\"channel\":%d,\"enctype\":%d,\"key\":\"%s\",", 
        wl2g_cfg.ssid, wl2g_cfg.hidden, wl2g_cfg.channel, wl2g_cfg.enctype, wl2g_cfg.key);
    webs_write(req->out, "\"chan_list\":[%s]}", get_regdmn_wl2g_list(region));
    webs_write(req->out, ",\"wl5g\":{\"ssid\":\"%s\",\"hidden\":%d,\"channel\":%d,\"enctype\":%d,\"key\":\"%s\",", 
        wl5g_cfg.ssid, wl5g_cfg.hidden, wl5g_cfg.channel, wl5g_cfg.enctype, wl5g_cfg.key);    
    webs_write(req->out, "\"chan_list\":[%s],", get_regdmn_wl5g_list(region));    
    webs_write(req->out, "\"chan_dfs\":[%s]}", get_regdmn_wl5g_dfs_list(region));
    webs_write(req->out, "}}");
    
out:

    if (cgi_errno != CGI_ERR_OK)
    {
        webs_json_header(req->out);
        webs_write(req->out, "{\"code\":%d,\"data\":{}}", cgi_errno);
    }
    
    return ret;
}

int set_wifi_config(cgi_request_t *req, cgi_response_t *resp)
{
    int ret = 0;
    int method = 0;
    cJSON *params = NULL;
    char *strVal = NULL;
    wifi_cfg_t wl2g_cfg;
    wifi_cfg_t wl5g_cfg;
    
    memset(&wl2g_cfg, 0x0, sizeof(wifi_cfg_t));
    memset(&wl5g_cfg, 0x0, sizeof(wifi_cfg_t));

    ret = param_init(req->post_data, &method, &params);
    if (ret < 0)
    {
        cgi_errno = CGI_ERR_PARAM;
        goto out;
    }

    ret += parse_wifi_config(WL2G_IDX, params, &wl2g_cfg);
    ret += parse_wifi_config(WL5G_IDX, params, &wl5g_cfg);
    if (ret < 0)
    {
        cgi_errno = CGI_ERR_CFG_PARAM;
        goto out;
    }

    libgw_set_wifi_cfg(WL2G_IDX, &wl2g_cfg);
    libgw_set_wifi_cfg(WL5G_IDX, &wl5g_cfg);

    fork_exec(1, "/sbin/wifi reload");
    
out:
    param_free();

    webs_json_header(req->out);
    webs_write(req->out, "{\"code\":%d,\"data\":{}}", cgi_errno);

    return 0;
}
