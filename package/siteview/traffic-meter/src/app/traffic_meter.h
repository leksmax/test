#ifndef __TRAFFIC_METER_H
#define __TRAFFIC_METER_H

#include "servlet.h"

#define TRAFFIC_LIMIT_ENABLED				("traffic.basic.enabled")
#define TRAFFIC_LIMIT_TYPE					("traffic.limit.type")
#define TRAFFIC_LIMIT_SIZE					("traffic.limit.monthly_size")
#define TRAFFIC_LIMIT_VOLUME				("traffic.limit.data_volume")
#define TRAFFIC_LIMIT_CONNECT_ENABLED		("traffic.limit.connect_time_enabled")	
#define TRAFFIC_LIMIT_CONNECT_TIME			("traffic.limit.connect_time")

#define TRAFFIC_COUNTER_RESTART_TIME		("traffic.counter.restart_time")

#define TRAFFIC_ACTION_SHOW_LIMIT_SIZE		("traffic.action.show_limit_size")
#define TRAFFIC_ACTION_LED_ENABLED			("traffic.action.led_enabled")
#define TRAFFIC_ACTION_DISCONNECT_NETWORK	("traffic.action.disconnect_network")

#define TRAFFIC_METER_DATA_FILE				("/tmp/traffic_every_month_data")
#define	BYTES_UNIT							(1024 * 1024.00)

enum{
	NOT_LIMIT,
	LIMIT_UPLOAD,
	LIMIT_DOWNLOAD,
	LIMIT_ALL
};

struct traffic_conf{
	int enabled;
	int limit_type;
	int limit_size;
	int limit_data_volume;
	int limit_connect_time_enabled;
	int limit_connect_time;
	int show_limit_size;
	int led_enabled;
	int disconnect_network;
	char restart_time[10];
};

struct traffic_stat{
	char time_s[20];
	char upload[20];
	char download[20];
	char total[20];
};

struct traffic_time_stat{
	long cur_timespec;
	struct traffic_stat today;
	struct traffic_stat yesterday;
	struct traffic_stat this_week;
	struct traffic_stat this_month;
	struct traffic_stat last_month;
};

int get_traffic_meter_config(cgi_request_t *req, cgi_response_t *resp);
int get_traffic_meter_list(cgi_request_t *req, cgi_response_t *resp);
int set_traffic_meter_config(cgi_request_t *req, cgi_response_t *resp);
int restart_counter(cgi_request_t *req, cgi_response_t *resp);
#endif //__TRAFFIC_METER_H 
