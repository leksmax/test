  
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "utils.h"
#include "cjson.h"
#include "traffic_meter.h"

void read_traffic_meter_config(struct traffic_conf *conf)
{
	conf->enabled = config_get_int(TRAFFIC_LIMIT_ENABLED);
	conf->limit_type = config_get_int(TRAFFIC_LIMIT_TYPE);
	conf->limit_size = config_get_int(TRAFFIC_LIMIT_SIZE);
	conf->limit_data_volume = config_get_int(TRAFFIC_LIMIT_VOLUME);
	conf->limit_connect_time_enabled = config_get_int(TRAFFIC_LIMIT_CONNECT_ENABLED);
	conf->limit_connect_time = config_get_int(TRAFFIC_LIMIT_CONNECT_TIME);
	
	strncpy(conf->restart_time, config_get(TRAFFIC_COUNTER_RESTART_TIME), sizeof(conf->restart_time) - 1);
	
	conf->show_limit_size = config_get_int(TRAFFIC_ACTION_SHOW_LIMIT_SIZE);
	conf->led_enabled = config_get_int(TRAFFIC_ACTION_LED_ENABLED);
	conf->disconnect_network = config_get_int(TRAFFIC_ACTION_DISCONNECT_NETWORK);
	return ;
}

void save_traffic_meter_config(struct traffic_conf conf)
{
	config_set_int(TRAFFIC_LIMIT_ENABLED, conf.enabled);
	if(1 == conf.enabled)
	{
		config_set_int(TRAFFIC_LIMIT_TYPE, conf.limit_type);
		if(NOT_LIMIT != conf.limit_type)
		{
			config_set_int(TRAFFIC_LIMIT_SIZE, conf.limit_size);
			config_set_int(TRAFFIC_LIMIT_VOLUME, conf.limit_data_volume);
		}
		config_set_int(TRAFFIC_LIMIT_CONNECT_ENABLED, conf.limit_connect_time_enabled);
		if(1 == conf.limit_connect_time_enabled)
			config_set_int(TRAFFIC_LIMIT_CONNECT_TIME, conf.limit_connect_time);
		
		config_set(TRAFFIC_COUNTER_RESTART_TIME, conf.restart_time);
		config_set_int(TRAFFIC_ACTION_SHOW_LIMIT_SIZE, conf.show_limit_size);
		config_set_int(TRAFFIC_ACTION_LED_ENABLED, conf.led_enabled);
		config_set_int(TRAFFIC_ACTION_DISCONNECT_NETWORK, conf.disconnect_network);
	}
}

void get_traffic_count_data(struct traffic_time_stat *data)
{
	data->today.connect_time = 1111111;
	strncpy(data->today.upload, "2.56", sizeof(data->today.upload) - 1);
	strncpy(data->today.download, "22", sizeof(data->today.download) - 1);
	strncpy(data->today.total, "24.56", sizeof(data->today.total) - 1);

	data->yesterday.connect_time = 2222222;
	strncpy(data->yesterday.upload, "3.56", sizeof(data->yesterday.upload) - 1);
	strncpy(data->yesterday.download, "33", sizeof(data->yesterday.download) - 1);
	strncpy(data->yesterday.total, "36.56", sizeof(data->yesterday.total) - 1);

	data->this_week.connect_time = 3333333;
	strncpy(data->this_week.upload, "4.56/3", sizeof(data->this_week.upload) - 1);
	strncpy(data->this_week.download, "44/3", sizeof(data->this_week.download) - 1);
	strncpy(data->this_week.total, "48.56/3", sizeof(data->this_week.total) - 1);

	data->this_month.connect_time = 4444444;
	strncpy(data->this_month.upload, "5.56/4", sizeof(data->this_month.upload) - 1);
	strncpy(data->this_month.download, "55/4", sizeof(data->this_month.download) - 1);
	strncpy(data->this_month.total, "60.56/4", sizeof(data->this_month.total) - 1);

	data->last_month.connect_time = 5555555;
	strncpy(data->last_month.upload, "6.56/5", sizeof(data->last_month.upload) - 1);
	strncpy(data->last_month.download, "66/5", sizeof(data->last_month.download) - 1);
	strncpy(data->last_month.total, "72.56/5", sizeof(data->last_month.total) - 1);

	return ;
}


int parse_traffic_meter_config(cJSON *pRoot, struct traffic_conf *conf)
{
	int ret = 0, intVal = 0;
	char *charVal = NULL;
	
	ret = cjson_get_int(pRoot, "enabled", &intVal);
	if(ret < 0)
	{
		cgi_debug("can not find enabled paramter\n");
		return -1;
	}
	conf->enabled = intVal;

	if(1 == conf->enabled)
	{
		ret = cjson_get_int(pRoot, "limit_type", &intVal);
		if(ret < 0)
		{
			cgi_debug("can not find limit_type paramter\n");
			return -1;
		}
		conf->limit_type = intVal;

		if(NOT_LIMIT != conf->limit_type)
		{
			ret = cjson_get_int(pRoot, "limit_size", &intVal);
			if(ret < 0)
			{
				cgi_debug("can not find limit_size paramter\n");
				return -1;
			}
			conf->limit_size = intVal;
			
			ret = cjson_get_int(pRoot, "data_volume", &intVal);
		#if 0
			if(ret < 0)
			{
				cgi_debug("can not find data_volume paramter\n");
				return -1;
			}
		#endif
			conf->limit_data_volume = 0;//intVal;
		}
		
		ret = cjson_get_int(pRoot, "connect_time_enabled", &intVal);
		if(ret < 0)
		{
			cgi_debug("can not find connect_time_enabled paramter\n");
			return -1;
		}
		conf->limit_connect_time_enabled = intVal;

		if(1 == conf->limit_connect_time_enabled)
		{
			ret = cjson_get_int(pRoot, "connect_time", &intVal);
			if(ret < 0)
			{
				cgi_debug("can not find connect_time paramter\n");
				return -1;
			}
			conf->limit_connect_time = intVal;
		}
		
		charVal = cjson_get_string(pRoot, "restart_time");
		if(NULL == charVal)
		{
			cgi_debug("can not find restart_time paramter\n");
			return -1;
		}
		strncpy(conf->restart_time, charVal, sizeof(conf->restart_time) - 1);
		
		ret = cjson_get_int(pRoot, "show_limit_size", &intVal);
		if(ret < 0)
		{
			cgi_debug("can not find show_limit_size paramter\n");
			return -1;
		}

		if(intVal >= conf->limit_size)
		{
			cgi_debug("show limit size can not gt limit size\n");
			return -1;
		}
		conf->show_limit_size = intVal;
		
		ret = cjson_get_int(pRoot, "led_enabled", &intVal);
		if(ret < 0)
		{
			cgi_debug("can not find led_enabled paramter\n");
			return -1;
		}
		conf->led_enabled = intVal;
		
		ret = cjson_get_int(pRoot, "disconnect_network", &intVal);
		if(ret < 0)
		{
			cgi_debug("can not find disconnect_network paramter\n");
			return -1;
		}
		conf->disconnect_network = intVal;
	}
	
	return 0;
}


#define TRAFFIC_METER_API

int get_traffic_meter_config(cgi_request_t *req, cgi_response_t *resp)
{
	int ret = 0;
	struct traffic_conf conf;

	memset(&conf, 0x0, sizeof(struct traffic_conf));
	read_traffic_meter_config(&conf);

	webs_json_header(req->out);
    webs_write(req->out, "{\"code\":%d,\"data\":{", cgi_errno);
    webs_write(req->out, "\"enabled\":%d,\"limit_type\":%d,\"limit_size\":%d,"
            "\"data_volume\":%d,\"connect_time_enabled\":%d,\"connect_time\":%d,"
            "\"restart_time\":\"%s\",\"show_limit_size\":%d,\"led_enabled\":%d,\"disconnect_network\":%d",
            conf.enabled, conf.limit_type, conf.limit_size, conf.limit_data_volume, 
            conf.limit_connect_time_enabled,  conf.limit_connect_time, conf.restart_time, 
            conf.show_limit_size, conf.led_enabled, conf.disconnect_network);
    webs_write(req->out, "}}");

	return ret;
}

int set_traffic_meter_config(cgi_request_t *req, cgi_response_t *resp)
{
    int ret = 0;
    int method = 0;
    cJSON *params = NULL;

	struct traffic_conf conf;
    ret = param_init(req->post_data, &method, &params);
    if (ret < 0)
    {
        cgi_errno = CGI_ERR_PARAM; 
        goto out;
    }

	memset(&conf, 0x0, sizeof(struct traffic_conf));
	ret = parse_traffic_meter_config(params, &conf);
	if (ret < 0)
    {
        cgi_errno = CGI_ERR_CFG_PARAM;
        goto out;
	}
	
	save_traffic_meter_config(conf);
	config_commit("traffic");
	fork_exec(1, "/etc/init.d/traffic_meter restart");
out:
	param_free();

    webs_json_header(req->out);
    webs_write(req->out, "{\"code\":%d,\"data\":{}}", cgi_errno);
	
	return ret;
}

int get_traffic_meter_list(cgi_request_t *req, cgi_response_t *resp)
{
	int ret = 0;
	struct traffic_time_stat data;
	
	memset(&data, 0x0, sizeof(struct traffic_time_stat));
	get_traffic_count_data(&data);

	webs_json_header(req->out);
    webs_write(req->out, "{\"code\":%d,\"data\":{", cgi_errno);
    webs_write(req->out, "\"start_time\":\"%d\",\"current_time\":\"%d\",\"remainning_date\":\"%s\","
            "\"Today\":{\"connect_time\":\"%d\",\"upload\":\"%s\",\"download\":\"%s\",\"total\":\"%s\"},"
			"\"Yesterday\":{\"connect_time\":\"%d\",\"upload\":\"%s\",\"download\":\"%s\",\"total\":\"%s\"},"
			"\"ThisWeek\":{\"connect_time\":\"%d\",\"upload\":\"%s\",\"download\":\"%s\",\"total\":\"%s\"},"
			"\"ThisMonth\":{\"connect_time\":\"%d\",\"upload\":\"%s\",\"download\":\"%s\",\"total\":\"%s\"},"
			"\"LastMonth\":{\"connect_time\":\"%d\",\"upload\":\"%s\",\"download\":\"%s\",\"total\":\"%s\"}",
			1111111, 2222222, "1G 457M 768K Bytes",
			data.today.connect_time, data.today.upload, data.today.download, data.today.total,
			data.yesterday.connect_time, data.yesterday.upload, data.yesterday.download, data.yesterday.total,
			data.this_week.connect_time, data.this_week.upload, data.this_week.download, data.this_week.total,
			data.this_month.connect_time, data.this_month.upload, data.this_month.download, data.this_month.total,
			data.last_month.connect_time, data.last_month.upload, data.last_month.download, data.last_month.total);
    webs_write(req->out, "}}");

	return ret;

}

int restart_counter(cgi_request_t *req, cgi_response_t *resp)
{    
	fork_exec(1, "/usr/sbin/traffic_meter clearall");
    webs_json_header(req->out);
	webs_write(req->out, "{\"code\":%d,\"data\":{}}", cgi_errno);
	return 0;
}


