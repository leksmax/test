  
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

void get_residual_flow(unsigned long long total, char *residual_flow)
{
	int limit_type = NOT_LIMIT, limit_size = 0;

	limit_type = config_get_int(TRAFFIC_LIMIT_TYPE);
	if(limit_type != NOT_LIMIT)
	{
		unsigned long long size = 0, tmp = 0; 
		limit_size = config_get_int(TRAFFIC_LIMIT_SIZE);

		size = limit_size * 1024 * 1024LL;

		if(size > total)
		{
			tmp = size - total;
			cgi_debug("tmp = %lld, limit_size = %d sizz = %lld, total = %lld, \n", tmp,limit_size, size, total);
			if(tmp >= 1024 && tmp < 1024 * 1024LL)
			{
				sprintf(residual_flow, "0G 0M %lldK bytes", tmp / 1024);
			}
			else if(tmp >= (1024 * 1024LL) && tmp < (1024 * 1024 * 1024LL))
			{
				sprintf(residual_flow, "0G %lldM %lldK bytes", tmp / (1024 * 1024LL), tmp % 1024);
			}
			else if(tmp >= (1024 * 1024 * 1024LL))
			{
				sprintf(residual_flow, "%lldG %lldM %lldK bytes", tmp / (1024 * 1024 * 1024LL), 
					(tmp % (1024 * 1024 * 1024LL)) / (1024 * 1024LL), ((tmp % (1024 * 1024 * 1024LL)) % (1024 * 1024LL)) / 1024 );
			}
			else 
			{
				sprintf(residual_flow, "%lld bytes", tmp);	
			}
		}
		else
		{
			strcpy(residual_flow, "0 bytes");	
		}
	}
	else
	{
		strcpy(residual_flow, "Not Limit");	
	}
	return ;
}

void get_traffic_count_data(struct traffic_time_stat *data, char *residual_flow)
{
	FILE *fp = NULL;
	unsigned long long upload, download, total;
	int days = 0, week = 0;
	char strline[1024] = {0}, str_time[10] = {0};
	
	fp = fopen(TRAFFIC_METER_DATA_FILE, "r");

	if(fp != NULL)
	{
		while(fgets(strline, sizeof(strline), fp))
		{
			//printf("strline = %s\n", strline);
			if(strstr(strline, "start timespec:") != NULL)
			{
				sscanf(strline, "start timespec: %ld", &data->cur_timespec);
			}
			if(strstr(strline, "today") != NULL)
			{
				sscanf(strline, "today: %llu %llu %llu %s", &upload, &download, &total, data->today.time_s);
				snprintf(data->today.upload, sizeof(data->today.upload), "%.2f", upload / BYTES_UNIT);
				snprintf(data->today.download, sizeof(data->today.download), "%.2f", download / BYTES_UNIT);
				snprintf(data->today.total, sizeof(data->today.total), "%.2f", total / BYTES_UNIT);
			}

			if(strstr(strline, "yesterday") != NULL)
			{
				sscanf(strline, "yesterday: %llu %llu %llu %s", &upload, &download, &total, data->yesterday.time_s);
				snprintf(data->yesterday.upload, sizeof(data->yesterday.upload), "%.2f", upload / BYTES_UNIT);
				snprintf(data->yesterday.download, sizeof(data->yesterday.download), "%.2f", download / BYTES_UNIT);
				snprintf(data->yesterday.total, sizeof(data->yesterday.total), "%.2f", total / BYTES_UNIT);
			}

			if(strstr(strline, "week") != NULL)
			{
				sscanf(strline, "week: %llu %llu %llu %d %d %s", &upload, &download, &total, &days, &week, str_time);
				snprintf(data->this_week.upload, sizeof(data->this_week.upload), "%.2f/%.2f", upload / BYTES_UNIT, upload / (BYTES_UNIT * days));
				snprintf(data->this_week.download, sizeof(data->this_week.download), "%.2f/%.2f", download / BYTES_UNIT, download / (BYTES_UNIT * days));
				snprintf(data->this_week.total, sizeof(data->this_week.total), "%.2f/%.2f", total / BYTES_UNIT, total / (BYTES_UNIT * days));
				snprintf(data->this_week.time_s, sizeof(data->this_week.time_s), "week:%d %s", week, str_time);
			}

			if(strstr(strline, "month") != NULL)
			{
				sscanf(strline, "month: %llu %llu %llu %d %d %s", &upload, &download, &total, &days, &week, str_time);
				snprintf(data->this_month.upload, sizeof(data->this_month.upload), "%.2f/%.2f", upload / BYTES_UNIT, upload / (BYTES_UNIT * days));
				snprintf(data->this_month.download, sizeof(data->this_month.download), "%.2f/%.2f", download / BYTES_UNIT, download / (BYTES_UNIT * days));
				snprintf(data->this_month.total, sizeof(data->this_month.total), "%.2f/%.2f", total / BYTES_UNIT, total / (BYTES_UNIT * days));
				snprintf(data->this_month.time_s, sizeof(data->this_month.time_s), "day:%d %s", week, str_time);
				get_residual_flow(total, residual_flow);
			}

			if(strstr(strline, "last_month") != NULL)
			{
				sscanf(strline, "last_month: %llu %llu %llu %d %d %s", &upload, &download, &total, &days, &week, str_time);
				snprintf(data->last_month.upload, sizeof(data->last_month.upload), "%.2f/%.2f", upload / BYTES_UNIT, upload / (BYTES_UNIT * days));
				snprintf(data->last_month.download, sizeof(data->last_month.download), "%.2f/%.2f", download / BYTES_UNIT, download / (BYTES_UNIT * days));
				snprintf(data->last_month.total, sizeof(data->last_month.total), "%.2f/%.2f", total / BYTES_UNIT, total / (BYTES_UNIT * days));
				snprintf(data->last_month.time_s, sizeof(data->last_month.time_s), "day:%d %s", week, str_time);
			}

		}
		fclose(fp);
	}

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

		if(NOT_LIMIT != conf->limit_type && intVal >= conf->limit_size)
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
	fork_exec(1, "/etc/init.d/traffic_init restart");
out:
	param_free();

    webs_json_header(req->out);
    webs_write(req->out, "{\"code\":%d,\"data\":{}}", cgi_errno);
	
	return ret;
}

int get_traffic_meter_list(cgi_request_t *req, cgi_response_t *resp)
{
	int ret = 0;
	time_t tt;
	struct traffic_time_stat data;
	char residual_flow[64] = {0};
	
	memset(&data, 0x0, sizeof(struct traffic_time_stat));
	get_traffic_count_data(&data, residual_flow);
	
	webs_json_header(req->out);
    webs_write(req->out, "{\"code\":%d,\"data\":{", cgi_errno);
    webs_write(req->out, "\"start_time\":%ld,\"current_time\":%ld,\"remainning_flow\":\"%s\","
            "\"Today\":{\"count_time\":\"%s\",\"upload\":\"%s\",\"download\":\"%s\",\"total\":\"%s\"},"
			"\"Yesterday\":{\"count_time\":\"%s\",\"upload\":\"%s\",\"download\":\"%s\",\"total\":\"%s\"},"
			"\"ThisWeek\":{\"count_time\":\"%s\",\"upload\":\"%s\",\"download\":\"%s\",\"total\":\"%s\"},"
			"\"ThisMonth\":{\"count_time\":\"%s\",\"upload\":\"%s\",\"download\":\"%s\",\"total\":\"%s\"},"
			"\"LastMonth\":{\"count_time\":\"%s\",\"upload\":\"%s\",\"download\":\"%s\",\"total\":\"%s\"}",
			data.cur_timespec, time(&tt), residual_flow,
			data.today.time_s, data.today.upload, data.today.download, data.today.total,
			data.yesterday.time_s, data.yesterday.upload, data.yesterday.download, data.yesterday.total,
			data.this_week.time_s, data.this_week.upload, data.this_week.download, data.this_week.total,
			data.this_month.time_s, data.this_month.upload, data.this_month.download, data.this_month.total,
			data.last_month.time_s, data.last_month.upload, data.last_month.download, data.last_month.total);
    webs_write(req->out, "}}");

	return ret;

}

int restart_counter(cgi_request_t *req, cgi_response_t *resp)
{    
	fork_exec(1, "killall -USR2 traffic_meter");
    webs_json_header(req->out);
	webs_write(req->out, "{\"code\":%d,\"data\":{}}", cgi_errno);
	return 0;
}


