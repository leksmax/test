#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "cJSON.h"
#include "vpn_config.h"
#include "file_tool.h"
#include "net_tool.h"
#include "process_tool.h"
#include "my_debug.h"
#include "system-config.h"

#define DEFAULT_CONFIG_FILE	"/etc/vpn-config/default.conf"
#define VPPN_CLOUD_CONF_FILE_FMT	"/etc/site/manager"
#define VPPN_TUNNEL_CONF_FILE_FMT	"/etc/site/site%d.conf"
#define VPN_CLOUD_CONF_FILE_FMT	"/etc/vpn/manager"
#define VPN_TUNNEL_CONF_FILE_FMT	"/etc/vpn/vpn%d.conf"


#define DEFAULT_CLOUD_SERVER "220.168.30.11"
#define DEFAULT_CLOUD_PORT (8888)

void printUsage()
{
	printf("vppnctrl [-t 0] <-d> ACTION\n");
	printf("Available ACTIONs:\n");
	printf("\trun\n");
	printf("\tkill\n");
	printf("\tstart\n");
	printf("\tstop\n");
	return;
}

#define VPN_TINC_SERVER	"server_addr"
#define VPN_TINC_SERVER_PORT	"server_port"
#define VPN_TINC_MYSELF_ADDR	"myself_addr"
#define VPN_TINC_TEAMID	"team_id"
#define VPN_SWITCH_STR  "on"

void my_skip_crlf(char *str)
{
	int i;
	if (str)
	{
		int str_len = strlen(str);
		for(i = 0; i < str_len; i++)
		{
			if (str[i] == '\r' || str[i] == '\n')
			{
				str[i] = 0;
			}
		}
	}
	return;
}

void vpn_config_load_tunnel_log_config(struct vpn_config_s *config, int tunnel_id)
{
	char log_conf_file[100];
	sprintf(log_conf_file, "/tmp/vppn_log_site%d.conf", tunnel_id);
	cJSON *log_obj = read_json_from_file(log_conf_file);
	if (log_obj)
	{
		cJSON *on_item = cJSON_GetObjectItem(log_obj, "log_on");
		cJSON *level_item = cJSON_GetObjectItem(log_obj, "log_level");
		if (on_item && on_item->valueint > 0
				&&
				level_item)
		{
			config->tunnel.log_on = 1;
			config->tunnel.log_level = level_item->valueint;
		}
	}
}

int vpn_config_load_tunnel_config(struct vpn_config_s *config, char *file_name, int tunnel_id)
{
	int ret = -1;
	char *conf = read_text(file_name);
	strncpy(config->tunnel.tunnel_dev, config->custom_tunnel_dev, sizeof(config->custom_tunnel_dev));
	if (conf)
	{
		cJSON *root = cJSON_Parse(conf);
		if (root)
		{
			if (root->type == cJSON_Object)
			{
				cJSON *on_item = cJSON_GetObjectItem(root, VPN_SWITCH_STR);
				cJSON *team_id_item = cJSON_GetObjectItem(root, VPN_TINC_TEAMID);
#if 1
				config->tunnel.tunnel_id = tunnel_id;
				if (on_item)
				{
					config->tunnel.tunnel_on = on_item->valueint;
				}
				if (team_id_item)
				{
					strcpy(config->team_id, team_id_item->valuestring);
				}
#else
				cJSON *server_item = cJSON_GetObjectItem(root, VPN_TINC_SERVER);
				cJSON *server_port_item = cJSON_GetObjectItem(root, VPN_TINC_SERVER_PORT);
				cJSON *myself_item = cJSON_GetObjectItem(root, VPN_TINC_MYSELF_ADDR);
				cJSON *teamid_item = cJSON_GetObjectItem(root, VPN_TINC_TEAMID);
				//cJSON *country_item = cJSON_GetObjectItem(root, "country_code");
				config->tunnel.tunnel_id = tunnel_id;
				if (on_item)
				{
					config->tunnel.tunnel_on = on_item->valueint;
				}
				if (server_item)
				{
					strcpy(config->tunnel.info.resource.vpn_server_host, server_item->valuestring);
				}
				if (server_port_item)
				{
					config->tunnel.info.resource.vpn_server_port = server_port_item->valueint;
				}
				if (myself_item)
				{
					strcpy(config->tunnel.info.resource.vpn_ip, myself_item->valuestring);
				}
				if (teamid_item)
				{
					strcpy(config->teamid, teamid_item->valuestring);
				}
#endif
				/*if (country_item)
				{
					strcpy(config->tunnel.tunnel_vpn_country, country_item->valuestring);
				}*/
				ret = 0;
			}
			cJSON_Delete(root);
		}
		free(conf);
	}
	else
	{
		char vppn_enable[100] = "";
		char vppn_teamid[100] ="";
		system_config_get("vppn_enable", vppn_enable);
		system_config_get("vppn_teamid", vppn_teamid);
		if (vppn_enable[0] && vppn_teamid[0])
		{
			config->tunnel.tunnel_on = atoi(vppn_enable);
			strcpy(config->team_id, vppn_teamid);
			ret = 0;
		}
	}
	return ret;
}

int vpn_config_load_cloud_config(struct vpn_config_s *config, char *file_name)
{
	int ret = -1;
	char *conf = read_text(file_name);
	if (conf)
	{
		cJSON *root = cJSON_Parse(conf);
		if (root)
		{
			if (root->type == cJSON_Object)
			{
				cJSON *host_item = cJSON_GetObjectItem(root, "cloud_host");
				cJSON *port_item = cJSON_GetObjectItem(root, "cloud_port");
				if (port_item && host_item)
				{
					config->cloud_port = port_item->valueint;
					strcpy(config->cloud_host, host_item->valuestring);
					ret = 0;
				}
			}
			cJSON_Delete(root);
		}
		free(conf);
	}
	/* apply default config */
	else
	{
		//read from config
		config->cloud_port = DEFAULT_CLOUD_PORT;
		strcpy(config->cloud_host, DEFAULT_CLOUD_SERVER);
		ret = 0;
	}
	return ret;
}

void vpn_config_cloud_conf_file(char *file_buf, int tunnel, int conf_type)
{
	if (conf_type == 0)
	{
		sprintf(file_buf, VPN_CLOUD_CONF_FILE_FMT);
	}
	else
	{
		sprintf(file_buf, VPPN_CLOUD_CONF_FILE_FMT);
	}
	return;
}

void vpn_config_tunnel_conf_file(char *file_buf, int tunnel, int conf_type)
{
	if (conf_type == 0)
	{
		sprintf(file_buf, VPN_TUNNEL_CONF_FILE_FMT, tunnel);
	}
	else
	{
		sprintf(file_buf, VPPN_TUNNEL_CONF_FILE_FMT, tunnel);
	}
	return;
}

static 

/* set self_id with mac addr of wan */
void vpn_config_set_self_id(struct vpn_config_s *config)
{
    char *id = read_text((char*)"/etc/vppn_id");
    if (id)
    {
        strncpy(config->self_id, id, sizeof(config->self_id) -1);
        free(id);
    }
    else
    {
#if 1
		char *ret_buf = process_tool_run_cmd((char*)"artmtd -r sn | head -n 1 | awk -F: '{print $2}'");
		if (ret_buf)
		{
			my_skip_crlf(ret_buf);
			strcpy(config->self_id, ret_buf);
			free(ret_buf);
		}
		else
		{
			strcpy(id, "PC123456");
		}
#else
		net_tool_get_if_hwaddr(config->custom_lan_if, config->self_id);
#endif
	}
	//net_tool_get_if_hwaddr("br0", config->self_id);
	return;
}

int vpn_tunnel_reload_config(struct vpn_config_s *config, int tunnel_id, int conf_type)
{
	char cloud_file[200];
	char tunnel_file[200];
	int ret = 0;
	int     ret_cloud;
	int     ret_tunnel;
	vpn_config_set_self_id(config);
	vpn_config_cloud_conf_file(cloud_file, tunnel_id, conf_type);
	vpn_config_tunnel_conf_file(tunnel_file, tunnel_id, conf_type);
	ret_cloud = vpn_config_load_cloud_config(config, cloud_file);
	ret_tunnel = vpn_config_load_tunnel_config(config, tunnel_file, tunnel_id);
	vpn_config_load_tunnel_log_config(config, tunnel_id);

	ret = ret_cloud || ret_tunnel;
	return ret;
}
extern int client_debug_level;
int vpn_config_load(struct vpn_config_s *config, int argc, char **argv, int *action, int *tunnel_id)
{
	int		tunnel = 0;
	int		c;
	int		ret = -1;
	/* default as vppn type */
	config->tunnel_type = 1;
	while( (c=getopt(argc,argv,"dt:c:D:l:")) != -1 )
	{
		switch (c)
		{
			case 't':
				tunnel = atoi(optarg);
				break;
			case 'd':
				config->debug = 1;
				break;
			case 'D':
				my_debug_set_level(atoi(optarg));
				break;
			case 'l':
				client_debug_level = atoi(optarg);
				break;
			case 'c':
				/* config as vpn type */
				if (strcmp(optarg, "vpn") == 0)
				{
					config->tunnel_type = 0;
				}
				break;
			default:
				printUsage();
				exit(-1);
				break;
		}
	}

	/* parse the custom config */
	cJSON *custom = read_json_from_file((char*)"/etc/vppn_custom.conf");
	if (custom)
	{
		cJSON *wan_item = cJSON_GetObjectItem(custom, "wan_interface");
		cJSON *lan_item = cJSON_GetObjectItem(custom, "lan_interface");
		cJSON *dev_item = cJSON_GetObjectItem(custom, "tun_dev");
		if (wan_item && wan_item->valuestring
				&&
				lan_item && lan_item->valuestring
				&&
				dev_item && dev_item->valuestring
				)
		{
			strncpy(config->custom_wan_if, wan_item->valuestring, sizeof(config->custom_wan_if));
			strncpy(config->custom_lan_if, lan_item->valuestring, sizeof(config->custom_lan_if));
			strncpy(config->custom_tunnel_dev, dev_item->valuestring, sizeof(config->custom_tunnel_dev));
			goto CONTINUE;
		}
		cJSON_Delete(custom);
	}
	printf("Error, /etc/vppn_custom.conf error\n");
	exit(-1);
CONTINUE:
	if (tunnel >= 0)
	{
		vpn_config_set_self_id(config);
		*tunnel_id = tunnel;
		if(strcmp(argv[optind], "run") == 0)
		{
			ret = 0;
			*action = ACTION_RUN;
		}
		else if(strcmp(argv[optind], "kill") == 0)
		{
			ret = 0;
			*action = ACTION_KILL;
		}
		else if(strcmp(argv[optind], "reload") == 0)
		{
			ret = 0;
			*action = ACTION_RELOAD;
		}
		else if(strcmp(argv[optind], "set_debug_level") == 0)
		{
			ret = 0;
			*action = ACTION_SET_DEBUG_LEVEL;
		}
		/*
#if (HAVE_DNS_REPORT == 1)
		else if(strcmp(argv[optind], "dns_report") == 0)
		{
			char cloud_file[200];
			vpn_config_cloud_conf_file(cloud_file, tunnel);
			int ret_cloud = vpn_config_load_cloud_config(config, cloud_file);
			if (ret_cloud == 0)
			{
				ret = 0;
				vpn_config_set_self_id(config);
				*action = ACTION_DNS_REPORT_LOOP;
			}
		}
#endif
		*/
	}
	return ret;
}
