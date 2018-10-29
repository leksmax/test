#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/socket.h>
#include <netinet/in.h>
#include <net/route.h>
#include <net/if.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/ioctl.h>
#include <linux/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <pthread.h>
#include "vpn_config.h"
#include "vpn_cloud.h"
#include "cJSON.h"
#include "net_tool.h"
#include "file_tool.h"
#include "process_tool.h"
#include "timer_tool.h"
//#include "iptables_tool.h"
#include "ctrl_server.h"
#include "ctrl-interface.h"
#include "my_debug.h"
//#include "attachdevice.h"
#include "log_tool.h"
#include "my-device.h"
#include "HttpClient.h"
#include "system-config.h"
#include "tinctool.h"

#define HTTP_TUNNEL_TINC_CLIENT_PORT (2323)
#define HTTP_TUNNEL_TINC_SERVER_PORT (8080)

extern void create_peers_update_thread();

#define PUBLIC_WHITE_LIST_FILE "/etc/vpn/publicwhitelist%d.conf"
#define WHITELIST_CONF_FMT	"/etc/site/whitelist%d.conf"
#define DNSMASQ_CONF_FMT	"/etc/dnsmasq.d/vppn_whitelist%d.conf"
#define KEY_DIR				"/tmp/"
#define VPN_SERVER_VIP		"10.255.255.254"

static bool s_enable_proxy = false;
int tunnel_id = -1;
int tunnel_on = 0;

pthread_mutex_t bakup_lock;
struct vpn_config_s g_config;
struct vpn_config_s g_config_bakup;

int refresh_flag = 0;
int running = 1;
extern int create_vpn_status_thread();
extern void update_vpn_status();

void GetConfig(const char *name, char *value)
{
	FILE *file = NULL;
	char cmd_buf[4000];
	char read_buf[4000];
	sprintf(cmd_buf, "/bin/config get %s", name);
	file = popen(cmd_buf, "r");
	if (file)
	{
		while(fgets(read_buf, sizeof(read_buf), file))
		{
			//output_oui(read_buf);
			strcpy(value, read_buf);
			usleep(1000);
		}
		pclose(file);
	}
	return;
}

int get_local_subnet(char *subnet)
{
	struct vpn_config_s* dump_config = ctrl_get_tunnel_config();
	int ret = net_tool_get_if_subnet(dump_config->custom_lan_if, subnet);
	free(dump_config);
	return ret;
}

#define TUNNEL_VPN_PID_FILE_FMT ("/var/run/vpnctrl%d.pid")
#define TUNNEL_VPPN_PID_FILE_FMT ("/var/run/vppnctrl%d.pid")
void vpn_tunnel_pid_file(int tunnel_id, char *buf, int conf_type)
{
	if (conf_type == 0)
	{
		sprintf(buf, TUNNEL_VPN_PID_FILE_FMT, tunnel_id);
	}
	else
	{
		sprintf(buf, TUNNEL_VPPN_PID_FILE_FMT, tunnel_id);
	}
	return;
}

void remove_ctrl_pid_file(int tunnel_id, int conf_type)
{
	char pid_file[200];
	vpn_tunnel_pid_file(tunnel_id, pid_file, conf_type);
	remove(pid_file);
	return;
}

void gen_ctrl_pid_file(int tunnel_id, int pid, int conf_type)
{
	char pid_file[200];
	vpn_tunnel_pid_file(tunnel_id, pid_file, conf_type);
	char pid_str[200];
	sprintf(pid_str, "%d\n", pid);
	write_text(pid_file, pid_str);
	return;
}

int get_ctrl_pid(int tunnel_id, int conf_type)
{
	int ret_pid = 0;
	char pid_file[200];
	vpn_tunnel_pid_file(tunnel_id, pid_file, conf_type);
	FILE *fp = fopen(pid_file, "r");
	if (fp)
	{   
		char buf[1000];
		while(fgets(buf, sizeof(buf), fp))
		{   
			ret_pid = atoi(buf);
			break;
		}   
		fclose(fp);
	}   
	return ret_pid;
}

void set_ctrl_pid(int tunnel, int pid, int conf_type)
{
	gen_ctrl_pid_file(tunnel_id, pid, conf_type);
	return ;
}


void dump_JSON(cJSON *json)
{
	char *str = cJSON_Print(json);
	if (str)
	{
		MY_DEBUG_INFO("%s\n", str);
		free(str);
	}
	else
	{
		MY_DEBUG_INFO("unknown json\n");
	}
	return;
}

int is_ip(char *host)
{
	int ret = 1;
	int len = strlen(host);
	int i;
	for(i = 0; i < len; i++)
	{
		if(host[i] != '.' && (host[i] > '9' || host[i] < '0'))
		{
			ret = 0;
			break;
		}
	}
	return ret;
}

void vpn_tunnel_get_name_form_resource_id(struct vpn_tunnel_s *tunnel, char* name)
{
	sprintf(name, "%d_%d_%d", tunnel->info.resource.resource_id/(256 * 256), (tunnel->info.resource.resource_id/256) % 256, tunnel->info.resource.resource_id % 256);
}

void get_name_from_vip(char* vip, char* name)
{
	int tmp1;
	int tmp2;
	int tmp3;
	int tmp4;
	sscanf(vip, "%d.%d.%d.%d", &tmp1, &tmp2, &tmp3, &tmp4);
	sprintf(name, "%d_%d_%d", tmp2, tmp3, tmp4);
}

void vpn_tunnel_set_resource_id(struct vpn_tunnel_s *tunnel, char *ip_str)
{
	/* find the 3rd dot according to vpn_ip */
	int tmp1;
	int tmp2;
	int tmp3;
	int tmp4;
	sscanf(ip_str, "%d.%d.%d.%d", &tmp1, &tmp2, &tmp3, &tmp4);
	tunnel->info.resource.resource_id = tmp2 *256 * 256 + tmp3 * 256 + tmp4;
}

int vpn_tunnel_get_resource_id(struct vpn_tunnel_s *tunnel)
{
	return tunnel->info.resource.resource_id;
}

char *vpn_tunnel_get_gw(struct vpn_tunnel_s *tunnel)
{
	char ip_buf1[32];
	char ip_buf2[32];
	int ip_seg1;
	int ip_seg2;
	int ip_seg3;
	int ip_seg4;
	strcpy(ip_buf1, tunnel->info.resource.vpn_ip);
	sscanf(ip_buf1, "%d.%d.%d.%d", &ip_seg1, &ip_seg2, &ip_seg3, &ip_seg4);
	sprintf(ip_buf2, "%d.%d.%d.%d", ip_seg1, ip_seg2, ip_seg3 ,1);
	return strdup(ip_buf2);
}

/* return -1:means cloud unreachable */
/* return 0:means need realloc resource */
/* return 1:means ok */
int vpn_tunnel_heartbeat(struct vpn_tunnel_s *tunnel, char *user, char *cloud_host, int cloud_port ,int server_reachable, int new_status)
{
	int ret = -1;
	cJSON *req = cJSON_CreateObject();
	cJSON_AddStringToObject(req, "mac", user);
	char labelName[100]= "";
	system_config_get((char*)"Device_name", labelName);
	cJSON_AddStringToObject(req, "labelName", labelName);
	cJSON_AddStringToObject(req, "ip", tunnel->info.resource.vpn_ip);
	cJSON_AddStringToObject(req, "proxyIp", tunnel->info.resource.vpn_server_host);
	//cJSON_AddNumberToObject(req, "proxyPort", tunnel->info.resource.vpn_server_port);
	cJSON_AddStringToObject(req, "teamId", g_config.team_id);
	/* 0 for router, 1 for other client */
	cJSON_AddNumberToObject(req, "memberType", 0);
	//cJSON_AddStringToObject(req, "teamId", tunnel->info.resource.teamid);
	char wan_ip[100] = "";
	char wan_subnet[100] = "";
	struct vpn_config_s* dump_config = ctrl_get_tunnel_config();
	//get_wan_subnet(wan_ip);

	cJSON* subnets = get_all_lan_subnets();
	get_my_wansubnet(wan_subnet);
	get_my_wanip(wan_ip);
	if (subnets)
	{
		cJSON_AddItemToObject(req, "lan_info", subnets);
	}

	cJSON_AddStringToObject(req, "wan", wan_subnet);
	cJSON_AddStringToObject(req, "wan_ip", wan_ip);
	cJSON_AddNumberToObject(req, "status", new_status);
	free(dump_config);
	//cJSON_AddStringToObject(req, "ConnectTo", tunnel->info.resource.vpn_server_host);
	//cJSON_AddStringToObject(req, "Subnet", tunnel->info.resource.vpn_ip);
	//cJSON *stat_item = cJSON_CreateObject();
	//cJSON_AddNumberToObject(stat_item, "PingStat", ping_latency);
	//cJSON_AddItemToObject(req, "Status", stat_item);
	dump_JSON(req);
#if 1
	//cJSON* response = net_tool_http_json_client2(1, cloud_host, cloud_port, "/vppn/api/v1/client/heartBeat", req, "Authorization: Basic YWRtaW46cHVibGlj\r\n");
	cJSON* response = vpn_cloud_tool3((char*)"/vppn/api/v1/client/heartBeat", req);
	if (response)
	{
		dump_JSON(response);
		if (response->type == cJSON_Object)
		{
			cJSON *code_item = cJSON_GetObjectItem(response, "code");
			if (code_item)
			{
				tunnel->last_heartbeat_code = code_item->valueint;
				/* need update select_code */
				tunnel->last_select_code = code_item->valueint;
				sprintf(tunnel->info.resource.error_code, "%d", code_item->valueint);
				if (code_item->valueint == 200)
				{
					cJSON *other_item = cJSON_GetObjectItem(response, "OtherInfo");
					if (other_item)
					{
						cJSON *endtime_item = cJSON_GetObjectItem(other_item, "endTime");
						if (endtime_item && endtime_item->type == cJSON_String)
						{
							strncpy(tunnel->info.package.endtime, endtime_item->valuestring, sizeof(tunnel->info.package.endtime));
						}
						cJSON *flow_item = cJSON_GetObjectItem(other_item, "flow");
						if (flow_item)
						{
							strncpy(tunnel->info.package.flow, flow_item->valuestring, sizeof(tunnel->info.package.flow));
						}
						cJSON *mac_item = cJSON_GetObjectItem(other_item, "mac");
						if (mac_item)
						{
							strncpy(tunnel->info.package.mac, mac_item->valuestring, sizeof(tunnel->info.package.mac));
						}
						cJSON *type_item = cJSON_GetObjectItem(other_item, "type");
						if (type_item)
						{
							strncpy(tunnel->info.package.type, type_item->valuestring, sizeof(tunnel->info.package.type));
						}
					}
					ret = 1;
				}
				else if(code_item->valueint == 903
						|| code_item->valueint == 904
						|| code_item->valueint == 906
						|| code_item->valueint == 908
						)
				{
					//log_tool_log("Heartbeat ret code %d", code_item->valueint);
					ret = 1;
				}
#if 0
				/* get some shell cmds from remote */
				else if (strcmp(code_item->valuestring, "300") == 0)
				{
					/* 注意使用shell cmd一定要能够返回，不要使用top/ping之类的命令 */
					cJSON *cmd_item = cJSON_GetObjectItem(response, "OtherInfo");
					if (cmd_item && cmd_item->valuestring)
					{
						do_cmd(cmd_item->valuestring);
					}
					ret = 1;
				}
#endif
				else
				{
					//log_tool_log("Heartbeat ret code %d", code_item->valueint);
					ret = 0;
				}
			}
		}
		cJSON_Delete(response);
	}
	else
	{
		//log_tool_log("Cloud not reachable");
	}
#endif
	cJSON_Delete(req);
	return ret;
}

void vpn_tunnle_public_whitelist_file(char *buf, int tunnel_id)
{
	sprintf(buf, PUBLIC_WHITE_LIST_FILE, tunnel_id);
	return;
}

int vpn_tunnel_set_public_whitelist_by_id(int tunnel_id, char *user, char *cloud_host, int cloud_port)
{
	int get_ret = -1;
	cJSON *req = cJSON_CreateObject();
	cJSON_AddNumberToObject(req, "tunnel_id", tunnel_id);
	if (req)
	{
		cJSON *response = vpn_cloud_tool3((char*)"/GetWhiteList", req);
		//cJSON *response = vpn_cloud_tool(req, cloud_host, cloud_port, "/GetWhiteList");
		if (response)
		{
			int array_count = cJSON_GetArraySize(response);
			int i;
			for(i = 0; i < array_count; i++)
			{
				cJSON *wl_array = cJSON_GetArrayItem(response, i);
				cJSON *wl = cJSON_GetObjectItem(wl_array, "List");
				if (wl)
				{
					cJSON *json_wl = cJSON_CreateObject();
					cJSON *json_list = cJSON_Duplicate(wl, 1);
					cJSON_AddItemToObject(json_wl, "whitelist", json_list);
					char *str = cJSON_Print(json_wl);
					if (str)
					{
						char public_list[200];
						vpn_tunnle_public_whitelist_file(public_list, tunnel_id);
						write_text(public_list, str);
						free(str);
					}
					cJSON_Delete(json_wl);
				}
			}
			cJSON_Delete(response);
		}
		cJSON_Delete(req);
	}
	return get_ret;
}

int vpn_tunnel_set_public_whitelist(struct vpn_tunnel_s *tunnel, char *user, char *cloud_host, int cloud_port)
{
	return vpn_tunnel_set_public_whitelist_by_id(tunnel->tunnel_id, user, cloud_host, cloud_port);
}

int vpn_tunnel_unset_public_whitelist_by_id(int tunnel_id, char *user, char *cloud_host, int cloud_port)
{
	int unset_ret = 0;
	char public_list[200];
	vpn_tunnle_public_whitelist_file(public_list, tunnel_id);
	remove(public_list);
	return unset_ret;
}

int vpn_tunnel_unset_public_whitelist(struct vpn_tunnel_s *tunnel, char *user, char *cloud_host, int cloud_port)
{
	return vpn_tunnel_unset_public_whitelist_by_id(tunnel->tunnel_id, user, cloud_host, cloud_port);
}

int vpn_tunnel_alive_confirm(struct vpn_tunnel_s *tunnel, char *user, char *cloud_host, int cloud_port, int conf_type)
{
	int ret = -1;
	cJSON *req = cJSON_CreateObject();
	cJSON_AddStringToObject(req, "MACAddr", user);
	cJSON *response = vpn_cloud_tool3((char*)"/vlan/routerHeartbeat", req);
	//cJSON *response = vpn_cloud_tool(req, cloud_host, cloud_port, "/vlan/routerHeartbeat");
	if (response)
	{
		ret = 0;
		cJSON_Delete(response);
	}
	cJSON_Delete(req);
	return ret;
}

//return 0:ok
//return -1:self is not in the members 
int set_members_conf(cJSON* members, char* teamid, char* self_id, int tunnel_id, struct vpn_tunnel_s *tunnel)
{
	int ret = -1;
	char peers_file[100];
	sprintf(peers_file, "/etc/site/vppn%d_peers.conf", tunnel_id);
	cJSON* new_arr = cJSON_CreateArray();
	if (new_arr)
	{
		int cnt = cJSON_GetArraySize(members);
		int i;
		for(i = 0; i < cnt; i++)
		{
			cJSON* item = cJSON_GetArrayItem(members, i);
			cJSON* ip_item = cJSON_GetObjectItem(item, "ip");
			cJSON* mac_item = cJSON_GetObjectItem(item, "mac");
			cJSON* status_item = cJSON_GetObjectItem(item, "status");
			cJSON* geoip_item = cJSON_GetObjectItem(item, "geo_ip");
			cJSON* wanip_item = cJSON_GetObjectItem(item, "wan_ip");
			cJSON* pubkey_item = cJSON_GetObjectItem(item, "pubkey");
			cJSON* connectionLimit_item = cJSON_GetObjectItem(item, "connectionLimit");
			if (strcmp(mac_item->valuestring, self_id) != 0)
			{
				cJSON* new_item = cJSON_CreateObject();
				cJSON_AddStringToObject(new_item, "peer_vip", ip_item->valuestring);
				cJSON_AddStringToObject(new_item, "peer_teamid", teamid);
				if (geoip_item && wanip_item)
				{
					if (strcmp(geoip_item->valuestring, wanip_item->valuestring) == 0)
					{
						cJSON_AddStringToObject(new_item, "peer_wan_ip", wanip_item->valuestring);
					}
					else
					{
						cJSON_AddStringToObject(new_item, "peer_wan_ip", "");
					}
				}

				if (status_item)
				{
					if (status_item->valueint == 1)
					{
						cJSON_AddNumberToObject(new_item, "peer_status", 1);
					}
					else
					{
						cJSON_AddNumberToObject(new_item, "peer_status", 0);
					}
				}

				if (pubkey_item)
				{
					cJSON_AddStringToObject(new_item, "peer_pubkey", pubkey_item->valuestring);
				}
				cJSON_AddItemToArray(new_arr, new_item);
				if (status_item)
				{
					log_tool_log(1,5,"Connectivity to Remote routers: sn - %s, virtual ip - %s, online - %d", mac_item->valuestring, ip_item->valuestring, status_item->valueint);
				}
			}
			else
			{
				strcpy(tunnel->info.resource.vpn_ip, ip_item->valuestring);
				vpn_tunnel_set_resource_id(tunnel, ip_item->valuestring);
				strcpy(tunnel->tunnel_relay_name, "vpnserver");
				tunnel->tunnel_relay_limit = atoi(connectionLimit_item->valuestring);
				tunnel->tunnel_public = 0;
				if (geoip_item && wanip_item)
				{
					if (strcmp(geoip_item->valuestring, wanip_item->valuestring) == 0)
					{
						tunnel->tunnel_public = 1;
					}
				}
				if (status_item)
				{
					//log_tool_log("Get self virtual ip:%s", ip_item->valuestring);
				}
				ret = 0;
			}
		}
		write_json_to_file(peers_file, new_arr);
		cJSON_Delete(new_arr);
		//ctrl_reload_bird(1, tunnel_id, teamid);
		ctrl_restart_swap_routed();
	}
	return ret;
}

int vpn_tunnel_select_resource_from_cloud2(struct vpn_tunnel_s *tunnel, char *user, char *cloud_host, int cloud_port, int conf_type, int tunnel_id)
{
	cJSON *req = NULL;
	int get_ret = ERROR_CLOUD_UNREACHABLE;
	memset(&tunnel->info.resource , 0, sizeof(tunnel->info.resource));
	MY_DEBUG_INFO("cloud_host:%s, cloud_port:%d\n", cloud_host, cloud_port);
	req = cJSON_CreateObject();
	if (req)
	{
		cJSON_AddStringToObject(req, "teamId", user);

#if 1
		//wait until pubkey generated
		char* pubkey_str = NULL;
		do {
			pubkey_str = read_text((char*)"/tmp/vppn_pub.pem");
		}while(pubkey_str == NULL);
		cJSON_AddStringToObject(req, "pubKey", pubkey_str);
		free(pubkey_str);
		cJSON_AddStringToObject(req, "mac", g_config.self_id);
#endif
		dump_JSON(req);
		cJSON* response = vpn_cloud_tool3((char*)"/vppn/api/v1/client/searchTeamById", req);
		//printf("1\n");
		//dump_JSON(response);
		cJSON_Dump(response);
		if (response)
		{
			cJSON* code_item = cJSON_GetObjectItem(response, "code");
			if (code_item)
			{
				//strncpy(tunnel->info.resource.error_code, code_item->valuestring, sizeof(tunnel->info.resource.error_code));
				//log_tool_log("Get resource ret code %d", code_item->valueint);
				sprintf(tunnel->info.resource.error_code, "%d", code_item->valueint);
				if (code_item->valueint == 200)
				{
					get_ret = ERROR_SELECT_NO_RESOURCE;
					cJSON* proxyIp_item = cJSON_GetObjectItem(response, "proxyIp");
					cJSON* proxyKey_item = cJSON_GetObjectItem(response, "pubKey");
					cJSON* subnet_item = cJSON_GetObjectItem(response, "subnet");
					cJSON* members_item = cJSON_GetObjectItem(response, "members");
					if (proxyIp_item)
					{
						//log_tool_log("Connecting to proxy(%s)", proxyIp_item->valuestring);
						strcpy(g_config.tunnel.info.resource.vpn_server_host, proxyIp_item->valuestring);
					}
					if (members_item)
					{
						int set_ret = set_members_conf(members_item, g_config.team_id, g_config.self_id, tunnel_id, tunnel);
						if (set_ret == 0)
						{
							get_ret = ERROR_OK;
						}
					}
					if (subnet_item)
					{
						char subnet_buf[100];
						sprintf(subnet_buf, "%s/28", subnet_item->valuestring);
						ctrl_reload_firewall(tunnel_id, subnet_buf);
					}
					if (proxyKey_item)
					{
						write_text((char*)"/tmp/rsa_key.pub", proxyKey_item->valuestring);
					}
				}
				else if(code_item->valueint == 902)
				{
					get_ret = ERROR_HEARTBEAT_RECONNECT;
				}
				else
				{
					get_ret = ERROR_SELECT_NO_RESOURCE;
				}
			}
			cJSON_Delete(response);
		}
		cJSON_Delete(req);
	}
	return get_ret;
}

#define LOCAL_VPN_CONFIG_FMT	("/etc/site/local_config_vpn%d.dump")
#define LOCAL_VPPN_CONFIG_FMT	("/etc/site/local_config_vppn%d.dump")

int vpn_tunnel_select_resource_from_local(struct vpn_tunnel_s *tunnel, int conf_type)
{
	int ret = ERROR_SELECT_NO_RESOURCE;
	char local_conf[200];
	if (conf_type == 0)
	{
		sprintf(local_conf, LOCAL_VPN_CONFIG_FMT, tunnel->tunnel_id);
	}
	else
	{
		sprintf(local_conf, LOCAL_VPPN_CONFIG_FMT, tunnel->tunnel_id);
	}
	char *text = read_text(local_conf);
	if (text)
	{
		cJSON *conf = cJSON_Parse(text);
		if (conf)
		{
			if (conf->type == cJSON_Object)
			{
				cJSON *host_item = cJSON_GetObjectItem(conf, "IP");
				cJSON *vpn_ip_item = cJSON_GetObjectItem(conf, "Subnet");
				if (host_item && vpn_ip_item)
				{
					strncpy(tunnel->info.resource.vpn_server_host, host_item->valuestring, sizeof(tunnel->info.resource.vpn_server_host));
					strncpy(tunnel->info.resource.vpn_ip, vpn_ip_item->valuestring, sizeof(tunnel->info.resource.vpn_ip));
					vpn_tunnel_set_resource_id(tunnel, vpn_ip_item->valuestring);
					ret = 0;
				}
			}
			cJSON_Delete(conf);
		}
		tunnel->info.resource.error = 1;
		free(text);
	}
	return ret;
}

void vpn_tunnel_put_resource_to_local(struct vpn_tunnel_s *tunnel, int conf_type)
{
	char local_conf[200];
	if (conf_type == 0)
	{
		sprintf(local_conf, LOCAL_VPN_CONFIG_FMT, tunnel->tunnel_id);
	}
	else
	{
		sprintf(local_conf, LOCAL_VPPN_CONFIG_FMT, tunnel->tunnel_id);
	}
	cJSON *conf = cJSON_CreateObject();
	cJSON_AddStringToObject(conf, "IP", tunnel->info.resource.vpn_server_host);
	cJSON_AddStringToObject(conf, "Subnet", tunnel->info.resource.vpn_ip);
	char *text = cJSON_Print(conf);
	write_text(local_conf, text);
	free(text);
	cJSON_Delete(conf);
	return;
}

#if 0
int vpn_tunnel_select_resource(struct vpn_tunnel_s *tunnel, char *user, char *cloud_host, int cloud_port, int cloud_cnt, int conf_type)
{
	int i;
	int cloud_ret;
	int ret = -1;
	for(i = 0; i < cloud_cnt; i++)
	{
		cloud_ret = vpn_tunnel_select_resource_from_cloud(tunnel, user, cloud_host, cloud_port, conf_type);
		if (cloud_ret != ERROR_CLOUD_UNREACHABLE)
		{
			break;
		}
	}
	if (cloud_ret == ERROR_OK)
	{
		ret = cloud_ret;
		vpn_tunnel_put_resource_to_local(tunnel, conf_type);
	}
	else if (cloud_ret == ERROR_CLOUD_UNREACHABLE)
	{
		ret = vpn_tunnel_select_resource_from_local(tunnel, conf_type);
	}
	else if (cloud_ret == ERROR_PACKAGE_FLOW)
	{
		ret = -1;
	}
	return ret;
}
#endif

struct vpn_config_s *dump_global_config()
{
	struct vpn_config_s *ret = (struct vpn_config_s*)malloc(sizeof(struct vpn_config_s));
	if (ret)
	{
		memcpy(ret, &g_config, sizeof(g_config));
	}
	return ret;
}

void vpn_tunnel_update_status(struct vpn_tunnel_s *tunnel, int status)
{
	if (status <= TUNNEL_DONE && status >= TUNNEL_DISABLE)
	{
		if (status == TUNNEL_DISABLE)
		{
			syslog_tool_log("vpn disabled");
		}
		else if(status == TUNNEL_CONNECT)
		{
			syslog_tool_log("vpn enabled");
		}
		tunnel->info.status = status;
	}
	return;
}

int vpn_tunnel_get_status(struct vpn_tunnel_s *tunnel)
{
	return tunnel->info.status;
}


void vpn_tunnel_add_connect_failtime(struct vpn_tunnel_s *tunnel)
{
	tunnel->info.connect_fail_time++;
}

void vpn_tunnel_reset_connect_failtime(struct vpn_tunnel_s *tunnel)
{
	tunnel->info.connect_fail_time = 0;
}

int vpn_tunnel_get_connect_failtime(struct vpn_tunnel_s *tunnel)
{
	return tunnel->info.connect_fail_time;
}

void vpn_tunnel_get_netmask(struct vpn_tunnel_s *tunnel, char *buf)
{
	sprintf(buf, "255.255.255.0");
}

void get_tunnel_conf_dir_name(struct vpn_tunnel_s* tunnel, char *buf, int conf_type)
{
	if (conf_type == 0)
	{
		sprintf(buf, "/etc/tinc/vpn%d", tunnel->tunnel_id);
	}
	else
	{
		sprintf(buf, "/etc/tinc/site%d", tunnel->tunnel_id);
	}
	return;
}

void get_tunnel_conf_hosts_dir_name(struct vpn_tunnel_s* tunnel, char *buf, int conf_type)
{
	if (conf_type == 0)
	{
		sprintf(buf, "/etc/tinc/vpn%d/hosts", tunnel->tunnel_id);
	}
	else
	{
		sprintf(buf, "/etc/tinc/site%d/hosts", tunnel->tunnel_id);
	}
	return;
}

void set_tinc_conf_file(struct vpn_tunnel_s *tunnel, int conf_type, int need_proxy)
{
	char *tinc_conf_format;
	char name_buf[200];
	char interface_buf[200];
	char connectto_buf[200];
	char content[400];
	char file_buf[200];
	char dir_buf[200];

	if (conf_type == 0)
	{
		tinc_conf_format = (char*)"Name = %s\n"
		"Interface = %s\n"
		"Device = %s\n"
		"ConnectTo = %s\n"
		"PingInterval = 30\n"
		"PingTimeout = 10\n";
		//get Interface
		sprintf(interface_buf, "tun%d", tunnel->tunnel_id);
	}
	else
	{
		tinc_conf_format = (char*)"Name = %s\n"
		"Interface = %s\n"
		"Device = %s\n"
		"DeviceType = tap\n"
		"Mode = switch\n"
		"ConnectTo = %s\n"
		"PingInterval = 30\n"
		"PingTimeout = 10\n";
		//get Interface
		sprintf(interface_buf, "site%d", tunnel->tunnel_id);
	}

	//get Name
	vpn_tunnel_get_name_form_resource_id(tunnel, name_buf);

	//get ConnectTo
	sprintf(connectto_buf, "vpnserver");
	sprintf(content, tinc_conf_format, name_buf, interface_buf, tunnel->tunnel_dev, connectto_buf);

	get_tunnel_conf_dir_name(tunnel, dir_buf, conf_type);
	sprintf(file_buf, "%s/tinc.conf", dir_buf);

	write_text(file_buf, content);
	if (need_proxy != 0)
	{
		char proxy_config[100];
		sprintf(proxy_config, "Proxy = httptunnel 127.0.0.1 %d\n", HTTP_TUNNEL_TINC_CLIENT_PORT);
		append_line(file_buf, proxy_config);
	}

	if ((tunnel->tunnel_relay_name[0] != '\0') && (tunnel->tunnel_relay_limit >= 0))
	{
		char limit_conf[100];
		sprintf(limit_conf, "RelayLimitName = %s\nRelayLimitSpeed = %d\n", tunnel->tunnel_relay_name, tunnel->tunnel_relay_limit);
		append_line(file_buf, limit_conf);
	}
	return;
}

void set_tinc_up_file(struct vpn_tunnel_s *tunnel, int conf_type, int need_proxy)
{
	char tinc_up_name[400];
	char dir_buf[200];
	char *tinc_up_format;
	char ip_buf[200];
	char interface_buf[200];
	char tinc_up_content[400];
	int netmask_num = 32;
	char netmask_buf[100];
	net_tool_num_to_netmask(netmask_num, netmask_buf);

	if (conf_type == 0)
	{
		tinc_up_format = (char*)
				"#!/bin/sh\n"
				"ifconfig %s %s netmask %s\n"
				"obfsproxy --daemonize --daemonize_with_pid=/var/run/obfsproxy%d.pid obfs2 --dest=%s:80 client 127.0.0.1:%d\n"
				"tinctop --config=/etc/tinc/site%d --pidfile=/var/run/site%d.pid";
			//"/usr/sbin/obfsproxy --daemonize --daemonize_with_pid=/var/run/obfsproxy%d.pid obfs2 --dest=%s:80 client 127.0.0.1:%d\n";
		sprintf(interface_buf, "tun%d", tunnel->tunnel_id);
	}
	else
	{
		tinc_up_format = (char*)
			"#!/bin/sh\n"
			"ifconfig %s %s netmask %s\n"
			"route add -net "VPN_SERVER_VIP" netmask 255.255.255.255 dev site%d\n"
			//"tinctop --config=/etc/tinc/site%d --pidfile=/var/run/site%d.pid\n"
			;
			//"/usr/sbin/obfsproxy --daemonize --daemonize_with_pid=/var/run/obfsproxy%d.pid obfs2 --dest=%s:80 client 127.0.0.1:%d\n";
		sprintf(interface_buf, "site%d", tunnel->tunnel_id);
	}
	get_tunnel_conf_dir_name(tunnel, dir_buf, conf_type);
	sprintf(tinc_up_name, "%s/tinc-up", dir_buf);
	sprintf(ip_buf, "%s", tunnel->info.resource.vpn_ip);
	if (conf_type == 0)
	{
		sprintf(tinc_up_content, tinc_up_format, interface_buf, ip_buf, netmask_buf, tunnel->tunnel_id, tunnel->info.resource.vpn_server_host, tunnel->tunnel_id + VPN_PORT_SERVER_BASE,
				tunnel->tunnel_id, tunnel->tunnel_id);
	}
	else
	{
		sprintf(tinc_up_content, tinc_up_format, interface_buf, ip_buf, netmask_buf, tunnel->tunnel_id);
		//sprintf(tinc_up_content, tinc_up_format, interface_buf, ip_buf, netmask_buf, tunnel->tunnel_id, tunnel->tunnel_id, tunnel->tunnel_id);
	}
	write_shell(tinc_up_name, tinc_up_content);
	if (need_proxy != 0)
	{
		char htc_cmd_buf[200];
		char uuid_buf[100];
		system_config_get((char*)"vppn_uuid", uuid_buf);
		sprintf(htc_cmd_buf, "obfsproxy_tinc --daemon http --dest=%s:%d client 127.0.0.1:%d\n", tunnel->info.resource.vpn_server_host, HTTP_TUNNEL_TINC_SERVER_PORT, HTTP_TUNNEL_TINC_CLIENT_PORT);
		append_line(tinc_up_name, htc_cmd_buf);
	}
	return;
}

void set_tinc_down_file(struct vpn_tunnel_s *tunnel, int conf_type, int need_proxy)
{
	char dir_buf[200];
	char tinc_down_name[400];
	char tinc_down_content[200];
	get_tunnel_conf_dir_name(tunnel, dir_buf, conf_type);
	sprintf(tinc_down_name, "%s/tinc-down", dir_buf);
	if (need_proxy == 0)
	{
		sprintf(tinc_down_content, "#!/bin/sh\n");
	}
	else
	{
		sprintf(tinc_down_content, "#!/bin/sh\nkillall obfsproxy_tinc\n");
	}
	write_shell(tinc_down_name, tinc_down_content);
}

void set_tinc_hosts_file(struct vpn_tunnel_s *tunnel, int conf_type)
{
	char local_sub[24];
	char tinc_hosts_dir[200];
	char tinc_dir[200];
	char self_subnet_buf[200];
	char self_port_buf[200];
	char self_file[400];
	get_tunnel_conf_hosts_dir_name(tunnel, tinc_hosts_dir, conf_type);
	get_tunnel_conf_dir_name(tunnel, tinc_dir, conf_type);

	/* create self host file */
	char *self_format = (char*)"Subnet=%s/32\n"
		"Subnet=%s\n"
		"Port=%s\n"
#ifndef TINC_ED_KEY
		"PrivateKeyFile=/tmp/vppn_priv.pem\n";
#else
		"Ed25519PrivateKeyFile=/tmp/vppn_priv.pem\n";
#endif

	sprintf(self_subnet_buf, "%s", tunnel->info.resource.vpn_ip);
	if (conf_type == 0)
	{
		sprintf(self_port_buf, "%d", 3267);
		//sprintf(self_port_buf, "%d", tunnel->tunnel_id * 256 + VPN_PORT_LOCAL_BASE + vpn_tunnel_get_resource_id(tunnel));
	}
	else
	{
		sprintf(self_port_buf, "%d", 3277);
		//sprintf(self_port_buf, "%d", tunnel->tunnel_id * 256 + VPN_PORT_LOCAL_BASE + 256 * 5 + vpn_tunnel_get_resource_id(tunnel));
	}

	get_local_subnet(local_sub);
	char self_content[400];
	sprintf(self_content, self_format, self_subnet_buf, local_sub, self_port_buf);
	//sprintf(self_content, self_format, self_subnet_buf, self_port_buf, priv_key_file);
	char name_buf[100];
	vpn_tunnel_get_name_form_resource_id(tunnel, name_buf);
	sprintf(self_file, "%s/%s", tinc_hosts_dir, name_buf);
	write_text(self_file, self_content);

	/* create server host file */
	char *server_format = (char*)
		"Address=%s\n"
		"Subnet=0.0.0.0/32\n"
		"Port=%d\n"
		"Weight=100\n"
#ifndef TINC_ED_KEY
		"PublicKeyFile=/tmp/rsa_key.pub\n";
#else
		"Ed25519PublicKeyFile=/tmp/rsa_key.pub\n";
#endif

	char server_content[400];
	if (conf_type == 0)
	{
		//sprintf(server_content, server_format, tunnel->info.resource.vpn_server_host, tunnel->info.resource.vpn_server_port);
		sprintf(server_content, server_format, tunnel->info.resource.vpn_server_host, tunnel->tunnel_id + VPN_PORT_SERVER_BASE);
	}
	else
	{
		//sprintf(server_content, server_format, tunnel->info.resource.vpn_server_host, tunnel->info.resource.vpn_server_port);
		sprintf(server_content, server_format, tunnel->info.resource.vpn_server_host, tunnel->tunnel_id + VPN_PORT_SERVER_BASE + 10);
	}
	//sprintf(server_content, server_format, server_host_buf, server_port_buf, pub_key_file);

	char server_file[400];
	sprintf(server_file, "%s/vpnserver", tinc_hosts_dir);
	write_text(server_file, server_content);

	return;
}

void create_tinc_dir(struct vpn_tunnel_s *tunnel, int conf_type)
{
	char vpn_dir_buf[200];
	char vpn_hosts_dir_buf[200];
	get_tunnel_conf_dir_name(tunnel, vpn_dir_buf, conf_type);
	get_tunnel_conf_hosts_dir_name(tunnel, vpn_hosts_dir_buf, conf_type);
	file_tool_create_dir(vpn_dir_buf, 0755);
	file_tool_create_dir(vpn_hosts_dir_buf, 0755);
	return;
}

void append_tinc_hosts_file(char* host_dir, cJSON* peers)
{
	int cnt = cJSON_GetArraySize(peers);
	int i;
	for(i = 0; i < cnt; i++)
	{
		char name[100];
		char host_file[100];
		char content[200];
		cJSON* peer = cJSON_GetArrayItem(peers, i);
		cJSON* peer_vip_item = cJSON_GetObjectItem(peer, "peer_vip");
		cJSON* peer_wan_ip_item = cJSON_GetObjectItem(peer, "peer_wan_ip");
		cJSON* peer_pubkey_item = cJSON_GetObjectItem(peer, "peer_pubkey");
		cJSON* peer_status_item = cJSON_GetObjectItem(peer, "peer_status");
		if (peer_status_item
				&&
				peer_status_item->valueint == 1
				&&
				peer_vip_item
				&&
				peer_wan_ip_item
				&&
				peer_wan_ip_item->valuestring
				&&
				peer_wan_ip_item->valuestring[0]
				&&
				peer_pubkey_item)
		{
			get_name_from_vip(peer_vip_item->valuestring, name);
			sprintf(host_file, "%s/%s", host_dir, name);
			sprintf(content, "Address = %s\n"
					"Port = 3277\n"
					"Weight=8\n"
					"%s",
					peer_wan_ip_item->valuestring,
					peer_pubkey_item->valuestring
			);
			write_text((char*)host_file, content);
		}
	}
	return;
}

void append_tinc_conf_file(char* conf_file, cJSON* peers)
{
	int cnt = cJSON_GetArraySize(peers);
	int i;
	for(i = 0; i < cnt; i++)
	{
		char name[100];
		cJSON* peer = cJSON_GetArrayItem(peers, i);
		cJSON* peer_vip_item = cJSON_GetObjectItem(peer, "peer_vip");
		cJSON* peer_wan_ip_item = cJSON_GetObjectItem(peer, "peer_wan_ip");
		cJSON* peer_status_item = cJSON_GetObjectItem(peer, "peer_status");
		cJSON* peer_pubkey_item = cJSON_GetObjectItem(peer, "peer_pubkey");
		if (peer_status_item
				&&
				peer_status_item->valueint == 1
				&&
				peer_vip_item
				&&
				peer_wan_ip_item
				&&
				peer_wan_ip_item->valuestring
				&&
				peer_wan_ip_item->valuestring[0]
				&&
				peer_pubkey_item)
		{

			get_name_from_vip(peer_vip_item->valuestring, name);
			char append_buf[100];
			sprintf(append_buf, "ConnectTo = %s\n", name);
			append_line(conf_file, append_buf);
		}
	}
}

void update_tinc_confs(struct vpn_tunnel_s *tunnel, int conf_type)
{
	char tinc_hosts_dir[200];
	char tinc_dir[200];
	char tinc_conf_file[200];
	get_tunnel_conf_hosts_dir_name(tunnel, tinc_hosts_dir, conf_type);
	get_tunnel_conf_dir_name(tunnel, tinc_dir, conf_type);
	sprintf(tinc_conf_file, "%s/tinc.conf", tinc_dir);

	cJSON* peers = read_json_from_file((char*)"/etc/site/vppn0_peers.conf");
	if (peers)
	{
		append_tinc_hosts_file(tinc_hosts_dir, peers);
		append_tinc_conf_file(tinc_conf_file, peers);
		cJSON_Delete(peers);
	}
	return;
}

void setup_tinc_conf_files(struct vpn_tunnel_s *tunnel, int conf_type, int need_proxy)
{
	create_tinc_dir(tunnel, conf_type);
	set_tinc_conf_file(tunnel, conf_type, need_proxy);
	set_tinc_up_file(tunnel, conf_type, need_proxy);
	set_tinc_down_file(tunnel, conf_type, need_proxy);
	set_tinc_hosts_file(tunnel, conf_type);

	if (tunnel->tunnel_public == 0)
	{
		update_tinc_confs(tunnel, conf_type);
	}
	return;
}

void set_peervpn_conf(struct vpn_tunnel_s * tunnel, int conf_type)
{
	char conf_file[100];

	char server_content[400];
	char interface_content[400];
	char port_content[400];
	char ifconfig4_content[400];

	if (conf_type == 0)
	{
		sprintf(port_content, "port %d", tunnel->tunnel_id + VPN_PORT_LOCAL_BASE);
		sprintf(conf_file, "/etc/peervpn%d.conf", tunnel->tunnel_id);
		sprintf(interface_content, "interface tun%d", tunnel->tunnel_id);
		sprintf(server_content, "initpeers %s %d", tunnel->info.resource.vpn_server_host, tunnel->tunnel_id + VPN_PORT_SERVER_BASE);
	}
	else
	{
		sprintf(port_content, "port %d", tunnel->tunnel_id + VPN_PORT_LOCAL_BASE + 10);
		sprintf(conf_file, "/etc/peervppn%d.conf", tunnel->tunnel_id);
		sprintf(interface_content, "interface site%d", tunnel->tunnel_id);
		sprintf(server_content, "initpeers %s %d", tunnel->info.resource.vpn_server_host, tunnel->tunnel_id + VPN_PORT_SERVER_BASE + 10);
	}
	sprintf(ifconfig4_content, "ifconfig4 %s/24", tunnel->info.resource.vpn_ip);
	char write_buf[4096];
	sprintf(write_buf,
			"networkname ExampleNet\n"
			"psk mysecretpassword\n"
			"enabletunneling yes\n"
			"%s\n"
			"%s\n"
			"%s\n"
			"%s\n", server_content, interface_content, port_content, ifconfig4_content
			);
	write_text(conf_file, write_buf);
	return;
}

void setup_peervpn_conf_files(struct vpn_tunnel_s *tunnel, int conf_type)
{
	set_peervpn_conf(tunnel, conf_type);
}

void vpn_tunnel_add_conf(struct vpn_tunnel_s *tunnel, int conf_type, int need_proxy)
{
#ifdef PEERVPN_TYPE
	setup_peervpn_conf_files(tunnel, conf_type);
#else
	setup_tinc_conf_files(tunnel, conf_type, need_proxy);
#endif
	return;
}

void vpn_tunnel_del_conf(struct vpn_tunnel_s *tunnel, int conf_type)
{
	//remove conf
#ifdef PEERVPN_TYPE
	char conf_file[100];
	if (conf_type == 0)
	{
		sprintf(conf_file, "/etc/peervpn%d.conf", tunnel->tunnel_id);
	}
	else
	{
		sprintf(conf_file, "/etc/peervppn%d.conf", tunnel->tunnel_id);
	}
	remove(conf_file);
#else
	char dir_buf[200];
	if (conf_type == 0)
	{
		sprintf(dir_buf, "/etc/tinc/vpn%d", tunnel->tunnel_id);
	}
	else
	{
		sprintf(dir_buf, "/etc/tinc/site%d", tunnel->tunnel_id);
	}
	file_tool_remove_dir(dir_buf);
#endif

	return;
}

void vpn_tunnel_get_dnsmasq_file_by_id(int tunnel_id, char *buf)
{
	sprintf(buf, DNSMASQ_CONF_FMT, tunnel_id);
}

void vpn_tunnel_get_dnsmasq_file(struct vpn_tunnel_s *tunnel, char *buf)
{
	vpn_tunnel_get_dnsmasq_file_by_id(tunnel->tunnel_id, buf);
}

void vpn_tunnel_get_whitelist_file_by_id(int tunnel_id, char *buf)
{
	sprintf(buf, WHITELIST_CONF_FMT, tunnel_id);
}

void vpn_tunnel_get_whitelist_file(struct vpn_tunnel_s *tunnel, char *buf)
{
	vpn_tunnel_get_whitelist_file_by_id(tunnel->tunnel_id, buf);
}

void vpn_tunnel_reset_whitelist_conf(int tunnel_id)
{
	char dnsmasq_file[200];
	vpn_tunnel_get_dnsmasq_file_by_id(tunnel_id, dnsmasq_file);
	remove(dnsmasq_file);
	return;
}


void vpn_tunnel_load_whitelist_conf_by_id(int tunnel_id)
{
	char	whitelist_conf[100];
	char	dnsmasq_conf[100];
	sprintf(whitelist_conf, WHITELIST_CONF_FMT, tunnel_id);
	sprintf(dnsmasq_conf, DNSMASQ_CONF_FMT, tunnel_id);

	cJSON *whitelist = read_json_from_file(whitelist_conf);
	if (whitelist)
	{
		char line_buf[100];
		int array_count = cJSON_GetArraySize(whitelist);
		int i;
		for(i = 0; i < array_count; i++)
		{
			cJSON *item = cJSON_GetArrayItem(whitelist, i);
			cJSON *domain_item = cJSON_GetObjectItem(item, "uri");
			cJSON *gw_item = cJSON_GetObjectItem(item, "vproxy");
			if (domain_item && gw_item)
			{
				sprintf(line_buf, "server=/%s/%s#53\n", domain_item->valuestring, gw_item->valuestring);
				append_line(dnsmasq_conf, line_buf);
			}
		}
		cJSON_Delete(whitelist);
	}

	return;
}

void vpn_tunnel_unload_whitelist_conf_by_id(int tunnel_id)
{
	char dnsmasq_conf_file[300];
	vpn_tunnel_get_dnsmasq_file_by_id(tunnel_id, dnsmasq_conf_file);
	remove(dnsmasq_conf_file);
	return;
}

#if 0
void vpn_tunnel_unload_whitelist_by_id(int tunnel_id)
{
	char dnsmasq_conf_file[300];
	char whitelist_conf_file[300];
	char tunnel_gw[20];
	char tunnel_dev[20];
	vpn_tunnel_get_dnsmasq_file_by_id(tunnel_id, dnsmasq_conf_file);
	remove(dnsmasq_conf_file);
	return;
}
#endif

/* get whitelist form local config file */
void vpn_tunnel_add_whitelist(struct vpn_tunnel_s *tunnel)
{
	char whitelist_file[200];
	char dnsmasq_file[200];
	vpn_tunnel_get_dnsmasq_file(tunnel, dnsmasq_file);
	vpn_tunnel_get_whitelist_file(tunnel, whitelist_file);

	char *gw_buf = NULL;
	gw_buf = vpn_tunnel_get_gw(tunnel);
	if (gw_buf)
	{
		char *content = read_text(whitelist_file);
		if (content)
		{
			cJSON *root = cJSON_Parse(content);
			if (root && root->type == cJSON_Object)
			{
				cJSON *whitelist_item = cJSON_GetObjectItem(root, "whitelist");
				if (whitelist_item)
				{
					int array_count = cJSON_GetArraySize(whitelist_item);
					int i;
					for(i = 0; i < array_count; i++)
					{
						cJSON *item = cJSON_GetArrayItem(whitelist_item, i);
						if (!is_ip(item->valuestring))
						{
							char line_buf[200];
							sprintf(line_buf, "server=/%s/%s#53\n", item->valuestring, gw_buf);
							append_line(whitelist_file, line_buf);
						}
						else
						{
							char ip_buf[40];
							char netmask_buf[40];
							char dev_buf[40];
							sprintf(ip_buf, "%s", item->valuestring);
							sprintf(netmask_buf, "%s", "255.255.255.255");
							sprintf(dev_buf, "site%d", tunnel->tunnel_id);
							add_route_by_cmd(ip_buf, netmask_buf, dev_buf);
						}
					}
				}
				cJSON_Delete(root);
			}
			free(content);
		}
		free(gw_buf);
	}
	return;
}

void vpn_tunnel_del_whitelist(struct vpn_tunnel_s *tunnel)
{
	char whitelist_file[200];
	char dnsmasq_file[200];
	vpn_tunnel_get_dnsmasq_file(tunnel, dnsmasq_file);
	vpn_tunnel_get_whitelist_file(tunnel, whitelist_file);

	remove(dnsmasq_file);
}

void vpn_tunnel_start_tinc_by_id(int tunnel_id, int conf_type, struct vpn_tunnel_s *tunnel)
{
	char cmd_buf[300];
	memset(cmd_buf, 0 , sizeof(cmd_buf));
	//sprintf(cmd_buf, "/sbin/tincd -n vpn%d", tunnel_id);
	if (conf_type == 0)
	{
		if (!tunnel->log_on)
		{
			sprintf(cmd_buf, "tincd --pidfile=/var/run/vpn%d.pid -n vpn%d",tunnel_id, tunnel_id);
		}
		else
		{
			sprintf(cmd_buf, "tincd --pidfile=/var/run/vpn%d.pid -n vpn%d -d %d -s",tunnel_id, tunnel_id, tunnel->log_level);
		}
	}
	else
	{
		if (!tunnel->log_on)
		{
			sprintf(cmd_buf, "tincd --pidfile=/var/run/site%d.pid -n site%d",tunnel_id, tunnel_id);
		}
		else
		{
			sprintf(cmd_buf, "tincd --pidfile=/var/run/site%d.pid -n site%d -d %d -s",tunnel_id, tunnel_id, tunnel->log_level);
		}
	}
	system(cmd_buf);
	return;
}

void vpn_tunnel_start_peervpn_by_id(int tunnel_id, int conf_type)
{
	char cmd_buf[300];
	memset(cmd_buf, 0 , sizeof(cmd_buf));
	//sprintf(cmd_buf, "/sbin/tincd -n vpn%d", tunnel_id);
	if (conf_type == 0)
	{
		sprintf(cmd_buf, "peervpn /etc/peervpn%d.conf", tunnel_id);
	}
	else
	{
		sprintf(cmd_buf, "peervpn /etc/peervppn%d.conf", tunnel_id);
	}
	system(cmd_buf);
	return;
}

void vpn_tunnel_start_tinc(struct vpn_tunnel_s *tunnel, int conf_type)
{
	return vpn_tunnel_start_tinc_by_id(tunnel->tunnel_id, conf_type, tunnel);
}

void vpn_tunnel_start_peervpn(struct vpn_tunnel_s *tunnel, int conf_type)
{
	return vpn_tunnel_start_peervpn_by_id(tunnel->tunnel_id, conf_type);
}

int get_tinc_pid(int channel, int conf_type)
{
	int ret_pid = 0;
	char match_str[100];
	if (conf_type == 0)
	{
		sprintf(match_str, "--pidfile=/var/run/vpn%d.pid", channel);
	}
	else
	{
		sprintf(match_str, "--pidfile=/var/run/site%d.pid", channel);
	}
	ret_pid = process_tool_ps((char*)"tincd", match_str);
	return ret_pid;                
}

void vpn_tunnel_stop_tinc_by_id(int tunnel_id, int conf_type)
{
	char cmd_buf[300];
	int pid = get_tinc_pid(tunnel_id, conf_type);
	if (pid)
	{
		sprintf(cmd_buf, "kill %d", pid);
		system(cmd_buf);
	}
	return;
}

int get_peervpn_pid(int tunnel_id, int conf_type)
{
	char match_str[100];
	if (conf_type == 0)
	{
		sprintf(match_str, "/etc/peervpn%d", tunnel_id);
	}
	else
	{
		sprintf(match_str, "/etc/peervppn%d", tunnel_id);
	}
	int pid = process_tool_ps((char*)"peervpn", match_str);
	return pid;
}

void vpn_tunnel_stop_peervpn_by_id(int tunnel_id, int conf_type)
{
	char cmd_buf[300];
	int pid = get_peervpn_pid(tunnel_id, conf_type);
	if (pid)
	{
		sprintf(cmd_buf, "kill %d", pid);
		system(cmd_buf);
	}
	return;
}

void vpn_tunnel_stop_tinc(struct vpn_tunnel_s *tunnel, int conf_type)
{
	return vpn_tunnel_stop_tinc_by_id(tunnel->tunnel_id, conf_type);
}

void vpn_tunnel_stop_peervpn(struct vpn_tunnel_s *tunnel, int conf_type)
{
	return vpn_tunnel_stop_peervpn_by_id(tunnel->tunnel_id, conf_type);
}

void vpn_tunnel_reset_routes_by_id(int tunnel_id)
{
	char dev_buf[200];
	sprintf(dev_buf, "site%d", tunnel_id);
	net_tool_reset_routes(dev_buf);
	return;
}

void vpn_tunnel_load_whitelist_by_id(int tunnel_id)
{
	vpn_tunnel_reset_whitelist_conf(tunnel_id);
	vpn_tunnel_reset_routes_by_id(tunnel_id);
	vpn_tunnel_load_whitelist_conf_by_id(tunnel_id);
	return;
}

void vpn_tunnel_unload_whitelist_by_id(int tunnel_id)
{
	/* 1st. reset whitelist_conf */
	vpn_tunnel_reset_whitelist_conf(tunnel_id);
	vpn_tunnel_reset_routes_by_id(tunnel_id);
	vpn_tunnel_unload_whitelist_conf_by_id(tunnel_id);
	/* 4th. restart dnsmasq */
	return;
}

void vpn_tunnel_load_whitelist(struct vpn_tunnel_s *tunnel)
{
	vpn_tunnel_load_whitelist_by_id(tunnel->tunnel_id);
	return;
}

void vpn_tunnel_unload_whitelist(struct vpn_tunnel_s *tunnel)
{
	vpn_tunnel_unload_whitelist_by_id(tunnel->tunnel_id);
	return;
}

void vpn_tunnel_reset_routes(struct vpn_tunnel_s *tunnel)
{
	vpn_tunnel_reset_routes_by_id(tunnel->tunnel_id);
}

void vpn_tunnel_connect(struct vpn_tunnel_s *tunnel, int conf_type, int need_proxy)
{
	MY_DEBUG_INFO("add conf\n");
	vpn_tunnel_add_conf(tunnel, conf_type, need_proxy);
	MY_DEBUG_INFO("start tinc\n");
#ifdef PEERVPN_TYPE
	vpn_tunnel_start_peervpn(tunnel, conf_type);
#else
	vpn_tunnel_start_tinc(tunnel, conf_type);
#endif
	sleep(1);
	//vpn_tunnel_load_whitelist(tunnel);
	tunnel->info.connect_time++;
	return;
}

void vpn_tunnel_disconnect(struct vpn_tunnel_s *tunnel, int conf_type)
{
#ifdef PEERVPN_TYPE
	vpn_tunnel_stop_peervpn(tunnel, conf_type);
#else
	vpn_tunnel_stop_tinc(tunnel, conf_type);
#endif
	vpn_tunnel_del_conf(tunnel, conf_type);
	return;
}

/* return ping latency */
double vpn_tunnel_latency(struct vpn_tunnel_s *tunnel)
{
	double ping_time = 0.0;
	int tinc_pid = get_tinc_pid(tunnel->tunnel_id, g_config.tunnel_type);
	if (tinc_pid > 0)
	{
		//char *tun_gw_ip = vpn_tunnel_get_gw(tunnel);
		char *tun_gw_ip = strdup(VPN_SERVER_VIP);
		if (tun_gw_ip)
		{
			ping_time = net_tool_ping_host(tun_gw_ip, 5);
			tunnel->info.latency = ping_time;
			free(tun_gw_ip);
		}
	}
	return ping_time;
}

/*
 *  * return 0: normal sleep return
 *   * return -1: interrupted sleep
 *    * */
int tunnel_sleep_intr(int timeout, int need_reset)
{
	int ret = 0;
	int i;
	for(i = 0; i < timeout; i++)
	{
		sleep(1);
		if (refresh_flag == 1)
		{
			ret = -1;
			if (need_reset)
			{
				refresh_flag = 0;
			}
			break;
		}
	}
	return ret;
}

/*
 *  * return 0: no need reconnect
 *   * return 1: need reconnect
 *    * */
int tunnel_check_reconnect(int need_reset)
{
	int ret = 0;
	if (refresh_flag == 1)
	{
		ret = 1;
		if (need_reset)
		{
			refresh_flag = 0;
		}
	}
	return ret;
}

/*
 *  * wait for tunnel_on
 *   * */
void tunnel_sleep_waiton()
{
	while(1)
	{
		if (tunnel_on == 1)
		{
			break;
		}
		usleep(3000);
	}
	return;
}

void vpn_tunnel_exit(struct vpn_tunnel_s* tunnel, int conf_type)
{
	vpn_tunnel_disconnect(tunnel, conf_type);
	exit(0);
}
#if 0
//return 0 means ok, return 1 means not ok, need disable
static int check_heartbeat_retcode(int retcode)
{
	int ret = 0;
	if (retcode == 903 
			|| retcode == 904 
			|| retcode == 906 
			|| retcode == 908 
			)
	{
		ret = 1;
	}
	return ret;
}
#endif

//1:reachable
//0:unreachable
int vpn_tunnel_check_reachable(struct vpn_config_s* config)
{
	int ret = 0;
	int tinc_pid = process_tool_ps((char*)"tincd", (char*)"--pidfile=");
	if (tinc_pid > 0)
	{
#if 0
		ret = net_tool_tcp_port_reachable(config->tunnel.info.resource.vpn_server_host, 50069);
#else
		//tinctool_dump_traffic();
		cJSON* info = tinctool_info_node((char*)"/etc/tinc/site0", (char*)"/var/run/site0.pid", (char*)"vpnserver");
		if (info)
		{
			cJSON* reachale_item = cJSON_GetObjectItem(info, "reachable");
			ret = reachale_item->valueint;
			cJSON_Delete(info);
		}
#endif
	}
	return ret;
}

int vpn_main_loop(struct vpn_config_s *config)
{
	my_debug_init();
	HttpClient_init();
	log_tool_init("0", "vppnctrl");
	syslog_tool_init("0", "[VPN] vppnctrl: ");
	Timer ping_timer;
	Timer get_resource_timer;
	Timer alive_timer;
	//Timer status_timer;
	//create_peers_update_thread();
	/* wait 2 seconds before network up */
	//vpn_upload_key_once(g_config.self_id);
	//vpn_upload_key(g_config.self_id);
	sleep(2);
	timer_tool_init(&ping_timer);
	timer_tool_countdown(&ping_timer, 10);
	timer_tool_init(&get_resource_timer);
	timer_tool_countdown(&get_resource_timer, 1);
	timer_tool_init(&alive_timer);
	timer_tool_countdown(&alive_timer, 600);

	int need_proxy = 0;

	while(running)
	{
		int tunnel_stat;
		int sel_ret = 0;
		int load_ret;
		int need_reconnect;
		tunnel_stat = vpn_tunnel_get_status(&config->tunnel);
		if (timer_tool_is_expired(&alive_timer))
		{
			vpn_tunnel_alive_confirm(&config->tunnel, config->self_id, config->cloud_host, config->cloud_port, config->tunnel_type);
			timer_tool_countdown(&alive_timer, 600);
		}

		switch(tunnel_stat)
		{
			case TUNNEL_DISABLE:
				MY_DEBUG_INFO("Tunnel disable\n");
				system("echo 0 >/proc/simple_config/vpn_led");
				tunnel_sleep_intr(1, 1);
				load_ret = vpn_tunnel_reload_config(config, tunnel_id, config->tunnel_type);
				if (load_ret == 0)
				{
					tunnel_on = config->tunnel.tunnel_on;
					if (tunnel_on)
					{
						vpn_tunnel_update_status(&config->tunnel, TUNNEL_READY);
					}
				}
				break;
			case TUNNEL_READY:
				MY_DEBUG_INFO("Tunnel ready\n");
				//vpn_upload_key_once(g_config.self_id);
				//vpn_tunnel_gen_key((char*)"/tmp");
				//vpn_tunnel_upload_key(&config->tunnel, config->self_id, config->team_id, config->cloud_host, config->cloud_port, config->tunnel_type, config->tunnel.tunnel_id);
				vpn_tunnel_update_status(&config->tunnel, TUNNEL_GET_RESOURCE);
				usleep(3000);
				break;

			case TUNNEL_GET_RESOURCE:
				need_reconnect = tunnel_check_reconnect(0);
				//log_tool_log("Start getting resource");
				if (need_reconnect)
				{
					vpn_tunnel_update_status(&config->tunnel, TUNNEL_DISABLE);
				}
				else if (timer_tool_is_expired(&get_resource_timer))
				{
					MY_DEBUG_INFO("Tunnel get_resource\n");
					timer_tool_countdown(&get_resource_timer, 20);
	//#if (HAVE_LOCAL_VPN_CONFIG == 1)
	//				sel_ret = vpn_tunnel_select_resource(&config->tunnel, config->self_id, config->cloud_host, config->cloud_port, 1, config->tunnel_type);
	//#else
					sel_ret = vpn_tunnel_select_resource_from_cloud2(&config->tunnel, config->team_id, config->cloud_host, config->cloud_port, config->tunnel_type, config->tunnel.tunnel_id);
	//#endif
					/* if get_resource failed, then try again 30s again */
					if (sel_ret == ERROR_SELECT_NO_RESOURCE)
					{
						//log_tool_log("Get resource error: no resource for device");
						ctrl_disable_vpn(config->tunnel_type, config->tunnel.tunnel_id);
						vpn_tunnel_update_status(&config->tunnel, TUNNEL_DISABLE);
					}
					else if (sel_ret == ERROR_HEARTBEAT_RECONNECT)
					{
						//log_tool_log("Heartbeat error: need reconnect");
						//ctrl_disable_vpn(config->tunnel_type, config->tunnel.tunnel_id);
						vpn_tunnel_update_status(&config->tunnel, TUNNEL_DISABLE);
					}
					else if (sel_ret < 0)
					{
						//tunnel_sleep_intr(20, 0);
						//log_tool_log("Get resource error: conductor reachable?");
						vpn_tunnel_update_status(&config->tunnel, TUNNEL_DISABLE);
					}
					else
					{
						//log_tool_log("Get resource ok");
						vpn_tunnel_update_status(&config->tunnel, TUNNEL_CONNECT);
					}
				}
				usleep(3000);
				break;

			case TUNNEL_CONNECT:
				//MY_DEBUG_INFO("Tunnel connect\n");
				//syslog_tool_log("VPN enabled");
				system("echo 1 >/proc/simple_config/vpn_led");
				//log_tool_log("Connecting to proxy");
				vpn_tunnel_connect(&config->tunnel, config->tunnel_type, need_proxy);
				vpn_tunnel_update_status(&config->tunnel, TUNNEL_DONE);
				ctrl_load_public_vpath(config->cloud_host, config->cloud_port, config->tunnel_type, config->tunnel.tunnel_id);
				ctrl_reload_vpn(config->tunnel_type, config->tunnel.tunnel_id, config->team_id);
				//create_vpn_status_thread();
				usleep(3000);
				break;

			case TUNNEL_DONE:
				//TODO: check if tunnel connected
				need_reconnect = tunnel_check_reconnect(0);
				//MY_DEBUG_INFO("Tunnel need_reconnect = %d\n", need_reconnect);
				if (need_reconnect)
				{
					//log_tool_log("Need reconnect in Connecting/Connected to proxy");
					//before reconnect, need heartbeat
					vpn_tunnel_heartbeat(&config->tunnel, config->self_id, config->cloud_host, config->cloud_port, 1, 0);
					vpn_tunnel_disconnect(&config->tunnel, config->tunnel_type);
					vpn_tunnel_reset_connect_failtime(&config->tunnel);
					vpn_tunnel_update_status(&config->tunnel, TUNNEL_DISABLE);
					ctrl_disable_dnsmasq_conf(config->tunnel_type, config->tunnel.tunnel_id);
				}
				else if (3 < vpn_tunnel_get_connect_failtime(&config->tunnel))
				{
					vpn_tunnel_disconnect(&config->tunnel, config->tunnel_type);
					vpn_tunnel_reset_connect_failtime(&config->tunnel);
					vpn_tunnel_update_status(&config->tunnel, TUNNEL_READY);
					ctrl_disable_dnsmasq_conf(config->tunnel_type, config->tunnel.tunnel_id);
					if (s_enable_proxy)
					{
						//reverse the need_proxy
						if (need_proxy == 0)
						{
							need_proxy = 1;
						}
						else
						{
							need_proxy = 0;
						}
					}
				}
				else
				{
					if (timer_tool_is_expired(&ping_timer))
					{
						MY_DEBUG_INFO("Tunnel heartbeat\n");
						int pid = process_tool_ps((char*)"vpnperf", (char*)"-i site0");
						if (pid <= 0)
						{
							system("/etc/init.d/vpnperf.init restart");
						}
						char v_dev[100];
						sprintf(v_dev, "site%d", config->tunnel.tunnel_id);
						timer_tool_init(&ping_timer);
						timer_tool_countdown(&ping_timer, 60);
						add_route_by_cmd((char*)VPN_SERVER_VIP, (char*)"255.255.255.255", v_dev);
						ctrl_reload_route(config->tunnel_type, config->tunnel.tunnel_id);
						//double ping_status = vpn_tunnel_latency(&config->tunnel);
						int server_reachable = vpn_tunnel_check_reachable(config);
						MY_DEBUG_INFO("Tunnel reachable = %d\n", server_reachable);
						int heart_beat_ret = vpn_tunnel_heartbeat(&config->tunnel, config->self_id, config->cloud_host, config->cloud_port, server_reachable, 1);
						/* need realloc resource */
						if (server_reachable == 0)
						{
							log_tool_log(1,3,"Connectivity to Proxy: unreachable");
#if 0
							if (check_heartbeat_retcode(config->tunnel.last_heartbeat_code))
							{
								ctrl_disable_vpn(config->tunnel_type, config->tunnel.tunnel_id);
							}
#endif
							vpn_tunnel_disconnect(&config->tunnel, config->tunnel_type);
							vpn_tunnel_reset_connect_failtime(&config->tunnel);
							vpn_tunnel_update_status(&config->tunnel, TUNNEL_READY);
							ctrl_disable_dnsmasq_conf(config->tunnel_type, config->tunnel.tunnel_id);
						}
#if 0
						else if(ping_status < 0.01f)
						{
							//Can't ping proxy's virtual ip
							vpn_tunnel_add_connect_failtime(&config->tunnel);
						}
#endif
						/* Can't connect to cloud */
						else if (heart_beat_ret < 0)
						{
							log_tool_log(1,3,"Connectivity to Proxy: reachable but not ok");
							//log_tool_log("Proxy is reachable but heartbeat ret not 200");
							vpn_tunnel_add_connect_failtime(&config->tunnel);
						}
						/* no need realloc resource */
						else
						{
							log_tool_log(1,5,"Connectivity to Proxy: reachable and ok");
							vpn_tunnel_reset_connect_failtime(&config->tunnel);
						}
					}
				}
				break;
			default:
				break;
		}
		usleep(50000);
	}

	remove_ctrl_pid_file(tunnel_id, config->tunnel_type);
	ctrl_server_exit();
	ctrl_disable_dnsmasq_conf(config->tunnel_type, config->tunnel.tunnel_id);
	vpn_tunnel_exit(&config->tunnel, config->tunnel_type);
	log_tool_exit();
	syslog_tool_exit();
	HttpClient_exit();
	my_debug_exit();
	return 0;
}

#define MY_SIG_STOP	(35)	/* 35 = SIGRTMIN */
#define MY_SIG_RELOAD (36)
#define MY_SIG_START (37)
#define MY_SIG_KILL (38)
#define MY_SIG_BIRD (39)


void sig_handler(int sig)
{
	MY_DEBUG_ERR("Got a signal %d\n", sig);
	if (sig == MY_SIG_STOP)
	{
		refresh_flag = 1;
	}
	else if (sig == MY_SIG_RELOAD)
	{
		vpn_tunnel_load_whitelist_by_id(tunnel_id);
	}
	else if (sig == MY_SIG_START)
	{
		refresh_flag = 1;
	}
	else if (sig == MY_SIG_KILL)
	{
		running = 0;
	}
	return;
}

void run_no_debug_init()
{
	close(1);
	int fd = open("/dev/null", O_RDWR);
	if (fd > 0)
	{
		dup2(fd, 1);
	}
}

void run_deamon(int conf_type)
{
	pid_t pid; 
	pid = fork();
	if (pid < 0) 
	{    
		MY_DEBUG_INFO("fork error\n");
	}    
	else if(pid > 0) 
	{ 
		set_ctrl_pid(tunnel_id, pid, conf_type);
		exit(0);
	} 
	setsid();
}
#if 0
void *vpn_tunnel_firewall_monitor_thread(void *arg)
{
	pthread_detach(pthread_self());
	int tunnel_id = *(int *)arg;
	free(arg);
	while(1)
	{
		char tun_buf[10];
		sprintf(tun_buf, "site%d", tunnel_id);
		int found;

		/* add rule in nat POSTROUTING */
		found = iptables_find_rule("nat", "POSTROUTING", NULL, tun_buf, NULL, NULL, "MASQUERADE");
		if (!found)
		{
			char rule_str[200];
			sprintf(rule_str, "-o %s -j MASQUERADE", tun_buf);
			iptables_insert_rule("nat", "POSTROUTING", rule_str, 0);
		}

		/* add rule in filter FORWARD */
		found = iptables_find_rule("filter", "FORWARD", "br0", tun_buf, NULL, NULL, "ACCEPT");
		if (!found)
		{
			char rule_str[200];
			sprintf(rule_str, "-i br0 -o %s -j ACCEPT", tun_buf);
			iptables_insert_rule("filter", "FORWARD", rule_str, 0);
		}

		/* add rule in filter FORWARD */
		found = iptables_find_rule("filter", "FORWARD", tun_buf, "br0", NULL, NULL, "ACCEPT");
		if (!found)
		{
			char rule_str[200];
			sprintf(rule_str, "-i %s -o br0 -j ACCEPT", tun_buf);
			iptables_insert_rule("filter", "FORWARD", rule_str, 0);
		}

		/* add rule in filter INPUT */
		found = iptables_find_rule("filter", "INPUT", tun_buf, NULL, NULL, NULL, "ACCEPT");
		if (!found)
		{
			char rule_str[200];
			sprintf(rule_str, "-i %s -j ACCEPT", tun_buf);
			iptables_insert_rule("filter", "INPUT", rule_str, 0);
		}

		/* add rule in filter OUTPUT */
		found = iptables_find_rule("filter", "OUTPUT", NULL, tun_buf, NULL, NULL, "ACCEPT");
		if (!found)
		{
			char rule_str[200];
			sprintf(rule_str, "-o %s -j ACCEPT", tun_buf);
			iptables_insert_rule("filter", "OUTPUT", rule_str, 0);
		}
		sleep(60);
	}
	free(arg);
	return NULL;
}
#endif

void vpn_start_tunnel(struct vpn_config_s* config, int tunnel_id)
{
	run_deamon(config->tunnel_type);
	signal(MY_SIG_STOP, sig_handler);
	signal(MY_SIG_RELOAD, sig_handler);
	signal(MY_SIG_START, sig_handler);
	signal(MY_SIG_KILL, sig_handler);
	signal(SIGPIPE, SIG_IGN);
	//create_attach_device_thread();
#if 1
#define CTRL_SERVER_PORT_BASE (4100)
	/* vppn tunnel port starts from 4100 to 4104 */
	u_short ctrl_port;
	if (config->tunnel_type == 0)
	{
		ctrl_port = tunnel_id + CTRL_SERVER_PORT_BASE + 100;
	}
	/* vpn tunnel port starts from 4200 to 4204 */
	else
	{
		ctrl_port = tunnel_id + CTRL_SERVER_PORT_BASE;
	}
	if (ctrl_server_init((char*)"127.0.0.1", ctrl_port) < 0)
	//if (ctrl_server_init(NULL, ctrl_port) < 0)
	{
		MY_DEBUG_INFO("create ctrl server error, Exit\n");
		remove_ctrl_pid_file(tunnel_id, config->tunnel_type);
		exit(-1);
	}
#endif
	umask(0022);
#if 0
	if (!config->debug)
	{
		run_no_debug_init();
	}
#endif
#if (BOARD_NAME == 7800)
#else
	if (tunnel_id == 0)
	{
		system("/www/cgi-bin/firewall.sh restart");
	}
#endif
	vpn_main_loop(config);
	return;
}

void vpn_start_tunnel_by_signal(int tunnel_id, int conf_type)
{
	int pid = get_ctrl_pid(tunnel_id, conf_type);
	//MY_DEBUG_INFO("pid = %d\n", pid);
	if (pid)
	{
		kill(pid, MY_SIG_START);
	}
	return;
}

void vpn_stop_tunnel_by_signal(int tunnel_id, int conf_type)
{
	int pid = get_ctrl_pid(tunnel_id, conf_type);
	//MY_DEBUG_INFO("pid = %d\n", pid);
	if (pid)
	{
		kill(pid, MY_SIG_STOP);
	}
	return;
}

void vpn_kill_tunnel_by_signal(int tunnel_id, int conf_type)
{
	int pid = get_ctrl_pid(tunnel_id, conf_type);
	//MY_DEBUG_INFO("pid = %d\n", pid);
	if (pid)
	{
		kill(pid, MY_SIG_KILL);
	}
	return;
}

void vpn_tunnel_load_whitelist_by_signal(int tunnel_id, int conf_type)
{
	int pid = get_ctrl_pid(tunnel_id, conf_type);
	if (pid)
	{
		kill(pid, MY_SIG_RELOAD);
	}
	return;
}

pid_t get_dnsmasq_pid()
{
	pid_t ret_pid = 0;
	FILE *fp = popen("/bin/ps | /bin/grep dnsmasq", "r");
	if (fp)
	{
		char buf[1000];
		char match_str[100];
		sprintf(match_str, "/usr/sbin/dnsmasq");
		while(fgets(buf, sizeof(buf), fp))
		{
			if(strstr(buf, match_str))
			{
				ret_pid = atoi(buf);
				break;
			}
		}
		pclose(fp);
	}
	return ret_pid;
}
#if 0
#define DNS_DUMP_FILE ("/tmp/dns.dump")

void start_dns_report_loop()
{
	run_deamon(g_config.tunnel_type);
	umask(0022);
	//run_no_debug_init();
	while(1)
	{
		pid_t dns_pid = get_dnsmasq_pid();
		if (dns_pid > 0)
		{
			kill(dns_pid, 38);
			sleep(2);
			char *text = read_text(DNS_DUMP_FILE);
			if (text)
			{
				cJSON *array = cJSON_Parse(text);
				if (array)
				{
					cJSON *obj = cJSON_CreateObject();
					cJSON_AddStringToObject(obj, "MACAddr", g_config.self_id);
					cJSON_AddItemToObject(obj, "DNSRecords", array);
					//dump_JSON(obj);
					//cJSON *res = vpn_cloud_tool(obj, g_config.cloud_host, g_config.cloud_port, "/InternetRecords");
					cJSON *res = vpn_cloud_tool_gzip(obj, g_config.cloud_host, g_config.cloud_port, "/InternetRecords");
					//MY_DEBUG_INFO("cloud_host:%s\n", g_config.cloud_host);
					//MY_DEBUG_INFO("cloud_port:%d\n", g_config.cloud_port);
					if (res)
					{
						dump_JSON(res);
						cJSON_Delete(res);
					}
					cJSON_Delete(obj);
				}
				free(text);
			}
			remove(DNS_DUMP_FILE);
		}
		sleep(600);
	}
}
#endif

int client_debug_level = 0; //No dubug

void vpn_client_set_debug_level(int tunnel_id, int level)
{
	cJSON* req = cJSON_CreateObject();
	if (req)
	{
		int port = tunnel_id + 4100;
		cJSON_AddNumberToObject(req, "action", 100);
		cJSON_AddNumberToObject(req, "channel", tunnel_id);
		cJSON_AddNumberToObject(req, "level", client_debug_level);
		cJSON* ret = net_tool_tcp_json_client_with_size((char*)"127.0.0.1", port, req, (char*)"json", 4);
		if (ret)
		{
			cJSON_Delete(ret);
		}
		cJSON_Delete(req);
	}
}

/**
 * @brief  :
 *
 * @Param  :argc
 * @Param  :argv
 *
 * @Returns  :
 */
int main(int argc, char **argv)
{
	int ret = -1;
	int action = -1;
//	char mask_buf[100] = "";
//	net_tool_num_to_netmask(28, mask_buf);
//	printf("mask_buf = %s\n", mask_buf);
	ret = vpn_config_load(&g_config, argc, argv, &action, &tunnel_id);
	if (ret >= 0)
	{
		switch(action)
		{
			case ACTION_RUN:
				if (get_ctrl_pid(tunnel_id, g_config.tunnel_type) == 0)
				{
					vpn_start_tunnel(&g_config, tunnel_id);
				}
				break;
			case ACTION_KILL:
				vpn_kill_tunnel_by_signal(tunnel_id, g_config.tunnel_type);
				break;
			case ACTION_RELOAD:
				vpn_tunnel_load_whitelist_by_signal(tunnel_id, g_config.tunnel_type);
				break;
			case ACTION_SET_DEBUG_LEVEL:
				vpn_client_set_debug_level(tunnel_id, client_debug_level);
				break;
			default:
				break;
		}
	}
	return 0;
}
