#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <iostream>
#include <string>
#include "my-device.h"
#include "process_tool.h"
#include "net_tool.h"
#include "file_tool.h"
#include "str_tool.h"
#include "system-config.h"
#include "cJSON.h"
#include "HttpClient.h"
#include "vpn_cloud.h"

using namespace std;

void vpn_tunnel_gen_key(char* dir)
{
	char* file = read_text((char*)"/tmp/vppn_pub.pem");
	if (file)
	{
		free(file);
	}
	else
	{
		char cmd_buf[100];
#ifndef TINC_ED_KEY
		sprintf(cmd_buf, "vpn_genkey.sh rsa %s", dir);
#else
		sprintf(cmd_buf, "vpn_genkey.sh ed25519 %s", dir);
#endif
		system(cmd_buf);
	}
	return;
}

int vpn_upload_key_once(char* user)
{
	cJSON *req = NULL;
	int ret = ERROR_CLOUD_UNREACHABLE;
	//int ret = ERROR_CLOUD_UNREACHABLE;
	//memset(&tunnel->info.resource , 0, sizeof(tunnel->info.resource));
	//MY_DEBUG_INFO("cloud_host:%s, cloud_port:%d\n", cloud_host, cloud_port);
	req = cJSON_CreateObject();


	if (req)
	{
		cJSON_AddStringToObject(req, "mac", user);
		char* key = read_text((char*)"/tmp/vppn_pub.pem");
		if (key)
		{
			cJSON_AddStringToObject(req, "pubKey", key);
			free(key);
		}
		else
		{
			cJSON_AddStringToObject(req, "pubKey", "");
		}

		cJSON* baseinfo_item = get_my_device_baseinfo();
		if (!baseinfo_item)
		{
			baseinfo_item = cJSON_CreateObject();
		}

		cJSON_AddItemToObject(req, "info", baseinfo_item);

		cJSON_Dump(req);
		cJSON* response = vpn_cloud_tool2((char*)"/vppn/api/v1/client/keyreport", req);
		if (response)
		{
			cJSON* code_item = cJSON_GetObjectItem(response, "code");
			if (code_item && (code_item->valueint == 200))
			{
				ret = ERROR_OK;
			}
			cJSON_Delete(response);
		}
		cJSON_Delete(req);
	}
	return ret;
}


static cJSON* get_nodes_available(cJSON* nodes)
{
	cJSON* ret = cJSON_CreateArray();
	int cnt = cJSON_GetArraySize(nodes);
	int i;
	for(i = 0; i < cnt; i++)
	{
		cJSON* node = cJSON_GetArrayItem(nodes, i);
		cJSON* clients_item = cJSON_GetObjectItem(node, "clients");
		cJSON* node_status_item = cJSON_GetObjectItem(node, "node_status");
		cJSON* max_fds_item = cJSON_GetObjectItem(node, "max_fds");
		cJSON* name_item = cJSON_GetObjectItem(node, "name");
		if (clients_item && max_fds_item && node_status_item && name_item)
		{
			if (strcmp(node_status_item->valuestring, "Running") == 0)
			{
				if (clients_item->valueint < max_fds_item->valueint)
				{
					if (strcmp(name_item->valuestring + 4, "220.168.30.11") != 0)
					{
						cJSON* new_item = cJSON_CreateObject();
						cJSON_AddStringToObject(new_item, "ip", name_item->valuestring + 4);
						cJSON_AddItemToArray(ret, new_item);
					}
				}
			}
		}
	}
	return ret;
}

static cJSON* get_best_node(cJSON* nodes)
{
	cJSON* best_node = NULL;
	int min_latency = 0;
	net_tool_ping_hosts2(nodes, (char*)"ip", (char*)"latency", 2);
	cJSON_Dump(nodes);
	int cnt = cJSON_GetArraySize(nodes);
	int i;
	for(i = 0; i < cnt; i++)
	{
		cJSON* node = cJSON_GetArrayItem(nodes, i);
		cJSON* latency_item = cJSON_GetObjectItem(node, "latency");
		if (latency_item->valueint > 0)
		{
			if (min_latency == 0 || latency_item->valueint < min_latency)
			{
				min_latency = latency_item->valueint;
				best_node = node;
			}
		}
	}
	return best_node;
}

int get_mqtt_manager_server_from_cloud_old(char* ret_server, char* host, int port)
{
	int ret = -1;
	cJSON* res = net_tool_http_json_client2(0, host, port, (char*)"/api/v2/monitoring/nodes", NULL, (char*)"Authorization: Basic YWRtaW46cHVibGlj\r\n");
	//res = cJSON_Parse(body.c_str());
	if (res)
	{
		cJSON_Dump(res);
		cJSON* code_item = cJSON_GetObjectItem(res, "code");
		if (code_item && (code_item->valueint == 0 || code_item->valueint == 200))
		{
			cJSON* nodes = cJSON_GetObjectItem(res, "result");
			cJSON* available_nodes = get_nodes_available(nodes);
			if (available_nodes)
			{
				cJSON* best_node = get_best_node(available_nodes);
				if (best_node)
				{
					cJSON* ip_item = cJSON_GetObjectItem(best_node, "ip");
					strcpy(ret_server, ip_item->valuestring);
					set_mqtt_manager_server_to_local(ip_item->valuestring);
					//set_http_manager_server_to_local(ip_item->valuestring, (char*)"443");
					ret = 0;
				}
				cJSON_Delete(available_nodes);
			}
		}
		cJSON_Delete(res);
	}
	return ret;
}

int get_mqtt_manager_server_from_cloud(char* ret_server, char* host, int port, int* http_saved)
{
	int ret = -1;
	string url = "https://";
	url += host;
	//url += ":443";
	char port_buf[100];
	sprintf(port_buf, ":%d", port);
	url += port_buf;
	url += "/vppn/api/v1/client/mqttnodes";
	string header = "Apikey: 0cde13b523sf9aa5a403dc9f5661344b91d77609f70952eb488f31641";
	HttpRequest http_req(url);
	http_req.AddHeader(header);
	cJSON* res = NULL;
	if (http_saved)
	{
		*http_saved = 0;
	}
	HttpResponse* http_resp = http_req.Get(15, (char*)"/etc/site/insight_ca.crt");
	if (http_resp)
	{
	//cJSON* res = net_tool_http_json_client2(0, host, port, (char*)"/api/v2/monitoring/nodes", NULL, (char*)"Authorization: Basic YWRtaW46cHVibGlj\r\n");
		string body = http_resp->GetBody();
		//cout << "--------- body --------" << body << endl;
		res = cJSON_Parse(body.c_str());
		if (res)
		{
			//cJSON_Dump(res);
			cJSON* code_item = cJSON_GetObjectItem(res, "code");
			if (code_item && (code_item->valueint == 0 || code_item->valueint == 200))
			{
				cJSON* nodes = cJSON_GetObjectItem(res, "result");
				cJSON* available_nodes = get_nodes_available(nodes);
				if (available_nodes)
				{
					cJSON* best_node = get_best_node(available_nodes);
					if (best_node)
					{
						cJSON* ip_item = cJSON_GetObjectItem(best_node, "ip");
						strcpy(ret_server, ip_item->valuestring);
						set_mqtt_manager_server_to_local(ip_item->valuestring);
						//set_http_manager_server_to_local(ip_item->valuestring, (char*)"443");
						ret = 0;
					}
					cJSON_Delete(available_nodes);
				}
				cJSON* httphost_item = cJSON_GetObjectItem(res, "leaderIP");
				cJSON* httpport_item = cJSON_GetObjectItem(res, "port");
				if (httphost_item && httpport_item)
				{
					if (http_saved)
					{
						*http_saved = 1;
					}
					set_http_manager_server_to_local(httphost_item->valuestring, httpport_item->valuestring);
				}
			}
			cJSON_Delete(res);
		}
		delete(http_resp);
	}
	else
	{
		cout << "http resp error" << endl;
	}
	return ret;
}

void set_mqtt_manager_server_to_local(char *server)
{
	cJSON* conf = cJSON_CreateObject();
	cJSON_AddStringToObject(conf, "host", server);
	write_json_to_file((char*)"/etc/site/mqtt-manager", conf);
	cJSON_Delete(conf);
	return;
}

int get_mqtt_manager_server_from_local(char *server)
{
	int ret = -1;
	cJSON* conf = read_json_from_file((char*)"/etc/site/mqtt-manager");
	if (conf)
	{
		cJSON* host_item = cJSON_GetObjectItem(conf, "host");
		if (host_item)
		{
			strcpy(server, host_item->valuestring);
			ret = 0;
		}
		cJSON_Delete(conf);
	}
	return ret;
}

static int check_ip(char *host)
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

void set_http_manager_server_to_local(char* server, char* port)
{
	/* /etc/site/manager file will be deleted in future */
	if (server && server[0]
	     && port && port[0])
	{
		cJSON* manager = cJSON_CreateObject();
		char* server_name = (char*)calloc(1, 100);
		if (check_ip(server))
		{
			strcpy(server_name, server);
			str_tool_replaceAll(server_name, '.', '-');
			strcat(server_name, ".insight.netgear.com");
		}
		else
		{
			strcpy(server_name, server);
		}
		cJSON_AddStringToObject(manager, "cloud_host", server_name);
		cJSON_AddNumberToObject(manager, "cloud_port", atoi(port));
		write_json_to_file((char*)"/etc/site/manager", manager);
		cJSON_Delete(manager);
		system_config_set("vppn_cloudhost", server_name);
		system_config_set("vppn_cloudport", port);
		system_config_commit();
		free(server_name);
	}
	return;
}

void get_my_id(char* id)
{
#if 1
	char *ret_buf = process_tool_run_cmd((char*)"artmtd -r sn | head -n 1 | awk -F: '{print $2}'");
	if (ret_buf)
	{
		str_tool_replaceFirst(ret_buf, '\n', 0);
		strcpy(id, ret_buf);
		free(ret_buf);
	}
	else
	{
		strcpy(id, "PC123456");
	}
#else
	char ret_buf[100] = "";
	net_tool_get_if_hwaddr((char*)"br0", ret_buf);
	strcpy(id, ret_buf);
#endif
}

void get_my_teamid(char* teamid)
{
	char buf[100];
	buf[0] = 0;
	system_config_get("vppn_teamid", buf);
	if (buf[0])
	{
		strcpy(teamid, buf);
	}
	else
	{
		cJSON* conf = read_json_from_file((char*)"/etc/site/site0.conf");
		if (conf)
		{
			cJSON* teamid_item = cJSON_GetObjectItem(conf, "team_id");
			strcpy(teamid, teamid_item->valuestring);
			cJSON_Delete(conf);
		}
	}
	return;
}

void set_my_teamid(char* teamid)
{
	if (teamid)
	{
		system_config_set("vppn_teamid", teamid);
		system_config_commit();
	}
}

void unset_my_teamid()
{
	system_config_unset("vppn_teamid");
	system_config_commit();
}

//0:disable
//1:enable
int get_vppn_status()
{
	int ret = 0;
	char buf[100];
	buf[0] = 0;
	system_config_get("vppn_enable", buf);
	if (buf[0])
	{
		ret = atoi(buf);
	}
	return ret;
}

void set_vppn_status(int status)
{
	char buf[100] = "";
	sprintf(buf, "%d", status);
	system_config_set("vppn_enable", buf);
	system_config_commit();
	return;
}

void get_my_lansubnet(char* lan_subnet)
{
	char buf[100];
	int ret = net_tool_get_if_subnet((char*)"br0", buf);
	if (ret == 0)
	{
		strcpy(lan_subnet, buf);
	}
	else
	{
		strcpy(lan_subnet, "192.168.2.0/24");
	}
	return;
}

int get_br500_wan_subnet(char* ret_buf)
{
	int ret = -1;
	char wan_proto[100] = "";
	system_config_get("wan_proto", wan_proto);
	if ((strcmp(wan_proto, "dhcp") == 0)
			||
			(strcmp(wan_proto, "static") == 0)
			)
	{
		ret = net_tool_get_if_subnet((char*)"brwan", ret_buf);
	}
	else
	{
		ret = net_tool_get_if_subnet((char*)"ppp0", ret_buf);
	}
	return ret;
}

int get_br500_wan_ip(char* ret_buf)
{
	int ret = -1;
	char wan_proto[100] = "";
	system_config_get("wan_proto", wan_proto);
	if ((strcmp(wan_proto, "dhcp") == 0)
			||
			(strcmp(wan_proto, "static") == 0)
			)
	{
		ret = net_tool_get_if_ip((char*)"brwan", ret_buf);
	}
	else
	{
		ret = net_tool_get_if_ip((char*)"ppp0", ret_buf);
	}
	return ret;
}

int get_br500_wan_mac(char* ret_buf)
{
	int ret = -1;
	char wan_proto[100] = "";
	system_config_get("wan_proto", wan_proto);
	if ((strcmp(wan_proto, "dhcp") == 0)
			||
			(strcmp(wan_proto, "static") == 0)
			)
	{
		ret = net_tool_get_if_hwaddr2((char*)"brwan", ret_buf);
	}
	else
	{
		ret = net_tool_get_if_hwaddr2((char*)"ppp0", ret_buf);
	}
	return ret;
}

void get_my_wansubnet(char* wan_subnet)
{
	get_br500_wan_subnet(wan_subnet);
	return;
}

void get_my_wanip(char* wan_ip)
{
	get_br500_wan_ip(wan_ip);
	return;
}

void get_my_wanmac(char* wan_mac)
{
	get_br500_wan_mac(wan_mac);
	return;
}

void get_my_virtualip(char* virtual_ip)
{
	char buf[100];
	int ret = net_tool_get_if_subnet((char*)"site0", buf);
	if (ret == 0)
	{
		strcpy(virtual_ip, buf);
	}
	else
	{
		strcpy(virtual_ip, "");
	}
	return;
}


/* cpu usage cal begin: */
#define TIME_INTERVAL (2)
#define BUFFER_LEN	(200)
#define MAX_CPU_NUM (20)

struct CpuTime_Info {
	int user_time;
	int nice_time;
	int system_time;
	int idle_time;
	int iowait_time;
	int irq_time;
	int softirq_time;
};

struct CPULoad_Info
{
	int cpu_num;
	double load[0];
};

static int cpu_num = 0;

void Get_Time_Info(const char * str, struct CpuTime_Info * time)
{
	char *data = (char *)str;
	//if str is total time buf
	//skip the first 5 bytes	
	data += 5;
	time->user_time = atoi(data);
	data = strchr(data, ' ');
	time->nice_time = atoi(data);
	data++;
	data = strchr(data, ' ');
	time->system_time = atoi(data);
	data++;
	data = strchr(data, ' ');
	time->idle_time = atoi(data);
	data++;
	data = strchr(data, ' ');
	time->iowait_time = atoi(data);
	data++;
	data = strchr(data, ' ');
	time->irq_time = atoi(data);
	data++;
	data = strchr(data, ' ');
	time->softirq_time = atoi(data);
	return;
}

//单位%
double Calculate_Load(struct CpuTime_Info *old_item, struct CpuTime_Info *new_item)
{
	int total_times;
	int idle_times;
	double t_times;
	double i_times;
	double result;
	total_times = (new_item->user_time - old_item->user_time) 
		+ (new_item->nice_time - old_item->nice_time) 
		+ (new_item->system_time - old_item->system_time)
		+ (new_item->idle_time - old_item->idle_time)
		+ (new_item->iowait_time - old_item->iowait_time)
		+ (new_item->irq_time - old_item->irq_time)
		+ (new_item->softirq_time - old_item->softirq_time)
		;
	idle_times =
		(new_item->idle_time - old_item->idle_time);
	t_times = (double)total_times;
	i_times = (double)idle_times;
	result = (t_times - i_times) / t_times;
	result *= 100;
	return result;
}

int Get_CPU_Num()
{
	FILE* stat_fd;
	char buf[BUFFER_LEN];
	//int i;
	int cur_num;
	if (!cpu_num)
	{
		stat_fd = fopen("/proc/stat", "r");
		fgets(buf, sizeof(buf), stat_fd);
		while (fgets(buf, sizeof(buf), stat_fd))
		{
			if (!strncmp(buf, "cpu", 3))
			{
				cur_num = atoi(buf+3);
				if (cpu_num < cur_num + 1)
				cpu_num++;
			}
			else
			{
				break;
			}
		}
		fclose(stat_fd);
	}
	return cpu_num;
}

//1. get the cpu count
//2. get each cpu load
cJSON *GetCPUJSON()
{
	FILE *stat_fd = NULL;
	char *buff = NULL;
	char total_buf[BUFFER_LEN];
	struct CpuTime_Info old_total_time;
	struct CpuTime_Info new_total_time;
	struct CpuTime_Info *old_cpu_times = NULL;
	struct CpuTime_Info *new_cpu_times = NULL;
	int cpu_num;
	int i;
	cJSON *array = NULL;
	struct CPULoad_Info *cpu_loads = NULL;

#if 0
	cpu_fd = fopen("/proc/cpuinfo", "r");
	fgets(CpuInfo->CPU_type, sizeof(CpuInfo->CPU_type), cpu_fd);
	fclose(cpu_fd);
#endif

	//step 1: get the cpu count

	cpu_num = Get_CPU_Num();
	//printf("~~cpu_num is %d\n", cpu_num);
	if (!cpu_num)
	{
		fprintf(stderr, "get cpu count error\n");
		return NULL;
	}

	buff = (char*)malloc(cpu_num * BUFFER_LEN);
	old_cpu_times = (struct CpuTime_Info *)malloc(cpu_num * sizeof(struct CpuTime_Info));
	new_cpu_times = (struct CpuTime_Info *)malloc(cpu_num * sizeof(struct CpuTime_Info));

	stat_fd = fopen("/proc/stat", "r");
#if 0
	if (!stat_fd)
	{
		goto out;
	}
#endif
	fgets(total_buf, sizeof(total_buf), stat_fd);
	for(i = 0; i < cpu_num; i++)
	{
		fgets(buff + i * BUFFER_LEN, BUFFER_LEN, stat_fd);
	}
	Get_Time_Info(total_buf, &old_total_time);
	for(i = 0; i < cpu_num; i++)
	{
		Get_Time_Info(buff + i * BUFFER_LEN, old_cpu_times + i);
	}
	fclose(stat_fd);

	//sleep 1s to get new cpu times
	sleep(1);

	stat_fd = fopen("/proc/stat", "r");
#if 0
	if (!stat_fd)
	{
		goto out;
	}
#endif
	fgets(total_buf, sizeof(total_buf), stat_fd);
	for(i = 0; i < cpu_num; i++)
	{
		fgets(buff + i * BUFFER_LEN, BUFFER_LEN, stat_fd);
	}
	Get_Time_Info(total_buf, &new_total_time);
	for(i = 0; i < cpu_num; i++)
	{
		Get_Time_Info(buff + i * BUFFER_LEN, new_cpu_times + i);
	}
	fclose(stat_fd);

	//第一个放total load result;
	//再依次存放每个cpu的load result;
	cpu_loads = (struct CPULoad_Info*)malloc(sizeof(struct CPULoad_Info) + (cpu_num + 1) * sizeof(double)); 
	cpu_loads->cpu_num = cpu_num;
	cpu_loads->load[0] = Calculate_Load(&old_total_time, &new_total_time);
	double total_cpu_load = ((double)cpu_loads->load[0]);
	array = cJSON_CreateArray();
	char cpu_load_total_buf[100] = "";
	sprintf(cpu_load_total_buf, "%.2lf", total_cpu_load);
	cJSON *obj = cJSON_CreateObject();	
	cJSON_AddStringToObject(obj, "cpu_name", "cpu");
	cJSON_AddStringToObject(obj, "cpu_usage", cpu_load_total_buf);
	cJSON_AddItemToArray(array, obj);
	//3700只有一个cpu，所以只填写一个总的cpu-load即可
#if 1
	for(i = 0; i < cpu_num; i++)
	{
		char cpu_load_buf[100] = "";
		cpu_loads->load[i+1] = Calculate_Load(&old_cpu_times[i], &new_cpu_times[i]);
		double cpu_load_i = ((double)cpu_loads->load[i+1]);
		cJSON *obj_i = cJSON_CreateObject();	
		char cpu_name[100] = "";
		sprintf(cpu_name, "cpu%d", i);
		sprintf(cpu_load_buf, "%.2lf", cpu_load_i);
		cJSON_AddStringToObject(obj_i, "cpu_name", cpu_name);
		cJSON_AddStringToObject(obj_i, "cpu_usage", cpu_load_buf);
		cJSON_AddItemToArray(array, obj_i);
	}
#endif

//out:
	if (old_cpu_times)
		free(old_cpu_times);
	if (new_cpu_times)
		free(new_cpu_times);
	if (cpu_loads)
		free(cpu_loads);
	return array;
}

cJSON *GetCPUJSON2(double* avg_load)
{
	FILE *stat_fd = NULL;
	char *buff = NULL;
	char total_buf[BUFFER_LEN];
	struct CpuTime_Info old_total_time;
	struct CpuTime_Info new_total_time;
	struct CpuTime_Info *old_cpu_times = NULL;
	struct CpuTime_Info *new_cpu_times = NULL;
	int cpu_num;
	int i;
	cJSON *array = NULL;
	struct CPULoad_Info *cpu_loads = NULL;

#if 0
	cpu_fd = fopen("/proc/cpuinfo", "r");
	fgets(CpuInfo->CPU_type, sizeof(CpuInfo->CPU_type), cpu_fd);
	fclose(cpu_fd);
#endif

	//step 1: get the cpu count

	cpu_num = Get_CPU_Num();
	//printf("~~cpu_num is %d\n", cpu_num);
	if (!cpu_num)
	{
		fprintf(stderr, "get cpu count error\n");
		return NULL;
	}

	buff = (char*)malloc(cpu_num * BUFFER_LEN);
	old_cpu_times = (struct CpuTime_Info *)malloc(cpu_num * sizeof(struct CpuTime_Info));
	new_cpu_times = (struct CpuTime_Info *)malloc(cpu_num * sizeof(struct CpuTime_Info));

	stat_fd = fopen("/proc/stat", "r");
#if 0
	if (!stat_fd)
	{
		goto out;
	}
#endif
	fgets(total_buf, sizeof(total_buf), stat_fd);
	for(i = 0; i < cpu_num; i++)
	{
		fgets(buff + i * BUFFER_LEN, BUFFER_LEN, stat_fd);
	}
	Get_Time_Info(total_buf, &old_total_time);
	for(i = 0; i < cpu_num; i++)
	{
		Get_Time_Info(buff + i * BUFFER_LEN, old_cpu_times + i);
	}
	fclose(stat_fd);

	//sleep 1s to get new cpu times
	sleep(4);

	stat_fd = fopen("/proc/stat", "r");
#if 0
	if (!stat_fd)
	{
		goto out;
	}
#endif
	fgets(total_buf, sizeof(total_buf), stat_fd);
	for(i = 0; i < cpu_num; i++)
	{
		fgets(buff + i * BUFFER_LEN, BUFFER_LEN, stat_fd);
	}
	Get_Time_Info(total_buf, &new_total_time);
	for(i = 0; i < cpu_num; i++)
	{
		Get_Time_Info(buff + i * BUFFER_LEN, new_cpu_times + i);
	}
	fclose(stat_fd);

	//第一个放total load result;
	//再依次存放每个cpu的load result;
	cpu_loads = (struct CPULoad_Info*)malloc(sizeof(struct CPULoad_Info) + (cpu_num + 1) * sizeof(double)); 
	cpu_loads->cpu_num = cpu_num;
	cpu_loads->load[0] = Calculate_Load(&old_total_time, &new_total_time);
	double total_cpu_load = ((double)cpu_loads->load[0]);
	array = cJSON_CreateArray();
	char cpu_load_total_buf[100] = "";
	sprintf(cpu_load_total_buf, "%.2lf", total_cpu_load);
	*avg_load = total_cpu_load;
	//cJSON *obj = cJSON_CreateObject();	
	//cJSON_AddStringToObject(obj, "cpu_name", "cpu");
	//cJSON_AddStringToObject(obj, "cpu_usage", cpu_load_total_buf);
	//cJSON_AddItemToArray(array, obj);
	//3700只有一个cpu，所以只填写一个总的cpu-load即可
#if 1
	for(i = 0; i < cpu_num; i++)
	{
		char cpu_load_buf[100] = "";
		cpu_loads->load[i+1] = Calculate_Load(&old_cpu_times[i], &new_cpu_times[i]);
		double cpu_load_i = ((double)cpu_loads->load[i+1]);
		cJSON *obj_i = cJSON_CreateObject();	
		char cpu_name[100] = "";
		sprintf(cpu_name, "cpu%d", i);
		sprintf(cpu_load_buf, "%.2lf", cpu_load_i);
		cJSON_AddStringToObject(obj_i, "name", cpu_name);
		cJSON_AddNumberToObject(obj_i, "percent", cpu_load_i);
		cJSON_AddItemToArray(array, obj_i);
	}
#endif

//out:
	if (old_cpu_times)
		free(old_cpu_times);
	if (new_cpu_times)
		free(new_cpu_times);
	if (cpu_loads)
		free(cpu_loads);
	return array;
}

/* cpu usage cal end: */

/* mem usage cal begin: */

#if 0
double Get_Mem_Info();

cJSON *GetMemJSON()
{
	double usage = Get_Mem_Info();
	cJSON *mem = cJSON_CreateNumber(usage); 
	return mem;
}
#endif

//单位%
double Get_Mem_Info(unsigned int* total_val, unsigned int* free_val)
{
	FILE *fp = NULL;
	char buff[200];
	char *data;
	int total_mem;
	int free_mem;
	double t_mem;
	double f_mem;
	double usage = 0;
	fp = fopen("/proc/meminfo", "r");
	if (fp)
	{
		fgets(buff, sizeof(buff), fp);
		data = strchr(buff, ' ');
		total_mem = atoi(data);
		*total_val = (unsigned int)total_mem;
		t_mem = (double)total_mem;

		fgets(buff, sizeof(buff), fp);
		data = strchr(buff, ' ');
		free_mem = atoi(data);
		*free_val = (unsigned int)free_mem;
		f_mem = (double)free_mem;

		usage = ((t_mem - f_mem) * 100)/t_mem;
		fclose(fp);
	}

	return usage;
}
/* mem usage cal end: */

extern void skip_crlf(char*);

/* get device info begin: */

cJSON* get_my_device_info()
{
	cJSON* obj = cJSON_CreateObject();

	/* get hardware version */
	char * hardware = read_text((char*)"/hardware_version");
	if (hardware)
	{
		skip_crlf(hardware);
		cJSON_AddStringToObject(obj, "hardware_version", hardware);
		free(hardware);
	}
	else
	{
		cJSON_AddStringToObject(obj, "hardware_version", "unknown");
	}

	char my_id[100] = "";
	get_my_id(my_id);
	cJSON_AddStringToObject(obj, "sn", my_id);

	/* get firmware version */
	char * firmware = read_text((char*)"/firmware_version");
	if (firmware)
	{
		skip_crlf(firmware);
		cJSON_AddStringToObject(obj, "firmware_version", firmware);
		free(firmware);
	}
	else
	{
		cJSON_AddStringToObject(obj, "firmware_version", "unknown");
	}

	/* GUI language version */
	char * language = read_text((char*)"/tmp/lang_version");
	if (language)
	{
		skip_crlf(language);
		cJSON_AddStringToObject(obj, "language_version", language);
		free(language);
	}
	else
	{
		cJSON_AddStringToObject(obj, "language_version", "unknown");
	}

	/* Operation Mode */
	char mode[100] = "";
	system_config_get("rae_cur_mode", mode);
	cJSON_AddStringToObject(obj, "operation_mode", mode);

	/* LAN MAC address */
	char lan_mac[100] = "";
	net_tool_get_if_hwaddr2((char*)"br0", lan_mac);
	cJSON_AddStringToObject(obj, "lan_mac", lan_mac);
	/* WAN MAC address */
	char wan_mac[100] = "";
	//net_tool_get_if_hwaddr2((char*)"brwan", wan_mac);
	get_my_wanmac(wan_mac);
	cJSON_AddStringToObject(obj, "wan_mac", wan_mac);

	/* LAN IP address */
	char lan_ip[100] = "";
	net_tool_get_if_ip((char*)"br0", lan_ip);
	cJSON_AddStringToObject(obj, "lan_ip", lan_ip);

	cJSON* lan_subnets = get_all_lan_subnets();
	if (lan_subnets)
	{
		cJSON_AddItemToObject(obj, "lan_subnets", lan_subnets);
	}
	/* WAN IP address */
	char wan_ip[100] = "";
	//net_tool_get_if_ip((char*)"brwan", wan_ip);
	get_my_wanip(wan_ip);
	cJSON_AddStringToObject(obj, "wan_ip", wan_ip);

	/* DHCP ON */
	int dhcp_pid = 0;
	dhcp_pid = process_tool_ps((char*)"udhcpd", (char*)"/tmp/udhcpd.conf");
	if (dhcp_pid)
	{
		cJSON_AddStringToObject(obj, "dhcp_server_on", "on");
	}
	else
	{
		cJSON_AddStringToObject(obj, "dhcp_server_on", "off");
	}

	//Tmperature info
	char * temperature = read_text((char*)"/sys/class/thermal/thermal_zone0/temp");
	if (temperature)
	{
		skip_crlf(temperature);
		cJSON_AddStringToObject(obj, "temperature", temperature);
		free(temperature);
	}
	else
	{
		cJSON_AddStringToObject(obj, "temperature", "0");
	}

	/* CPU info */
	cJSON* cpu_info = GetCPUJSON();
	cJSON_AddItemToObject(obj, "cpu_info", cpu_info);

	/* Mem info */
	unsigned int total_mem = 0;
	unsigned int free_mem = 0;
	char total_mem_buf[100] = "";
	char free_mem_buf[100] = "";
	char usage_buf[100] = "";
	double mem_usage = Get_Mem_Info(&total_mem, &free_mem);
	sprintf(usage_buf, "%.2lf", mem_usage);
	sprintf(total_mem_buf, "%u", total_mem);
	sprintf(free_mem_buf, "%u", free_mem);
	cJSON* mem_info = cJSON_CreateObject();
	cJSON_AddStringToObject(mem_info, "total", total_mem_buf);
	cJSON_AddStringToObject(mem_info, "free", free_mem_buf);
	cJSON_AddStringToObject(mem_info, "usage", usage_buf);

	cJSON_AddItemToObject(obj, "mem_info", mem_info);
	char buf[100];
	buf[0] = 0;
	system_config_get("http_passwd", buf);
	if (strcmp((const char*)buf, "password") == 0)
	{
		cJSON_AddNumberToObject(obj, "pwd_changed", 0);
	}
	else
	{
		cJSON_AddNumberToObject(obj, "pwd_changed", 1);
	}

	return obj;
}

/* get device info end: */

cJSON* get_br500_baseinfo()
{
	cJSON* ret = NULL;
	char mac[100] = "";
	char wan_ip[100] = "";

	get_my_wanip(wan_ip);
	net_tool_get_if_hwaddr2((char*)"br0", mac);
	
    char geoip_host[128] = "52.25.79.82";
	int geoip_port = 10000;
	char geoip_uri[100] = "/geoip_json.php";

	ret = cJSON_CreateObject();
	cJSON* geoip_res = net_tool_http_json_client2(0, geoip_host, geoip_port, geoip_uri, NULL, NULL);
	if (geoip_res)
	{
		char id[100] = "";
		get_my_id(id);
		if (strcmp(id, "5JR1885B01159") == 0)
		{
			cJSON* ip_item = cJSON_GetObjectItem(geoip_res, "ipaddr");
			if (ip_item)
			{
				cJSON_ReplaceItemInObject(geoip_res, "ipaddr", cJSON_CreateString("192.168.9.189"));
			}
		}
	}
	else
	{
		geoip_res = cJSON_CreateObject();
	}

	char * firmware = read_text((char*)"/firmware_version");
	if (firmware)
	{
		skip_crlf(firmware);
		cJSON_AddStringToObject(ret, "firmware_version", firmware);
		free(firmware);
	}
	else
	{
		cJSON_AddStringToObject(ret, "firmware_version", "unknown");
	}

	char * module = read_text((char*)"/module_name");
	if (module)
	{
		skip_crlf(module);
		cJSON_AddStringToObject(ret, "module_name", module);
		free(module);
	}
	else
	{
		cJSON_AddStringToObject(ret, "module_name", "unknown");
	}

	cJSON_AddStringToObject(ret, "mac_br0", mac);
	cJSON_AddStringToObject(ret, "wan_ip", wan_ip);
	cJSON_AddItemToObject(ret, "geoip", geoip_res);

	return ret;
}

cJSON* get_my_device_baseinfo()
{
	return get_br500_baseinfo();
}

/* get attach device begin: */

cJSON* get_attach_device(char* line)
{
	cJSON* ret = NULL;
	int i = 0;
	char* token = NULL;
	char* str1 = line;
	char* saveptr1 = NULL;

	char ip[100] = "";
	char mac[100] = "";
	char name[100] = "";


	for(i = 0; ; i++, str1 = NULL)
	{
		token = strtok_r(str1, " ", &saveptr1);
		if (token != NULL)
		{
			if (i == 0)
			{
				strcpy(ip, token);
			}
			else if (i == 1)
			{
				strcpy(mac, token);
			}
			else if (i == 2)
			{
				strcpy(name, token);
			}
			else
			{
				break;
			}
		}
		else
		{
			break;
		}
	}
	if (ip[0] && mac[0] && name[0])
	{
		ret = cJSON_CreateObject();
		cJSON_AddStringToObject(ret, "ip", ip);
		cJSON_AddStringToObject(ret, "mac", mac);
		cJSON_AddStringToObject(ret, "name", name);
		cJSON_AddStringToObject(ret, "type", "");
	}
	return ret;
}

cJSON* get_attach_devices()
{
	cJSON* ret = NULL;
	ret = cJSON_CreateArray();
	FILE* fp = fopen("/tmp/netscan/attach_device", "r");
	if (fp)
	{
		char line_buf[200] = "";
		while(fgets(line_buf, sizeof(line_buf), fp))
		{
			cJSON* item = get_attach_device(line_buf);
			if (item)
			{
				cJSON_AddItemToArray(ret, item);
			}
		}
		fclose(fp);
	}
	return ret;
}
/* get attach device end: */

void random_id_init(char* out_buf, int save_config)
{
	char *res = process_tool_run_cmd((char*)"openssl rand -hex 16");
	if (res)
	{
		//my_skip_crlf(res);
		str_tool_replaceFirst(res, '\n', 0);
		if (save_config)
		{
			system_config_set("vppn_uuid", res);
			system_config_commit();
		}
		strcpy(out_buf, res);
		free(res);
	}
	return;
}

#if 1
cJSON* get_br500_lan_subnets(int* subnet_cnt)
{
	cJSON* ret = NULL;
	cJSON* subnets = NULL;
	*subnet_cnt = 0;
	char* ret_str = process_tool_run_cmd((char*)"network.cli lan_subnet_list");
	if (ret_str)
	{
		subnets = cJSON_Parse(ret_str);
		if (subnets)
		{
			cJSON* code_item = cJSON_GetObjectItem(subnets, "code");
			if (code_item && code_item->valueint == 0)
			{
				cJSON* data_item = cJSON_GetObjectItem(subnets, "data");
				if (data_item)
				{
					cJSON* num_item = cJSON_GetObjectItem(data_item, "num");
					cJSON* subnet_item = cJSON_GetObjectItem(data_item, "subnet");
					ret = cJSON_Duplicate(subnet_item, 1);
					*subnet_cnt = num_item->valueint;
				}
			}
			cJSON_Delete(subnets);
		}
		free(ret_str);
	}
	return ret;
}

cJSON* get_lan_subnet(cJSON* subnets, int cur_cnt)
{
	cJSON* ret = NULL;
	cJSON* subnet = cJSON_GetArrayItem(subnets, cur_cnt);
	if (subnet)
	{
		cJSON* id_item = cJSON_GetObjectItem(subnet, "id");
		cJSON* ipaddr_item = cJSON_GetObjectItem(subnet, "ipaddr");
		cJSON* netmask_item = cJSON_GetObjectItem(subnet, "netmask");
		if (id_item && ipaddr_item && netmask_item)
		{
			char subnet_str[100] = "";
			char lan_name_str[100] = "";
			uint32_t mask_num = net_tool_netmask_to_num(netmask_item->valuestring);
			net_tool_ip_to_subnet(ipaddr_item->valuestring, (int)mask_num, subnet_str);
			sprintf(lan_name_str, "lan%d", cur_cnt + 1);
			ret = cJSON_CreateObject();
			cJSON_AddStringToObject(ret, "lan_name", lan_name_str);
			cJSON_AddStringToObject(ret, "lan_subnet", subnet_str);
		}
	}
	return ret;
}

cJSON* get_all_lan_subnets()
{
	cJSON* ret = cJSON_CreateArray();
	int subnet_cnt = 0;
	cJSON* subnets = get_br500_lan_subnets(&subnet_cnt);
	if (subnet_cnt > 0 && subnets)
	{
		int i;
		for(i = 0; i < subnet_cnt; i++)
		{
			cJSON* subnet_item = get_lan_subnet(subnets, i);
			cJSON_AddItemToArray(ret, cJSON_Duplicate(subnet_item, 1));
		}
		cJSON_Delete(subnets);
	}
	return ret;
}

void set_br500_lan_subnet(cJSON* new_subnet)
{
	cJSON* lan_name_item = cJSON_GetObjectItem(new_subnet, "lan_name");
	cJSON* lan_subnet_item = cJSON_GetObjectItem(new_subnet, "lan_subnet");
	if (lan_name_item && lan_subnet_item)
	{
		int id = 0;
		int lan_num = 0;
		char lan_num_buf[100] = "";
		system_config_get("lan_num", lan_num_buf);
		lan_num = atoi(lan_num_buf);

		char dhcpx_name_buf[100] = "";
		char dhcpx_value_buf[100] = "";
		char namex_name_buf[100] = "";
		char namex_value_buf[100] = "";
		char vidx_name_buf[100] = "";
		char vidx_value_buf[100] = "";
		char descx_name_buf[100] = "";
		char descx_value_buf[100] = "";
		char macx_name_buf[100] = "";
		char macx_value_buf[100] = "";
		char ipaddr_buf[100] = "";
		char netmask_buf[100] = "";
		char dhcp_start_buf[100] = "";
		char dhcp_end_buf[100] = "";
		char subnet_str[100] = "";
		sscanf(lan_name_item->valuestring, "lan%d", &id);
		if (id > 0 && lan_num > 0 && id <= lan_num)
		{
			if (id == 1)
			{
				sprintf(dhcpx_name_buf, "lan_dhcp");
				sprintf(namex_name_buf, "lan_name");
				sprintf(vidx_name_buf, "lan_vid");
				sprintf(descx_name_buf, "lan_desc");
				sprintf(macx_name_buf, "lan_factory_mac");

				strcpy(subnet_str, lan_subnet_item->valuestring);
				net_tool_subnet_to_ipmask(subnet_str, ipaddr_buf, netmask_buf);
				net_tool_get_ip_from_subnet(subnet_str, 2, dhcp_start_buf);
				net_tool_get_ip_from_subnet(subnet_str, 254, dhcp_end_buf);
			}
			else
			{
				sprintf(dhcpx_name_buf, "ct_lan_dhcp_x%d", id - 1);
				sprintf(namex_name_buf, "ct_lan_name_x%d", id - 1);
				sprintf(vidx_name_buf, "ct_lan_vid_x%d", id - 1);
				sprintf(descx_name_buf, "ct_lan_desc_x%d", id - 1);
				sprintf(macx_name_buf, "ct_lan_macaddr_x%d", id - 1);

				strcpy(subnet_str, lan_subnet_item->valuestring);
				net_tool_subnet_to_ipmask(subnet_str, ipaddr_buf, netmask_buf);
				net_tool_get_ip_from_subnet(subnet_str, 2, dhcp_start_buf);
				net_tool_get_ip_from_subnet(subnet_str, 254, dhcp_end_buf);
			}
			system_config_get(dhcpx_name_buf, dhcpx_value_buf);
			system_config_get(namex_name_buf, namex_value_buf);
			system_config_get(vidx_name_buf, vidx_value_buf);
			system_config_get(descx_name_buf, descx_value_buf);
			system_config_get(macx_name_buf, macx_value_buf);
			cJSON *cmd_param = cJSON_CreateObject();
			if (cmd_param)
			{
				cJSON* obj = cJSON_CreateObject();
				cJSON_AddNumberToObject(obj, "id", id);
				cJSON_AddStringToObject(obj, "name", namex_value_buf);
				cJSON_AddStringToObject(obj, "ipaddr", ipaddr_buf);
				cJSON_AddStringToObject(obj, "netmask", netmask_buf);
				cJSON_AddNumberToObject(obj, "dhcp_enable", atoi(dhcpx_value_buf));
				cJSON_AddStringToObject(obj, "dhcp_start", dhcp_start_buf);
				cJSON_AddStringToObject(obj, "dhcp_end", dhcp_end_buf);
				cJSON_AddStringToObject(obj, "macaddr", macx_value_buf);
				cJSON_AddNumberToObject(obj, "vlanid", atoi(vidx_value_buf));
				cJSON_AddStringToObject(obj, "desc", netmask_buf);
				cJSON_AddItemToObject(cmd_param, "subnet", obj);
				char* param_str = cJSON_PrintUnformatted(cmd_param);
				if (param_str)
				{
					char cmd_buf[1024] = "";
					sprintf(cmd_buf, "network.cli lan_subnet_edit '%s'", param_str);
					system(cmd_buf);
					free(param_str);
				}
				cJSON_Delete(cmd_param);
			}
		}
	}
	return;
}

void set_lan_subnets(cJSON* new_subnets)
{
	int cnt = cJSON_GetArraySize(new_subnets);
	int i;
	for(i = 0; i < cnt; i++)
	{
		cJSON* new_subnet = cJSON_GetArrayItem(new_subnets, i);
		set_br500_lan_subnet(new_subnet);
	}
	return;
}


#endif
