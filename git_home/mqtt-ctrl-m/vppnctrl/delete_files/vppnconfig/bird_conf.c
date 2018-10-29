#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "bird_conf.h"
#include "cJSON.h"
#include "net_tool.h"
#include "file_tool.h"
#include "nvram-common.h"

char* get_custom_lan_if()
{
	char *str = NULL;
	cJSON *obj = read_json_from_file("/etc/vppn_custom.conf");
	if (obj)
	{
		cJSON *dev_item = cJSON_GetObjectItem(obj, "tun_dev");
		str = strdup(dev_item->valuestring);
		cJSON_Delete(obj);
	}
	return str;
}

void bird_config_common(char *buf, cJSON *root)
{
	char *common_format = "router id %s; \n\n"
						"log \"/var/log/bird.log\" all; \n"
						"debug protocols { states, routes, filters, interfaces } \n\n"
						"protocol kernel { \n"
						"\timport none; \n"
						"\texport all; \n"
						"} \n\n"
						"protocol device { \n"
						"\t# default \n"
						"} \n\n";

	char local_ip[20] = {0};
	char common_buf[400] = {0};

	char *lan = get_custom_lan_if();
	if (!lan)
	{
		lan = strdup("br0");
	}
	net_tool_get_if_ip(lan, local_ip);

	sprintf(common_buf, common_format, local_ip);
	strcat(buf, common_buf);
	free(lan);
	return;
}

void bird_config_ospf(char *buf, cJSON *root)
{
	int i=0;
	int n=0;
	char intf_first[] =  "protocol ospf { \n"
						"\tarea 0 { \n"
						"\t\tinterface \"lo\" { \n"
						"\t\t\tstub; \n"
						"\t\t}; \n";
						/*"\t\tinterface \"br0\" { \n"
						"\t\t}; \n";*/
	
	char *intf_format = "\t\tinterface \"%s\" { \n"
						"\t\t\tstub; \n"
						"\t\t}; \n";
	
	char intf_last[] =	"\t}; \n"
						"}\n\n";

	strcat(buf, intf_first);
	
	cJSON *array = cJSON_GetObjectItem(root, "interface");
	n = cJSON_GetArraySize(array);
	for (i=0; i<n; i++)
	{
		cJSON *item = cJSON_GetArrayItem(array, i);
		char content[100] = {0};
		sprintf(content, intf_format, item->valuestring);
		strcat(buf, content);
	}
	
	strcat(buf, intf_last);

	return;
}

void bird_config_ebgp(char *buf, cJSON *root)
{
	int i=0;
	int n=0;
	//cJSON *local_ip_item = NULL;
	cJSON *local_sub_item = NULL;
	cJSON *peer_info_array = NULL;

	//char obj_str[20] = {0};
	char table_name[30] = {0};
	
	struct in_addr local_vip;
	struct in_addr peer_vip;

	char *ebgp_format = "table %s \n"	// table name
						"protocol static originate_to_%s { \n"	// table name
						"\ttable %s; \n"	// table name
						"\timport all; \n"
						"\troute %s blackhole; \n"	// subnet
						"} \n\n"
						"protocol bgp ebgp_%s { \n" // table name
						"\ttable %s; \n"	// table name
						"\tlocal %s as %d; \n"	// local vip, AS number
						"\tneighbor %s as %d; \n"	// peer vip, AS number
						"\timport filter { \n"
						"\t\taccept; \n"
						"\t}; \n"
						"\timport keep filtered on; \n"
						"\texport where source = RTS_STATIC; \n"
						"} \n\n"
						"protocol pipe p_master_to_%s { \n" // table name
						"\ttable master; \n"
						"\tpeer table %s; \n"	// table name
						"\timport where source = RTS_BGP; \n"
						"\texport none; \n"
						"} \n\n";

	/*sprintf(obj_str, "tunnel%d", tunnel_id);
	cJSON *local_ip_array = NULL;
	cJSON *local_ip_obj = NULL;
	local_ip_array = cJSON_GetObjectItem(root, JSON_LOCAL_VIP);
	n = cJSON_GetArraySize(local_ip_array);
	for (i=0; i<n; i++)
	{
		local_ip_obj = cJSON_GetArrayItem(local_ip_array, i);
		local_ip_item = cJSON_GetObjectItem(local_ip_obj, obj_str);
	}*/
	
	local_sub_item = cJSON_GetObjectItem(root, "local_subnet");
	//local_sub_item = cJSON_GetObjectItem(root, JSON_LOCAL_SUBNET);
	peer_info_array = cJSON_GetObjectItem(root, "p2p_info");
	//peer_info_array = cJSON_GetObjectItem(root, JSON_PEER_INFO);

	/*if (local_ip_item)
	{
		inet_aton(local_ip_item->valuestring, &local_vip);
		local_vip.s_addr = htonl(local_vip.s_addr);
	}
	else
	{
		//printf("please start tinc first!\n");
	}*/
	
	//inet_aton(local_sub_item->valuestring, &peer_vip);
	//peer_vip.s_addr = htonl(peer_vip.s_addr);
	
	n = cJSON_GetArraySize(peer_info_array);
	for (i=0; i<n; i++)
	{
		cJSON *obj = cJSON_GetArrayItem(peer_info_array, i);
		cJSON *peer_item = cJSON_GetObjectItem(obj, "ip");
		//cJSON *peer_item = cJSON_GetObjectItem(obj, JSON_PEER_IP);
		cJSON *local_item = cJSON_GetObjectItem(obj, "local_vip");
		//cJSON *local_item = cJSON_GetObjectItem(obj, JSON_LOCAL_VIP);
		cJSON *tun_item = cJSON_GetObjectItem(obj, "tunnel_id");
		//cJSON *tun_item = cJSON_GetObjectItem(obj, JSON_TUNNEL_ID);

		inet_aton(peer_item->valuestring, &peer_vip);
		peer_vip.s_addr = htonl(peer_vip.s_addr);

		inet_aton(local_item->valuestring, &local_vip);
		local_vip.s_addr = htonl(local_vip.s_addr);
		
		int local_as = local_vip.s_addr%1022 + 64512;
		int peer_as = peer_vip.s_addr%1022 + 64512;

		sprintf(table_name, "tun%d_%d", tun_item->valueint, peer_vip.s_addr & 0xffff);
		char content[1024] = {0};
		sprintf(content, ebgp_format, 
				table_name, table_name, table_name, local_sub_item->valuestring,
				table_name, table_name, local_item->valuestring, local_as, peer_item->valuestring, peer_as,
				table_name, table_name);
				
		strcat(buf, content);
	}
}

int set_bird_file()
{
	int		ret = -1;
	char *buf = NULL;
	char 	file[100] = {0};
	cJSON 	*root = NULL;
	char 	*ptr = NULL;
	
	buf = malloc(256*1024);
	if (buf)
	{
		buf[0] = 0;
		sprintf(file, BIRD_INFO_FILE);
		ptr = read_text(file);
		if (ptr)
		{
			root = cJSON_Parse(ptr);
			if (root)
			{
				bird_config_common(buf, root);
				bird_config_ospf(buf, root);
				bird_config_ebgp(buf, root);
		
				cJSON_Delete(root);
		
				write_text("/etc/bird.conf", buf);
				ret = 0;
			}
			free(ptr);
		}
		free(buf);
	}

	return ret;
}


