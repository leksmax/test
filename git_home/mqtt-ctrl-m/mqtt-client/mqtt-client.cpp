#include <mongoose.h>
#include "cJSON.h"
#include "my-device.h"
#include "vlan-topic.h"
#include "file_tool.h"
#include "str_tool.h"
#include "net_tool.h"
#include "system-config.h"
#include "log_tool.h"
#include "HttpClient.h"

#define DEFAULT_SSL_TRY_TIMES (8)

static char *s_address_ssl = NULL;
static char *s_address_nonssl = NULL;
//static char *s_address = NULL;
static char *s_user_name = NULL;
static char *s_password = NULL;
static char *s_public_topic = NULL;
static char *s_topic = NULL;
static char *s_clientid = NULL;
static char *s_teamtopic = NULL;
static char s_xagent_id[100] = "";
static int s_mode = 0;
static char s_random_id[40];

//static char *init_host = (char*)"13.230.51.38";
//static int init_port = 18083;
static char* init_host = NULL;
static int init_port = 0;

static bool s_enable_proxy = false;
static int s_use_proxy = 0;

static int s_use_ssl = 1;
static int s_try_ssl_cnt = 0;
static int s_try_conn_cnt = 0;
static int s_try_init_cnt = 0;

static int http_manager_saved = 0;
//static const char *s_topic = "/stuff";
//static struct mg_mqtt_topic_expression s_topic_expr = {NULL, 0};

#define HTTP_TUNNEL_MQTT_CLIENT_PORT (2324)
#define HTTP_TUNNEL_MQTT_SERVER_PORT (80)

#define KEEP_ALIVE_TIME (15)

static int keep_alive = KEEP_ALIVE_TIME;
ev_timer reconnect_timer;
ev_timer keepalive_timer;

struct mg_connect_opts conn_opt;

void test_cloud_led()
{
	FILE* fp = NULL;
	char line[100];
	fp = fopen("/proc/simple_config/cloud_led", "r");
	if (fp)
	{
		memset(line, 0, sizeof line);
		fgets(line, sizeof(line) - 1, fp);
		str_tool_replaceFirst(line, '\r', '\0');
		str_tool_replaceFirst(line, '\n', '\0');
		fclose(fp);
	}
	printf("line:%s\n", line);
}

void test_vpnlog()
{
	int i = 0;
	for(i = 0; i < 200; i++)
	{
		char line[1000];
		sprintf(line, "hello world my test 111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111112312312312312312321312312321321321a3: %d", i);
		log_tool_log(1, 3, line);
		usleep(20);
	}
	return;
}

void test_get_subnets()
{
	cJSON* subnets = get_all_lan_subnets();
	if (subnets)
	{
		cJSON_Dump(subnets);
		cJSON_Delete(subnets);
	}
	return;
}

void test_set_subnets()
{
	cJSON* array = cJSON_CreateArray();
	if (array)
	{
		cJSON* obj1 = cJSON_CreateObject();
		cJSON_AddStringToObject(obj1, "lan_name", "lan2");
		cJSON_AddStringToObject(obj1, "lan_subnet", "192.168.7.0/24");
		cJSON_AddItemToArray(array, obj1);
		set_lan_subnets(array);
		cJSON_Delete(array);
	}
	return;
}

int get_init_config()
{
	int ret = -1;
	cJSON *init_json = read_json_from_file((char*)"/etc/site/init_domain.conf");
	if (init_json)
	{
		int init_cnt = cJSON_GetArraySize(init_json);
		if (init_cnt > 0)
		{
			int init_cur = s_try_init_cnt % init_cnt;
			cJSON* init_item = cJSON_GetArrayItem(init_json, init_cur);
			cJSON* init_host_item = cJSON_GetObjectItem(init_item, "init_host");
			cJSON* init_port_item = cJSON_GetObjectItem(init_item, "init_port");
			if (init_host_item && init_port_item)
			{
				if (init_host)
				{
					free(init_host);
					init_host = NULL;
				}
				init_host = strdup(init_host_item->valuestring);
				init_port = init_port_item->valueint;
				ret = 0;
			}
		}
		cJSON_Delete(init_json);
	}
	return ret;
}

void free_init_config()
{
	if (init_host)
	{
		free(init_host);
		init_host = NULL;
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

void run_deamon()
{
	pid_t pid; 
	pid = fork();
	if (pid < 0) 
	{    
	}    
	else if(pid > 0) 
	{ 
		exit(0);
	} 
	setsid();
}

/* init an original sub topic */
static int topic_clientid_init()
{
	int ret = -1;
	char id[100] = "";
	get_my_id(id);
	if (s_topic)
	{
		free(s_topic);
		s_topic = NULL;
	}
	if (s_clientid)
	{
		free(s_clientid);
		s_clientid = NULL;
	}
	if (s_public_topic)
	{
		free(s_public_topic);
		s_public_topic = NULL;
	}
	if (id[0])
	{
		char topic[100];
		char clientid_buf[100] = "";
		if (s_mode)
		{
			sprintf(clientid_buf, "monitor:%s", s_random_id);
			sprintf(topic, "vppn/monitor/%s", id);
			s_public_topic = NULL;
			s_clientid = strdup(clientid_buf);
		}
		else
		{
			//sprintf(clientid_buf, "%s:%s", id, s_xagent_id);
			sprintf(topic, "vppn/%s", id);
			s_public_topic = strdup("vppn/proxy/publickey");
			s_clientid = strdup(s_random_id);
		}
		s_topic = strdup(topic);
		//s_clientid = strdup(clientid_buf);
		char username[100] = "";
		char password[100] = "";
		char md5_buf[100] = "";
		memset(md5_buf, 0, sizeof(md5_buf));

		if (s_user_name)
		{
			free(s_user_name);
			s_user_name = NULL;
		}
		if (s_password)
		{
			free(s_password);
			s_password = NULL;
		}
		sprintf(username, "%s", id);
		sprintf(password, "%s", s_xagent_id);
		s_user_name = strdup(username);
#if 1
		printf("md5_src:%s\n", password);
		str_tool_md5((const unsigned char*)password, strlen(password), md5_buf);
		s_password = strdup(md5_buf);
#else
		s_password = strdup(password);
#endif
		ret = 0;
	}
	return ret;
}

static void topic_clientid_exit()
{
	if (s_topic)
	{
		free(s_topic);
		s_topic = NULL;
	}
	if (s_clientid)
	{
		free(s_clientid);
		s_clientid = NULL;
	}
	if (s_user_name)
	{
		free(s_user_name);
		s_user_name = NULL;
	}
	if (s_password)
	{
		free(s_password);
		s_password = NULL;
	}
	return;
}

static int teamtopic_init()
{
	int ret = -1;
	char teamid[100] = "";
	get_my_teamid(teamid);
	if (s_teamtopic)
	{
		free(s_teamtopic);
		s_teamtopic = NULL;
	}
	if (teamid[0])
	{
		char team_topic[100];
		if (s_mode)
		{
			sprintf(team_topic, "vppn/monitor/%s", teamid);
		}
		else
		{
			sprintf(team_topic, "vppn/%s", teamid);
		}
		s_teamtopic = strdup(team_topic);
		ret = 0;
	}
	return ret;
}

static void teamtopic_exit()
{
	if (s_teamtopic)
	{
		free(s_teamtopic);
		s_teamtopic = NULL;
	}
	return;
}

static void restart_proxy(char* server_ip, int mode)
{
	char htc_stop_cmd[100];
	char htc_start_cmd[100];
	if(mode)
	{
		sprintf(htc_stop_cmd, "killall obfsproxy_mqtt-m");
		//sprintf(htc_start_cmd, "htc_mqtt-m -F %d %s:%d -U %s", HTTP_TUNNEL_MQTT_CLIENT_PORT + 1, server_ip, HTTP_TUNNEL_MQTT_SERVER_PORT, s_random_id);
		sprintf(htc_start_cmd, "obfsproxy_mqtt-m --daemon http --dest=%s:%d client 127.0.0.1:%d", server_ip, HTTP_TUNNEL_MQTT_SERVER_PORT, HTTP_TUNNEL_MQTT_CLIENT_PORT + 1);
	}
	else
	{
		sprintf(htc_stop_cmd, "killall obfsproxy_mqtt");
		//sprintf(htc_start_cmd, "htc_mqtt -F %d %s:%d -U %s", HTTP_TUNNEL_MQTT_CLIENT_PORT, server_ip, HTTP_TUNNEL_MQTT_SERVER_PORT, s_random_id);
		sprintf(htc_start_cmd, "obfsproxy_mqtt --daemon http --dest=%s:%d client 127.0.0.1:%d", server_ip, HTTP_TUNNEL_MQTT_SERVER_PORT, HTTP_TUNNEL_MQTT_CLIENT_PORT);
	}

	system(htc_stop_cmd);
	usleep(500000);
	system(htc_start_cmd);
}

static int pre_init()
{
	int  ret = -1;
	system_config_set("dns_hijack", (char*)"0");
	system_config_set("wiz_success", (char*)"1");
	system_config_commit();

	while ((get_init_config()) < 0)
	{
		printf("Please check /etc/site/init_domain.conf\n");
		sleep(5);
	}

	do {
		//log_tool_log("try get x_agent_id");
		system_config_get("x_agent_id", s_xagent_id);
		sleep(2);
	}while(!s_xagent_id[0]);

	if (!s_mode)
	{
		random_id_init(s_random_id, 1);
	}
	else
	{
		random_id_init(s_random_id, 0);
	}

	char manager_server[100] = "";
	if (get_mqtt_manager_server_from_cloud(manager_server, init_host, init_port, &http_manager_saved) == 0)
	{
		char temp_ssl[100];
		char temp_nonssl[100];
		//8883 for ssl, 1883 for nonssl

		//if enable proxy, alterlating using proxy or not in the next connection
		if (s_enable_proxy)
		{
			if (s_use_proxy == 1)
			{
				restart_proxy(manager_server, s_mode);
				if (s_mode)
				{
					sprintf(temp_ssl, "127.0.0.1:%d", HTTP_TUNNEL_MQTT_CLIENT_PORT + 1);
				}
				else
				{
					sprintf(temp_ssl, "127.0.0.1:%d", HTTP_TUNNEL_MQTT_CLIENT_PORT);
				}
				s_use_proxy = 0;
			}
			else
			{
				sprintf(temp_ssl, "%s:8883", manager_server);
				s_use_proxy = 1;
			}
		}
		else
		{
			sprintf(temp_ssl, "%s:8883", manager_server);
			//sprintf(temp_ssl, "127.0.0.1:8888");
		}
		//sprintf(temp_ssl, "127.0.0.1:2323");
		//sprintf(temp_ssl, "192.168.9.89:8883");
		//sprintf(temp_ssl, "13.230.51.38:8883");
		sprintf(temp_nonssl, "%s:1883", manager_server);
		//sprintf(temp_nonssl, "127.0.0.1:1883");
		//sprintf(temp_nonssl, "192.168.9.89:1883");
		//sprintf(temp_nonssl, "54.65.68.67:1883");
		//sprintf(temp_nonssl, "13.230.51.38:1883");
		s_address_ssl = strdup(temp_ssl);
		s_address_nonssl = strdup(temp_nonssl);
		//set_manager_server_to_local(manager_server);
		//s_address = strdup("54.65.68.67:8883");

		//in case config files disappear after upgrading firmware
		char team_id[100] = "";
		int enable = get_vppn_status();
		get_my_teamid(team_id);
		cJSON* conf = cJSON_CreateObject();
		cJSON_AddNumberToObject(conf, "on", enable?1:0);
		cJSON_AddStringToObject(conf, "team_id", team_id);
		write_json_to_file((char*)"/etc/site/site0.conf", conf);
		cJSON_Delete(conf);
		ret = topic_clientid_init();
		system("nps-cli");
		int port_reachable = net_tool_tcp_port_reachable(manager_server, 8883);
		if (port_reachable)
		{
			log_tool_log(1, 5,"Connectivity to Conductor: ok");
		}
		else
		{
			log_tool_log(1, 3,"Connectivity to Conductor: not ok");
		}
	}
	else
	{
		s_try_init_cnt++;
	}
	return ret;
}

static void post_exit()
{
	if (s_address_ssl)
	{
		free(s_address_ssl);
	}

	if (s_address_nonssl)
	{
		free(s_address_nonssl);
	}
	topic_clientid_exit();
}


cJSON* manager_request()
{
	char my_id[100] = "";
	get_my_id(my_id);
	cJSON* req = cJSON_CreateObject();
	cJSON_AddStringToObject(req, "appType", "vppn");
	cJSON_AddStringToObject(req, "businessType", "0");
	cJSON_AddStringToObject(req, "message", "");
	cJSON_AddStringToObject(req, "id", "111");
	cJSON_AddStringToObject(req, "from", my_id);
	cJSON_AddStringToObject(req, "messageType", "req");
	return req;
}

static void ev_handler(struct mg_connection *nc, int ev, void *data)
{
	struct mg_mqtt_message *msg = (struct mg_mqtt_message *)data;
	struct mg_mqtt_topic_expression s_topic_expr = {NULL, 0};
	struct mg_mqtt_topic_expression s_teamtopic_expr = {NULL, 0};
	struct mg_mqtt_topic_expression s_publictopic_expr = {NULL, 0};
	struct mg_send_mqtt_handshake_opts opts;
	char recv_topic[100];
	char pub_topic[100];
	char add_topic[100];
	char del_topic[100];
	char* response;
	char *topic[1];
	cJSON* manager_req = NULL;
	char *str_req = NULL;
	switch (ev) {
		case MG_EV_CONNECT: 
			//log_tool_log("Try connecting to conductor server(%s)", s_address_ssl);
			//syslog(LOG_USER |LOG_NOTICE, "[mqttclient]Try connect to conductor server");
			//syslog(LOG_INFO, "Try connect to conductor server");
			teamtopic_init();
			memset(&opts, 0, sizeof(opts));
			opts.user_name = s_user_name;
			opts.password = s_password;
			mg_set_protocol_mqtt(nc);
			/* each client must send a unique handshake string, we use s_topic */
			//mg_send_mqtt_handshake_opt(nc, "1234577", opts);
			printf("clientid:%s\n", s_clientid);
			printf("username:%s\n", s_user_name);
			printf("password:%s\n", s_password);
			if (s_clientid)
			{
				mg_send_mqtt_handshake_opt(nc, s_clientid, opts);
			}
			else
			{
				mg_send_mqtt_handshake_opt(nc, s_topic, opts);
			}
			break;

		case MG_EV_MQTT_CONNACK:
			if (msg->connack_ret_code != MG_EV_MQTT_CONNACK_ACCEPTED)
			{
				nc->flags |= MG_F_CLOSE_IMMEDIATELY;
				//log_tool_log("Connect to conductor server(%s) failed(error code is %d), try connect again after a few seconds", s_address_ssl, msg->connack_ret_code);
				log_tool_log(1, 3, "Authentication: Failure");
				printf("Got mqtt connection error: %d\n", msg->connack_ret_code);
				//exit(1);
			}
			else
			{
				log_tool_log(1, 5, "Authentication: Success");
				//log_tool_log("Connect to conductor server(%s) ok", s_address_ssl);
				//syslog(LOG_INFO, "Connect to conductor server ok");
				s_topic_expr.topic = s_topic;
				//s_topic_expr.topic = (char*)"/stuff";
				s_topic_expr.qos = 0;
				printf("Subscribing to '%s'\n", s_topic);
				mg_mqtt_subscribe(nc, &s_topic_expr, 1, 42);
				if (s_teamtopic)
				{
					s_teamtopic_expr.topic = s_teamtopic;
					s_teamtopic_expr.qos = 0;
					printf("Subscribing to '%s'\n", s_teamtopic);
					mg_mqtt_subscribe(nc, &s_teamtopic_expr, 1, 42);
				}
				if (s_public_topic)
				{
					s_publictopic_expr.topic = s_public_topic;
					s_publictopic_expr.qos = 0;
					printf("Subscribing to '%s'\n", s_public_topic);
					mg_mqtt_subscribe(nc, &s_publictopic_expr, 1, 43);
				}
				//get manager server
#if 0
				if (!http_manager_saved)
#endif
				{
					manager_req = manager_request();
					if (manager_req)
					{
						str_req = cJSON_Print(manager_req);
						if (str_req)
						{
							printf("publish request body:%s\n", str_req);
							mg_mqtt_publish(nc, "vppn/Manager/Server", 65, MG_MQTT_QOS(0), str_req, strlen(str_req));
							free(str_req);
						}
						cJSON_Delete(manager_req);
					}
				}
				ev_timer_stop(nc->mgr->loop, &keepalive_timer);
				ev_timer_set(&keepalive_timer, 10, 10);
				ev_timer_start(nc->mgr->loop, &keepalive_timer);
			}
			break;

		case MG_EV_MQTT_PUBACK:
		  printf("Message publishing acknowledged (msg_id: %d)\n", msg->message_id);
	      break;
		
		case MG_EV_MQTT_SUBACK:
			printf("Subscription acknowledged, forwarding to '/test'\n");
			break;

		case MG_EV_MQTT_PUBLISH:
#if 0
			char hex[1024] = {0};
			mg_hexdump(nc->recv_mbuf.buf, msg->payload.len, hex, sizeof(hex));
			printf("Got incoming message %.*s:\n%s", (int)msg->topic.len, msg->topic.p, hex);
			printf("Forwarding to /test\n");
			mg_mqtt_publish(nc, "/test", 65, MG_MQTT_QOS(0), msg->payload.p,
			msg->payload.len);
#else
			//printf("Got incoming message %.*s: %.*s\n", (int) msg->topic.len,
			//msg->topic.p, (int) msg->payload.len, msg->payload.p);
			strncpy(recv_topic, msg->topic.p, msg->topic.len);
			recv_topic[msg->topic.len] = 0;
			response = handle_mqtt_topic((char*)msg->payload.p, (int) msg->payload.len, (char*)msg->topic.p, pub_topic, add_topic, del_topic);
			if (response)
			{
				printf("publish [%s]:%s\n", pub_topic, response);
				if (pub_topic[0])
				{
					//mg_mqtt_publish(nc, "vppn/PC123457", 65, MG_MQTT_QOS(0), response, strlen(response) + 1);
					mg_mqtt_publish(nc, pub_topic, 65, MG_MQTT_QOS(0), response, strlen(response));
					//mg_mqtt_publish(nc, "/test", 65, MG_MQTT_QOS(0), msg->payload.p, msg->payload.len);
				}
				free(response);
			}
			if (add_topic[0])
			{
				s_topic_expr.topic = add_topic;
				s_topic_expr.qos = 0;
				printf("Subscribing to '%s'\n", s_topic);
				mg_mqtt_subscribe(nc, &s_topic_expr, 1, 42);
			}
			if (del_topic[0])
			{
				topic[0] = del_topic;
				mg_mqtt_unsubscribe(nc, topic, 1, 43);
			}
#endif
			break;

		case MG_EV_MQTT_PINGRESP:
			printf("Recv PingResp\n");
			keep_alive = KEEP_ALIVE_TIME;
			break;
		
		case MG_EV_POLL:
			if (keep_alive == 0) {
				printf("keep alive failed\n");
				nc->flags |= MG_F_CLOSE_IMMEDIATELY;
				keep_alive = KEEP_ALIVE_TIME;
			}
			break;
		case MG_EV_CLOSE:
			if (s_use_ssl)
			{
				s_try_ssl_cnt++;
			}
			else
			{
			}
			s_try_conn_cnt++;
			printf("Connection closed(ssl connection count %d)\n", s_try_ssl_cnt);
			log_tool_log(1, 3, "Connectivity to Conductor: lost connection, retrying after 5 seconds");
			//log_tool_log("Kicked off by conductor server(%s) %d times, try connect again after a few seconds", s_address_ssl, s_try_conn_cnt);
			//syslog(LOG_SYSLOG | LOG_EMERG, "Kicked off by conductor server %d times, try connect again after a few seconds", s_try_conn_cnt);
			teamtopic_exit();
			//ev_timer_stop(nc->mgr->loop, &reconnect_timer);
			ev_timer_set(&reconnect_timer, 5, 5);
			ev_timer_start(nc->mgr->loop, &reconnect_timer);
		break;
	}
}

static void signal_cb(struct ev_loop *loop, ev_signal *w, int revents)
{
	printf("Got signal: %d\n", w->signum);
	ev_break(loop, EVBREAK_ALL);
}

static void reconnect_cb(struct ev_loop *loop, ev_timer *w, int revents)
{
	ev_timer_stop(loop, w);
	while(pre_init() < 0)
	{
		printf("pre_init failed, can't reconnect\n");
		sleep(3);
	}
	struct mg_mgr *mgr = (struct mg_mgr *)w->data;
	//syslog(LOG_SYSLOG |LOG_EMERG, "Try reconnect to mqtt server");
	//log_tool_log("Try reconnect to mqtt server");
	if (s_use_ssl == 0)
	{
		mg_connect(mgr, s_address_nonssl, ev_handler);
		printf("Try Reconnect to %s\n", s_address_nonssl);
	}
	else
	{
		mg_connect_opt(mgr, s_address_ssl, ev_handler, conn_opt);
		printf("Try Reconnect to %s\n", s_address_ssl);
	}
}

static void keepalive_cb(struct ev_loop *loop, ev_timer *w, int revents)
{
	keep_alive = keep_alive - 1;
	if (keep_alive == 0)
		ev_timer_stop(loop, w);
}

int main(int argc, char *argv[])
{
	struct ev_loop *loop = EV_DEFAULT;
	ev_signal sig_watcher;
	struct mg_mgr mgr;
	struct mg_connection *nc;
	int i;

	//test_cloud_led();

	int front_ground = 0;
	/* Parse command line arguments */
	for (i = 1; i < argc; i++) {
#if 0
		if (strcmp(argv[i], "-U") == 0)
			s_user_name = argv[++i];
		else if (strcmp(argv[i], "-t") == 0)
			s_topic = argv[++i];
		else if (strcmp(argv[i], "-P") == 0)
			s_password = argv[++i];
		else
#endif
		if (strcmp(argv[i], "-f") == 0)
		{
			front_ground = 1;
		}
#if 0
		else if (strcmp(argv[i], "-h") == 0)
		{
			init_host = argv[++i];
		}
		else if (strcmp(argv[i], "-p") == 0)
		{
			init_port = atoi(argv[++i]);
		}
#endif
		else if (strcmp(argv[i], "-m") == 0)
		{
			s_mode = 1;
		}
		//use nonssl, we will try ssl first
		else if (strcmp(argv[i], "-n") == 0)
		{
			s_use_ssl = 0;
		}
	}

	//test_get_subnets();
	//test_set_subnets();
	//test_get_subnets();

	//printf("user: %s\n", s_user_name);
	//printf("password: %s\n", s_password);
	int init_config_ok = get_init_config();
	if (init_config_ok < 0)
	{
		printf("Please set init_host and init_port in /etc/site/init_domain.conf first\n");
		printf("eg. \n[\n{\t\"init_host\":\"example.com\",\n\t\"init_port\":443}\n]");
		exit(-1);
	}

	if (!front_ground)
	{
		run_deamon();
		run_no_debug_init();
	}

	HttpClient_init();
	if (!s_mode)
	{
		vpn_tunnel_gen_key((char*)"/tmp");
	}
	log_tool_init("0", "mqtt-client");
	//test_vpnlog();
	while(pre_init() < 0)
	{
		printf("pre_init failed\n");
		sleep(10);
	}

	ev_signal_init(&sig_watcher, signal_cb, SIGINT);
	ev_signal_start(loop, &sig_watcher);
	
	mg_mgr_init(&mgr, NULL, loop);

	//conn_opt.ssl_cert = "/etc/site/cert.pem";
	//conn_opt.ssl_key = "/etc/site/key.pem";
	conn_opt.ssl_cert = NULL;
	conn_opt.ssl_key = NULL;
	conn_opt.ssl_ca_cert = "*";
	//conn_opt.ssl_ca_cert = "/etc/site/cacert.pem";

	if (s_use_ssl == 0)
	{
		nc = mg_connect(&mgr, s_address_nonssl, ev_handler);
		if (!nc) {
			fprintf(stderr, "mg_connect(%s) failed\n", s_address_nonssl);
			goto err;
		}
	}
	else
	{
		//conn_opt.ssl_server_name = "*";
		nc = mg_connect_opt(&mgr, s_address_ssl, ev_handler, conn_opt);
		if (!nc) {
			fprintf(stderr, "mg_connect_opt(%s) failed\n", s_address_ssl);
			goto err;
		}
	}

	ev_timer_init(&reconnect_timer, reconnect_cb, 5, 10);
	reconnect_timer.data = &mgr;

	ev_timer_init(&keepalive_timer, keepalive_cb, 10, 10);
	
	ev_run(loop, 0);

err:
	printf("exit...\n");
	
	mg_mgr_free(&mgr);

	post_exit();

	log_tool_exit();

	HttpClient_exit();

	free_init_config();
	return 0;
}
