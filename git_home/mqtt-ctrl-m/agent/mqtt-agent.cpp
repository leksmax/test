#include <mongoose.h>
#include "cJSON.h"
#include "my-device.h"
#include "file_tool.h"

#define DEFAULT_SSL_TRY_TIMES (8)

static char *s_address_ssl = NULL;
static char *s_address_nonssl = NULL;

//static char *s_user_name = NULL;
static char *s_user_name = NULL;
//static char *s_password = NULL;
static char *s_password = NULL;

static char *s_topic = NULL;
static char *s_teamtopic = NULL;

static int s_enable_ssl = 1;
static int s_use_ssl = 1;
static int s_try_ssl_cnt = 0;
//static const char *s_topic = "/stuff";
//static struct mg_mqtt_topic_expression s_topic_expr = {NULL, 0};

#define KEEP_ALIVE_TIME (4)

static int keep_alive = KEEP_ALIVE_TIME;
ev_timer keepalive_timer;

struct mg_connect_opts conn_opt;

char* s_pub_topic = NULL;
cJSON* s_pub_json = NULL;

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
static void topic_init()
{
	char id[100] = "";
	char teamid[100] = "";
	get_my_id(id);
	get_my_teamid(teamid);
	if (s_topic)
	{
		free(s_topic);
		s_topic = NULL;
	}
#if 0
	if (s_teamtopic)
	{
		free(s_teamtopic);
		s_teamtopic = NULL;
	}
#endif
	if (id[0])
	{
		char topic[100];
		sprintf(topic, "vppn/%s-agent", id);
		s_topic = strdup(topic);
	}
#if 0
	if (teamid[0])
	{
		char team_topic[100];
		sprintf(team_topic, "vppn/%s-agent-team", teamid);
		s_teamtopic = strdup(team_topic);
	}
#endif
	return;
}

static int pre_init()
{
	int  ret = -1;
	char manager_server[100] = "";
	if (get_mqtt_manager_server_from_local(manager_server) == 0)
	{
		char temp_ssl[100];
		char temp_nonssl[100];
		//8883 for ssl, 1883 for nonssl
		sprintf(temp_ssl, "%s:8883", manager_server);
		sprintf(temp_nonssl, "%s:1883", manager_server);
		s_address_ssl = strdup(temp_ssl);
		s_address_nonssl = strdup(temp_nonssl);
		//set_manager_server_to_local(manager_server);
		//s_address = strdup("54.65.68.67:8883");

		//in case config files disappear after upgrading firmware
		ret = 0;
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
}

static void topic_exit()
{
	if (s_topic)
	{
		free(s_topic);
		s_topic = NULL;
	}
	if (s_teamtopic)
	{
		free(s_teamtopic);
		s_teamtopic = NULL;
	}
	return;
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
	struct mg_send_mqtt_handshake_opts opts;
	char* pub_str = NULL;
	static int already_pub = 0;
	char hex[1024] = {0};
	switch (ev) {
		case MG_EV_CONNECT: 
			memset(&opts, 0, sizeof(opts));
			opts.user_name = s_user_name;
			opts.password = s_password;
			mg_set_protocol_mqtt(nc);
			/* each client must send a unique handshake string, we use s_topic */
			mg_send_mqtt_handshake_opt(nc, s_topic, opts);
			break;

		case MG_EV_MQTT_CONNACK:
			if (msg->connack_ret_code != MG_EV_MQTT_CONNACK_ACCEPTED) {
				printf("Got mqtt connection error: %d\n", msg->connack_ret_code);
				nc->flags |= MG_F_CLOSE_IMMEDIATELY;
				//exit(1);
			}
			//mg_mqtt_subscribe(nc, &s_topic_expr, 1, 42);
			ev_timer_start(nc->mgr->loop, &keepalive_timer);
			break;

		case MG_EV_MQTT_PUBACK:
			nc->flags |= MG_F_CLOSE_IMMEDIATELY;
			printf("Message publishing acknowledged (msg_id: %d)\n", msg->message_id);
			break;
		
		case MG_EV_MQTT_SUBACK:
			printf("Subscription acknowledged\n");
			break;

		case MG_EV_MQTT_PUBLISH:
			mg_hexdump(nc->recv_mbuf.buf, msg->payload.len, hex, sizeof(hex));
			printf("Got incoming message %.*s:\n%s", (int)msg->topic.len, msg->topic.p, hex);
			//printf("Forwarding to /test\n");
			//mg_mqtt_publish(nc, "/test", 65, MG_MQTT_QOS(0), msg->payload.p,
			//msg->payload.len);
			break;

		case MG_EV_MQTT_PINGRESP:
			printf("Recv PingResp\n");
			if (!already_pub)
			{
				pub_str = cJSON_PrintUnformatted(s_pub_json);
				if (pub_str)
				{
					mg_mqtt_publish(nc, s_pub_topic, 65, MG_MQTT_QOS(0), pub_str, strlen(pub_str));
					free(pub_str);
				}
				already_pub = 1;
			}
			else
			{
				nc->flags |= MG_F_CLOSE_IMMEDIATELY;
			}
			//keep_alive = KEEP_ALIVE_TIME;
			break;
		
		case MG_EV_POLL:
			if (keep_alive == 0) {
				printf("keep alive failed\n");
				nc->flags |= MG_F_CLOSE_IMMEDIATELY;
				keep_alive = KEEP_ALIVE_TIME;
			}
			break;
		case MG_EV_CLOSE:
			ev_break(nc->mgr->loop, EVBREAK_ALL);
			printf("Connection closed(ssl connection count %d)\n", s_try_ssl_cnt);
			break;
	}
}

static void signal_cb(struct ev_loop *loop, ev_signal *w, int revents)
{
	printf("Got signal: %d\n", w->signum);
	ev_break(loop, EVBREAK_ALL);
}

static void keepalive_cb(struct ev_loop *loop, ev_timer *w, int revents)
{
	keep_alive = keep_alive - 1;
	if (keep_alive == 0)
		ev_timer_stop(loop, w);
}

char* init_pub_topic(char* sn)
{
	char buf[100]= "";
	sprintf(buf, "vppn/%s", sn);
	return strdup(buf);
}

void exit_pub_topic(char* pub_topic)
{
	if (pub_topic)
	{
		free(pub_topic);
	}
	return;
}

cJSON* init_pub_json(char* action, char* teamid, char* vip)
{
	cJSON* prepare_json = NULL;
	if (strcmp(action, "add_device") == 0)
	{
		char vip_buf[100] = "";
		prepare_json = cJSON_CreateObject();
		cJSON_AddStringToObject(prepare_json, "id", "11111");
		cJSON_AddStringToObject(prepare_json, "type", "start_vpn_request");
		cJSON_AddStringToObject(prepare_json, "teamId", teamid);
		if (vip != NULL)
		{
			sprintf(vip_buf, "%s/28", vip);
			cJSON_AddStringToObject(prepare_json, "vitrualIp", vip_buf);
		}
	}
	else if (strcmp(action, "del_device") == 0)
	{
		prepare_json = cJSON_CreateObject();
		cJSON_AddStringToObject(prepare_json, "id", "11111");
		cJSON_AddStringToObject(prepare_json, "type", "stop_vpn_request");
		cJSON_AddStringToObject(prepare_json, "teamId", teamid);
	}
	else if (strcmp(action, "start_vpn") == 0)
	{
		char vip_buf[100] = "";
		prepare_json = cJSON_CreateObject();
		cJSON_AddStringToObject(prepare_json, "id", "11111");
		cJSON_AddStringToObject(prepare_json, "type", "start_vpn_request");
		cJSON_AddStringToObject(prepare_json, "teamId", teamid);
		if (vip)
		{
			sprintf(vip_buf, "%s/28", vip);
			cJSON_AddStringToObject(prepare_json, "vitrualIp", vip_buf);
		}
	}
	else if (strcmp(action, "stop_vpn") == 0)
	{
		prepare_json = cJSON_CreateObject();
		cJSON_AddStringToObject(prepare_json, "id", "11111");
		cJSON_AddStringToObject(prepare_json, "type", "stop_vpn_request");
		cJSON_AddStringToObject(prepare_json, "teamId", teamid);
	}
	else if (strcmp(action, "modify_subnet") == 0)
	{
		prepare_json = cJSON_CreateObject();
		cJSON_AddStringToObject(prepare_json, "id", "11111");
		cJSON_AddStringToObject(prepare_json, "type", "modify_subnet_request");
		cJSON_AddStringToObject(prepare_json, "teamId", teamid);
		cJSON_AddStringToObject(prepare_json, "lanSubnet", vip);
	}
	return prepare_json;
}

void exit_pub_json(cJSON* json)
{
	if (json)
	{
		cJSON_Delete(json);
	}
	return;
}

int main(int argc, char *argv[])
{
	struct ev_loop *loop = EV_DEFAULT;
	ev_signal sig_watcher;
	struct mg_mgr mgr;
	struct mg_connection *nc;
	int i;

	char *l_sn = NULL;
	char *l_action = NULL;
	char *l_teamid = NULL;
	char *l_vip = NULL;

	/* Parse command line arguments */
	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-u") == 0)
			s_user_name = argv[++i];
		else if (strcmp(argv[i], "-t") == 0)
			s_topic = argv[++i];
		else if (strcmp(argv[i], "-p") == 0)
			s_password = argv[++i];
		//use nonssl, we will try ssl first
		else if (strcmp(argv[i], "-n") == 0)
		{
			s_enable_ssl = 0;
			s_use_ssl = 0;
		}
		/* parse sn */
		else if (strcmp(argv[i], "-1") == 0)
		{
			l_sn = argv[++i];
		}
		/* parse action */
		else if (strcmp(argv[i], "-2") == 0)
		{
			l_action = argv[++i];
		}
		/* parse teamid */
		else if (strcmp(argv[i], "-3") == 0)
		{
			l_teamid = argv[++i];
		}
		/* parse ip */
		else if (strcmp(argv[i], "-4") == 0)
		{
			l_vip = argv[++i];
		}
	}
	run_no_debug_init();
	if (pre_init() < 0)
	{
		printf("pre_init failed\n");
		return -1;
	}

	s_pub_topic = init_pub_topic(l_sn);
	s_pub_json = init_pub_json(l_action, l_teamid, l_vip);
	if (s_pub_topic && s_pub_json)
	{
		topic_init();
		ev_signal_init(&sig_watcher, signal_cb, SIGINT);
		ev_signal_start(loop, &sig_watcher);
		
		mg_mgr_init(&mgr, NULL, loop);

		conn_opt.ssl_cert = "/etc/site/cert.pem";
		conn_opt.ssl_key = "/etc/site/key.pem";
		/* disable the server's ca */
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

		ev_timer_init(&keepalive_timer, keepalive_cb, 10, 10);
		
		ev_run(loop, 0);

	err:
		printf("exit...\n");
		topic_exit();	

		mg_mgr_free(&mgr);

	}

	exit_pub_topic(s_pub_topic);
	exit_pub_json(s_pub_json);

	post_exit();

	return 0;
}
