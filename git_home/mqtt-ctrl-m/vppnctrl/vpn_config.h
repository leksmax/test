#ifndef __VPN_CONFIG_H__
#define __VPN_CONFIG_H__

#define VPN_PORT_LOCAL_BASE (1000)
#define VPN_PORT_SERVER_BASE (50059)


#define	ACTION_RUN		(0)
#define	ACTION_KILL		(1)
#define ACTION_START	(2)
#define ACTION_STOP		(3)
#define ACTION_RELOAD	(4)
#define ACTION_DNS_REPORT_LOOP (5)
#define ACTION_SET_DEBUG_LEVEL	(6)

#define	TUNNEL_DISABLE	(0)
#define	TUNNEL_READY	(1)
#define	TUNNEL_SELECT_SERVER	(2)
#define	TUNNEL_GET_RESOURCE		(3)
#define	TUNNEL_CONNECT			(4)
#define	TUNNEL_DONE				(5)

#ifdef __cplusplus
extern "C" {
#endif

struct vpn_resource_s
{
	int		error;
	char	teamid[32];
	char	error_code[32];
	char	vpn_server_host[32];
	int		vpn_server_port;
	char	vpn_subnet[32];
	char	vpn_ip[32];
	char	vpn_pubkey[1024];
	char	vpn_prikey[1024];
	int		resource_id;
};

struct vpn_package_s
{
	char	endtime[32];
	char	flow[32];
	char	mac[32];
	char	type[32];
};

struct vpn_tunnel_info_s
{
	int						status;
	int						enable;
	int						connect_time;
	int						connect_fail_time;
	double					latency;
	struct vpn_resource_s	resource;
	struct vpn_package_s	package;
};

struct vpn_tunnel_s
{
	int		tunnel_on;
	int		tunnel_id;
	int		tunnel_type;		/* 0:game, 1:web and more in future */
	int		auto_mode;			/* 0:non-auto_mode, 1:auto_mode */
	char	tunnel_vpn_server[32];	/* if in non-auto_mode, the vpn will
								 * connect to the tunnel_vpn_server; if in
								 * auto_mode, the client will select
								 * a vpn server based on some rules
								 * */
	char	tunnel_vpn_server_port[32];
	char	tunnel_vpn_country[32];
	char	tunnel_relay_name[32];
	int		tunnel_relay_limit;
	int		tunnel_public;	/* 1:tunnel has public ip, can be connected directly by public ip */
	int		last_select_code;
	int		last_heartbeat_code;
	struct vpn_tunnel_info_s	info;
	int							log_level;
	int							log_on;
	char	tunnel_dev[32];
};

struct vpn_tunnel_set_s
{
	int						tunnel_num;
	struct	vpn_tunnel_s*	each_tunnel;
};

struct vpn_config_s
{
	char						self_id[64];
	char						team_id[64];
	char						cloud_host[64];
	int							cloud_port;
	struct vpn_tunnel_s			tunnel;
	int							debug;
	int							tunnel_type;	/* 0 for vpn, 1 for vppn */
	char						custom_wan_if[32];
	char						custom_lan_if[32];
	char						custom_tunnel_dev[32];
};

/**
 * @brief  :load the vppn config from arguments and config file
 *
 * @Param  :config
 * @Param  :argc
 * @Param  :argv
 * @Param  :action
 * @Param  :tunnel_id
 *
 * @Returns  :
 */
int vpn_config_load(struct vpn_config_s *config, int argc, char **argv, int *action, int *tunnel_id);


/**
 * @brief  :reload the vppn config from config file
 *
 * @Param  :config
 * @Param  :tunnel_id
 *
 * @Returns  :
 */
int vpn_tunnel_reload_config(struct vpn_config_s *config, int tunnel_id, int conf_type);
#ifdef __cplusplus
}
#endif
#endif
