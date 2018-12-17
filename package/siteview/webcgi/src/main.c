
/*
 * WEB CGI
 *
 * 基本返回格式:
 *      '{"code":0,data:{""}}'
 *      
 *      code: 状态码，表示接口调用是否成功，也包含认证状态
 *      data: 数据部分，接口需要返回的数据 
 *
 * POST基本格式:
 *      '{"method":"get|set|add|del","params":{}}'
 *
 *      method: 查询数据为get，设置参数为set
 *      params: 参数部分，接口需要的参数
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "servlet.h"
#include "utils.h"

#include "auth.h"
#include "system.h"
#include "network.h"
#include "wireless.h"

int cgi_errno = CGI_ERR_OK;

int handle_common(cgi_request_t *req, cgi_response_t *resp)
{
    webs_json_header(req->out);
    webs_write(req->out, "{\"code\":0,\"data\":{}}");
    return 0;
}

static cgi_handler_t handlers[] = {
    /* login */
    { .url = "/do_login", .handler = handle_login, .auth = PRIV_NONE },
    { .url = "/get_login_info", .handler = get_login_info, = PRIV_GUEST | PRIV_ADMIN },
    { .url = "/do_logout", .handler = handle_logout, .auth = PRIV_GUEST | PRIV_ADMIN },
    /* status */
    { .url = "/get_port_status", .handler = handle_common, .auth = PRIV_GUEST | PRIV_ADMIN },  /* 端口状态，link，duplex，speed */
    { .url = "/get_system_status", .handler = handle_common, .auth = PRIV_GUEST | PRIV_ADMIN },
    { .url = "/attached_devices", .handler = handle_common, .auth = PRIV_GUEST | PRIV_ADMIN },
    /* vlan */
    { .url = "/get_vlan_entry", .handler = handle_common, .auth = PRIV_GUEST | PRIV_ADMIN },
    { .url = "/vlan_entry_config", .handler = handle_common, .auth = PRIV_ADMIN },
    { .url = "/port_vlan_list", .handler = handle_common, .auth = PRIV_GUEST | PRIV_ADMIN },
    { .url = "/port_vlan_config", .handler = handle_common, .auth = PRIV_ADMIN },
    /* lan */
    { .url = "/get_interface_lan", .handler = get_interface_lan, .auth = PRIV_GUEST | PRIV_ADMIN },
    { .url = "/get_lan_status", .handler = handle_common, .auth = PRIV_GUEST | PRIV_ADMIN },
    { .url = "/get_lan_config", .handler = get_lan_config, .auth = PRIV_GUEST | PRIV_ADMIN },
    { .url = "/set_lan_config", .handler = set_lan_config, .auth = PRIV_ADMIN },
    /* wan */
    { .url = "/get_interface_wan", .handler = get_interface_wan, .auth = PRIV_GUEST | PRIV_ADMIN },
    { .url = "/get_wan_status", .handler = handle_common, .auth = PRIV_GUEST | PRIV_ADMIN },
    { .url = "/get_wan_config", .handler = get_wan_config, .auth = PRIV_GUEST | PRIV_ADMIN },
    { .url = "/set_wan_config", .handler = set_wan_config, .auth = PRIV_ADMIN },
    /* ipv6 */
    { .url = "/get_lan6_config", .handler = handle_common, .auth = PRIV_ADMIN },
    /* wireless */
    { .url = "/get_regdmn_list", .handler = get_regdmn_list, .auth = PRIV_GUEST | PRIV_ADMIN },
    { .url = "/get_wifi_config", .handler = get_wifi_config, .auth = PRIV_GUEST | PRIV_ADMIN },
    { .url = "/set_wifi_config", .handler = set_wifi_config, .auth = PRIV_ADMIN },
    /* route */
    { .url = "/static_route_list", .handler = get_wifi_config, .auth = PRIV_GUEST | PRIV_ADMIN },
    { .url = "/static_route_config", .handler = set_wifi_config, .auth = PRIV_ADMIN },    
    /* ipsec */
    { .url = "/get_ipsec_policy", .handler = handle_common, .auth = PRIV_GUEST | PRIV_ADMIN },
    { .url = "/ipsec_policy_config", .handler = handle_common, .auth = PRIV_ADMIN },
    /* ddns */
    { .url = "/get_ddns_services", .handler = handle_common, .auth = PRIV_GUEST | PRIV_ADMIN },
    { .url = "/get_ddns_config", .handler = handle_common, .auth = PRIV_GUEST | PRIV_ADMIN },
    { .url = "/set_ddns_config", .handler = handle_common, .auth = PRIV_ADMIN },
    /* upnpd */
    { .url = "/get_upnpd_rules", .handler = handle_common, .auth = PRIV_GUEST | PRIV_ADMIN },
    { .url = "/get_upnpd_config", .handler = handle_common, .auth = PRIV_GUEST | PRIV_ADMIN },
    { .url = "/set_upnpd_config", .handler = handle_common, .auth = PRIV_ADMIN },
    /* firewall */
    { .url = "/port_forward_list", .handler = handle_common, .auth = PRIV_GUEST | PRIV_ADMIN },
    { .url = "/port_forward_config", .handler = handle_common, .auth = PRIV_ADMIN },    
    { .url = "/port_trigger_list", .handler = handle_common, .auth = PRIV_GUEST | PRIV_ADMIN },
    { .url = "/port_trigger_config", .handler = handle_common, .auth = PRIV_ADMIN },
    /* firmware */
    { .url = "/upgrade_check", .handler = upgrade_check, .auth = PRIV_ADMIN },
    { .url = "/firmware_upgrade", .handler = firmware_upgrade, .auth = PRIV_ADMIN },
    /* system */
    { .url = "/do_reboot", .handler = do_reboot, .auth = PRIV_ADMIN },
    { .url = "/factory_reset", .handler = do_factory_reset, .auth = PRIV_ADMIN },
    { .url = "/backup_config", .handler = do_backup_config, .auth = PRIV_ADMIN },
    { .url = "/restore_config", .handler = do_restore_config, .auth = PRIV_ADMIN },
    /* syslog */
    { .url = "/get_syslog_info", .handler = handle_common, .auth = PRIV_GUEST | PRIV_ADMIN },
    { .url = "/clear_syslog_info", .handler = handle_common, .auth = PRIV_ADMIN },
    { .url = "/get_syslog_config", .handler = upgrade_check, .auth = PRIV_ADMIN },
    { .url = "/set_syslog_config", .handler = handle_common, .auth = PRIV_ADMIN },
    /* ntp */
    { .url = "/get_ntp_config", .handler = handle_common, .auth = PRIV_GUEST | PRIV_ADMIN },
    { .url = "/set_ntp_config", .handler = handle_common, .auth = PRIV_ADMIN },
    { .url = "/sync_current_time", .handler = handle_common, .auth = PRIV_ADMIN },
    { /* terminating entry */ }
};

int main(int argc, char *argv[])
{
    return cgi_servlet_init(handlers);
}
