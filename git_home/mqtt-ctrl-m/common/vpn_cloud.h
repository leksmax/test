#ifndef __VPN_CLOUD_H__
#define __VPN_CLOUD_H__

#include <stdio.h>
#include "cJSON.h"

#define	ERROR_OK					(0)
#define	ERROR_CLOUD_UNREACHABLE		(-1)
#define	ERROR_SELECT_NO_RESOURCE	(-2)
#define	ERROR_PACKAGE_FLOW			(-3)
#define	ERROR_HEARTBEAT_RECONNECT   (-4)

struct vpu_cloud_s
{
	char	cloud_host[30];
	int		cloud_port;
};

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief  :a simple client that can communicate to cloud manager with plain text
 *
 * @Param  :req
 * @Param  :cloud_host
 * @Param  :cloud_port
 * @Param  :uri
 *
 * @Returns  :
 */
cJSON *vpn_cloud_tool(cJSON *req, char *cloud_host, int cloud_port, char *uri);
cJSON *vpn_cloud_tool2(char *uri, cJSON *req);
cJSON *vpn_cloud_tool3(char *uri, cJSON *req);


/**
 * @brief  :a simple client that can communicate to cloud manager with gzip text
 *
 * @Param  :req
 * @Param  :cloud_host
 * @Param  :cloud_port
 * @Param  :uri
 *
 * @Returns  :
 */
cJSON *vpn_cloud_tool_gzip(cJSON *req, char *cloud_host, int cloud_port, char *uri);


#ifdef __cplusplus
}
#endif

#endif
