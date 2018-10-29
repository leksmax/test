#ifndef __VPN_CLOUD_H__
#define __VPN_CLOUD_H__

#include <stdio.h>
#include "cJSON.h"

struct vpu_cloud_s
{
	char	cloud_host[30];
	int		cloud_port;
};

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

#endif
