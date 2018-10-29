/*
 * ctrl_server.h
 *
 *  Created on: Jun 2, 2017
 *      Author: pp
 */

#ifndef CTRL_SERVER_H_
#define CTRL_SERVER_H_

#include <pthread.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif
struct ctrl_server_s
{
	int listen_fd;
	pthread_t loop_tid;
	int req_cnt;
	int res_cnt;
};
typedef struct ctrl_server_s ctrl_server_t;

struct ctrl_request_s
{
	int 	client_fd;
	void 	*data;
	int 	data_size;
};
typedef struct ctrl_request_s ctrl_request_t;

struct ctrl_response_s
{
	int		client_fd;
	void 	*data;
	int 	data_size;
};
typedef struct ctrl_response_s ctrl_response_t;

int ctrl_server_init(char *host, u_short port);
void ctrl_server_exit();

#ifdef __cplusplus
}
#endif

#endif /* CTRL_SERVER_H_ */
