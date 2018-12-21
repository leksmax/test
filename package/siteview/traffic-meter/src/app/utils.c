#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <linux/if.h>

#include "utils.h"

int init_sockopt(struct ipt_account_context *ctx)
{
	memset(ctx, 0, sizeof(struct ipt_account_context));

	ctx->sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (ctx->sockfd < 0) {
		ctx->sockfd = -1;
		ctx->error_str = "Can't open socket to kernel. "
		                 "Permission denied or ipt_ACCOUNT module not loaded";
		return -1;
	}

	// 4096 bytes default buffer should save us from reallocations
	// as it fits 200 concurrent active clients
	if ((ctx->data = malloc(IPT_ACCOUNT_MIN_BUFSIZE)) == NULL) {
		close(ctx->sockfd);
		ctx->sockfd = -1;
		ctx->error_str = "Out of memory for data buffer";
		return -1;
	}
	ctx->data_size = IPT_ACCOUNT_MIN_BUFSIZE;

	return 0;
}
/* 销毁sockopt结构体 */
void destory_sockopt(struct ipt_account_context *ctx)
{
	free(ctx->data);
	ctx->data = NULL;

	close(ctx->sockfd);
	ctx->sockfd = -1;
	return ;
}

int ipt_account_set_sockopt(int sockfd, int action, void *data, size_t data_size)
{
	return setsockopt(sockfd, IPPROTO_IP, action, data, data_size);
}

int ipt_account_get_sockopt(int sockfd, int action, void *data, size_t data_size)
{
	return getsockopt(sockfd, IPPROTO_IP, action, data, &data_size);
}

/* 清除一张表的所有数据 */
int ipt_account_clear_data_of_table(int sockfd, unsigned char *name)
{
	if(name != NULL)
	{
		return ipt_account_set_sockopt(sockfd, SOCK_SET_ACCOUNT_CLEAR_ONE_DATA, name, strlen(name) + 1);
	}
}

int ipt_account_set_limit_size_of_table(struct ipt_account_context *ctx)
{
	return ipt_account_set_sockopt(ctx->sockfd, SOCK_SET_ACCOUNT_LIMIT_SIZE, 
				&ctx->handle, sizeof(struct account_handle_sockopt));
}

/* 设置表定时清除数据时间 */
int ipt_account_set_zero_time_of_table(struct ipt_account_context *ctx)
{
	return ipt_account_set_sockopt(ctx->sockfd, SOCK_SET_ACCOUNT_ZERO_TIME, 
				&ctx->handle, sizeof(struct account_handle_sockopt));
}

/* 清除所有表的所有数据 */
int ipt_account_clear_data_of_all_table(int sockfd)
{
	return ipt_account_set_sockopt(sockfd, SOCK_SET_ACCOUNT_CLEAR_ALL_DATA, NULL, 0);
}

/* 获取所有表的名称 */
int ipt_account_get_name_of_table(struct ipt_account_context *ctx)
{
	return ipt_account_get_sockopt(ctx->sockfd, SOCK_GET_ACCOUNT_TABLE_LIST, ctx->data, ctx->data_size);
}
/* 获取表的所有数据 */
int ipt_account_get_data_of_table(struct ipt_account_context *ctx)
{
	return ipt_account_get_sockopt(ctx->sockfd, SOCK_GET_ACCOUNT_TABLE_DATA, ctx->data, ctx->data_size);		
}


