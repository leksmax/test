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

/* 设置限制表双向流量大小 */
int ipt_account_set_all_limit_size_of_table(struct ipt_account_context *ctx)
{
	return ipt_account_set_sockopt(ctx->sockfd, SOCK_SET_ACCOUNT_ALL_LIMIT_SIZE, 
				&ctx->handle, sizeof(struct account_handle_sockopt));
}

/* 设置限制表上传流量大小 */
int ipt_account_set_upload_limit_size_of_table(struct ipt_account_context *ctx)
{
	return ipt_account_set_sockopt(ctx->sockfd, SOCK_SET_ACCOUNT_SRC_LIMIT_SIZE, 
				&ctx->handle, sizeof(struct account_handle_sockopt));
}

/* 设置限制表下载流量大小 */
int ipt_account_set_download_limit_size_of_table(struct ipt_account_context *ctx)
{
	return ipt_account_set_sockopt(ctx->sockfd, SOCK_SET_ACCOUNT_DST_LIMIT_SIZE, 
				&ctx->handle, sizeof(struct account_handle_sockopt));
}

/* 关闭限制 */
int  ipt_account_set_not_limit_size_of_table(struct ipt_account_context *ctx)
{
	return ipt_account_set_sockopt(ctx->sockfd, SOCK_SET_ACCOUNT_NOT_LIMIT_SIZE, 
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

/* 同步表数据 */
int ipt_account_sync_data_of_table(struct ipt_account_context *ctx)
{
	return ipt_account_set_sockopt(ctx->sockfd, SOCK_SET_ACCOUNT_SYNC_ALL_DATA, 
			&ctx->handle, sizeof(struct account_handle_sockopt));
}

/* 获取所有表的名称 */
int ipt_account_get_name_of_table(struct ipt_account_context *ctx)
{
	return ipt_account_get_sockopt(ctx->sockfd, SOCK_GET_ACCOUNT_TABLE_LIST, ctx->data, ctx->data_size);
}

/* 获取表的所有数据 */
int ipt_account_get_data_of_table(struct ipt_account_context *ctx)
{
	memcpy(ctx->data, &ctx->handle, sizeof(struct account_handle_sockopt));
	if(ctx->data_size < sizeof(sizeof(struct account_handle_sockopt)))
		ctx->data_size = sizeof(struct account_handle_sockopt);
	return ipt_account_get_sockopt(ctx->sockfd, SOCK_GET_ACCOUNT_TABLE_DATA, ctx->data, ctx->data_size);		
}

/* 读取统计到的流量信息 */
void read_table_all_data(struct account_handle_sockopt *handle)
{
	strncpy(handle->name, "lan", sizeof(handle->name));
	handle->data.info.dst_bytes = 123123;
	handle->data.info.dst_packet = 23;
	handle->data.info.src_bytes = 234234;
	handle->data.info.src_packet = 34;
	handle->data.info.total_bytes = 357357;
	handle->data.info.total_packet = 57;
	handle->data.info.timespec = 111111111;
	return ;
}

/*获取当前系统时间*/
void get_current_systime(struct tm *tm_cur)
{
	time_t t;
	struct tm *tm_tmp;

	time(&t);
	
	tm_tmp = localtime(&t);

	if(tm_cur != NULL)
		memcpy(tm_cur, tm_tmp, sizeof(struct tm));
	
	return ;
}

