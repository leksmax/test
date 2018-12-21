#ifndef __UTILS_H
#define __UTILS_H

#include <account_sockopt.h>

#ifndef TRAFFIC_METER_DEBUG
#define TRAFFIC_METER_PRINTF(format, args...) printf("[%s:%05d]: "format, __FUNCTION__, __LINE__, ##args);
#else
#define TRAFFIC_METER_PRINTF(format, args...)
#endif
#define IPT_ACCOUNT_MIN_BUFSIZE 4096

struct ipt_account_context
{
	int sockfd;
	struct account_handle_sockopt handle;

	unsigned int data_size;
	void *data;
	char *error_str;
};

/* 初始化sockopt结构体 */
extern int init_sockopt(struct ipt_account_context *ctx);
/* 销毁sockopt结构体 */
extern void destory_sockopt(struct ipt_account_context *ctx);
/* 设置限制表流量大小 */
extern int ipt_account_set_limit_size_of_table(struct ipt_account_context *ctx);
/* 设置表定时清除数据时间 */
extern int ipt_account_set_zero_time_of_table(struct ipt_account_context *ctx);
/* 清除一张表的所有数据 */
extern int ipt_account_clear_data_of_table(int sockfd, unsigned char *name);
/* 清除所有表的所有数据 */
extern int ipt_account_clear_data_of_all_table(int sockfd);
/* 获取所有表的名称 */
extern int ipt_account_get_name_of_table(struct ipt_account_context *ctx);
/* 获取表的所有数据 */
extern int ipt_account_get_data_of_table(struct ipt_account_context *ctx);
#endif // __UTILS_H

