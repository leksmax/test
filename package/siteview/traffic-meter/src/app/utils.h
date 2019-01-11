#ifndef __UTILS_H
#define __UTILS_H

#include <account_sockopt.h>
#include <time.h>

extern int debug_flag;

#define TRAFFIC_METER_PRINTF(format, args...) \
{\
	if(debug_flag) \
		printf("[%s:%05d]: "format, __FUNCTION__, __LINE__, ##args); \
}

#define IPT_ACCOUNT_MIN_BUFSIZE 4096
#define IPT_ACCOUNT_TRAFFIC_NAME		("/proc/net/account/lan")
#define TRAFFIC_METER_PID_FILE			("/var/run/traffic_meter.pid")
#define TRAFFIC_METER_DATA_FILE			("/tmp/traffic_every_month_data")

#define DEV_BLOCK_NAME					("traffic_meter")
#define TAG_DATA_HEADER					(0xeaea)

#define TRAFFIC_METER_COUNT_INTERVAL	10 //s
#define UPDATA_TIME_EVERYDAY			(0 * 3600 + 1 * 60 + 0) //00:01:00

typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;

struct ipt_account_context
{
	int sockfd;
	struct account_handle_sockopt handle;

	unsigned int data_size;
	void *data;
	char *error_str;
};

struct traffic_stat{
	struct tm tm_l;
	unsigned long long u_b; // upload bytes
	unsigned long long d_b; // download bytes
	unsigned long long t_b;	// total bytes
	unsigned long long u_p;	// upload packte
	unsigned long long d_p;	// download packte
	unsigned long long t_p;	// total packte
}__attribute__((packed));

struct traffic_stat_c{
	int count;
	struct traffic_stat st;
}__attribute__((packed));

struct traffic_stat_t{
	struct traffic_stat today;
	struct traffic_stat yesterday;
	struct traffic_stat_c week;
	struct traffic_stat_c month;
	struct traffic_stat_c last_month;
}__attribute__((packed));

struct traffic_param_t{
	int limit_dire;
	int limit_size;
	int zero_sec;
	char table_name[IPT_ACCOUNT_NAME_LEN + 1];
};

struct data_info_t{
	uint16_t header;
	uint16_t datalen;
	struct traffic_stat_t data;
	uint8_t cksum;
}__attribute__((packed));

enum{NOT_LIMIT, LIMIT_UPLOAD, LIMIT_DOWNLOAD, LIMIT_ALL};
enum{HANDLE_CLOSE, HANDLE_OPEN, HANDLE_CLEAR};

/* 初始化sockopt结构体 */
extern int init_sockopt(struct ipt_account_context *ctx);
/* 销毁sockopt结构体 */
extern void destory_sockopt(struct ipt_account_context *ctx);

/* 设置限制表双向流量大小 */
int ipt_account_set_all_limit_size_of_table(struct ipt_account_context *ctx);
/* 设置限制表上传流量大小 */
int ipt_account_set_upload_limit_size_of_table(struct ipt_account_context *ctx);
/* 设置限制表下载流量大小 */
int ipt_account_set_download_limit_size_of_table(struct ipt_account_context *ctx);
/* 关闭限制 */
int  ipt_account_set_not_limit_size_of_table(struct ipt_account_context *ctx);
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
/* 读取统计到的流量信息 */
extern void read_table_all_data(struct account_handle_sockopt *handle);
extern void get_current_systime(struct tm *tm_cur);

#endif // __UTILS_H

