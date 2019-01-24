#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <linux/if.h>
#include <errno.h>

#include <shared.h>

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

/* 设置表中主机的老化时间 */
int ipt_account_set_aging_time_of_table(struct ipt_account_context *ctx)
{
	return ipt_account_set_sockopt(ctx->sockfd, SOCK_SET_ACCOUNT_AGING_TIME, 
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

/*调试打印数据*/
void dump_traffic_data(struct traffic_stat_t data)
{
	if(debug_flag == 1)
	{
		printf("=================================================================================\n");
		printf("today: %llu %llu %llu %s\n", data.today.u_b, data.today.d_b, 
			data.today.t_b, asctime(&data.today.tm_l));
		
		printf("yesterday: %llu %llu %llu %s\n", data.yesterday.u_b, data.yesterday.d_b, 
			data.yesterday.t_b, asctime(&data.yesterday.tm_l));

		printf("week: %llu %llu %llu %d %s\n", data.week.st.u_b, data.week.st.d_b, 
			data.week.st.t_b, data.week.count, asctime(&data.week.st.tm_l));
		
		printf("month: %llu %llu %llu %d %s\n", data.month.st.u_b, data.month.st.d_b, 
			data.month.st.t_b, data.month.count, asctime(&data.month.st.tm_l));

		printf("last_month: %llu %llu %llu %d %s\n", data.last_month.st.u_b, data.last_month.st.d_b, 
			data.last_month.st.t_b, data.last_month.count, asctime(&data.last_month.st.tm_l));
		printf("=================================================================================\n\n");
	}
	return ;
}

void dump_traffic_stat(struct traffic_stat data, char *name)
{
	if(debug_flag == 1)
	{
		printf("######################################################################################\n");
		printf("%s: %llu %llu %llu %s\n", name, data.u_b, data.d_b, data.t_b, asctime(&data.tm_l));
		printf("######################################################################################\n\n");
	}
}

/*将数据写入临时文件中*/
void write_traffic_data_to_file(struct traffic_stat_t data)
{
	FILE *fp = NULL;
	
	fp = fopen(TRAFFIC_METER_DATA_FILE, "w");
	if(fp != NULL)
	{
		fprintf(fp, "start timespec: %ld\n", mktime(&data.month.st.tm_l));

		fprintf(fp, "today: %llu %llu %llu %02d:%02d\n", data.today.u_b, data.today.d_b,
			data.today.t_b, data.today.tm_l.tm_hour, data.today.tm_l.tm_min);

		fprintf(fp, "yesterday: %llu %llu %llu %02d:%02d\n", data.yesterday.u_b, data.yesterday.d_b,
			data.yesterday.t_b, data.yesterday.tm_l.tm_hour, data.yesterday.tm_l.tm_min);

		if(data.week.count <= 0)
			data.week.count = 1;
		fprintf(fp, "week: %llu %llu %llu %d %d %02d:%02d\n", 
			data.week.st.u_b,
			data.week.st.d_b,
			data.week.st.t_b,
			data.week.count,
			data.week.st.tm_l.tm_wday,
			data.week.st.tm_l.tm_hour, 
			data.week.st.tm_l.tm_min);	

		if(data.month.count <= 0)
			data.month.count = 1;
		fprintf(fp, "month: %llu %llu %llu %d %d %02d:%02d\n", 
			data.month.st.u_b,
			data.month.st.d_b,
			data.month.st.t_b,
			data.month.count,
			data.month.st.tm_l.tm_mday,
			data.month.st.tm_l.tm_hour, 
			data.month.st.tm_l.tm_min);
				
		if(data.last_month.count <= 0)
			data.last_month.count = 1;
		fprintf(fp, "last_month: %llu %llu %llu %d %d %02d:%02d\n", 
			data.last_month.st.u_b,
			data.last_month.st.d_b,
			data.last_month.st.t_b,
			data.last_month.count,
			data.last_month.st.tm_l.tm_mday,
			data.last_month.st.tm_l.tm_hour, 
			data.last_month.st.tm_l.tm_min);

		fclose(fp);
	}
	return;
}

/*校验CRC数据*/
uint8_t get_cksum(struct   data_info_t *info, int len)
{
	int i = 0;
	uint8_t cksum = 0;
	uint8_t *data = (uint8_t *)info;

	for(i = 0; i < len; i++)
	{
		cksum += data[i];
	}

	return cksum;
}

/*检查数据的合理性*/
int check_data_is_true(struct data_info_t info)
{
	uint8_t cksum = 0;
	if(info.header != TAG_DATA_HEADER)
	{
		printf("Data tag header is error!\n");
		return 0;
	}

	cksum = get_cksum(&info, sizeof(struct data_info_t) - 1);
	//printf("cksum = 0x%x, file cksum = 0x%x\n", cksum, info.cksum);
	
	dump_traffic_data(info.data);
	if(cksum != info.cksum)
	{	
		printf("Data cksum is error!\n");
		return 0;
	}

	return 1;
}


/*读取上次保存在flash里面的数据*/
int read_data_to_flash(struct data_info_t *info)
{		
	memset(info, 0x0, sizeof(struct data_info_t));
	return flash_mtd_read(DEV_BLOCK_NAME, 0, (unsigned char *)info, sizeof(struct data_info_t));
}


/*将数据保存在flash里面*/
int write_data_to_flash(struct traffic_stat_t data)
{
	struct data_info_t info;

	memset(&info, 0x0, sizeof(struct data_info_t));
	info.header = TAG_DATA_HEADER;
	info.datalen = sizeof(struct traffic_stat_t);
	memcpy(&info.data, &data, info.datalen);
	info.cksum = get_cksum(&info, sizeof(struct data_info_t) - 1);

	dump_traffic_data(data);
	
	return flash_mtd_write(DEV_BLOCK_NAME, 0, (unsigned char *)&info, sizeof(struct data_info_t));
}


void clean_data_to_flash()
{	
	struct data_info_t info;

	memset(&info, 0xff, sizeof(struct data_info_t));
	flash_mtd_write(DEV_BLOCK_NAME, 0, (unsigned char *)&info, sizeof(struct data_info_t));
	return ;
}


