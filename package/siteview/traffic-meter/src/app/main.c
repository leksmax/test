
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>

#include "utils.h"

static int daemon_flag = 1;
static int zero_sec = 0;
static unsigned char table_name[IPT_ACCOUNT_NAME_LEN + 1] = {0};
static struct ipt_account_context g_ctx;
int debug_flag = 0;

static struct traffic_stat last_day;
static struct traffic_stat last_week;
static struct traffic_stat last_month;
struct traffic_stat_t g_stat_data;

static pthread_mutex_t mutex;

void show_usage(char *name)
{
	printf("%s\n"
		"	[set [limit_all|limit_src|limit_dst name size | zero_time name time]]"
		"		set paramter of table\n"
		"	[get [table_name|table_data name] get data of table\n"
		"	[clear name] clear all data of table\n"
		"	[clearall] clear all data of all table\n"
		"	[sync] sync data to kernel\n"
		"	-f, close daemon\n"
		"	-D, open debug info\n"
		"	-a, table name\n"
		"	-h, print this help\n"
		,name);
	return ;
}

void process_exit()
{	
	destory_sockopt(&g_ctx);
	pthread_mutex_destroy(&mutex);
	unlink(TRAFFIC_METER_PID_FILE);
	exit(0);
}

void handle_over_limit_bytes(int action)
{
	if(action == HANDLE_CLOSE)
	{
		//printf("handle close\n");
		system("/lib/traffic/traffic_meter.script stop");
	}
	else
	{
		//printf("handle open\n");
		system("/lib/traffic/traffic_meter.script start");
	}
	return ;
}

void clear_traffic_stat(struct traffic_stat *stat)
{
	get_current_systime(&stat->tm_l);
	stat->d_b = 0;	
	stat->u_b = 0;
	stat->t_b = 0;
	stat->d_p = 0;
	stat->u_p = 0;
	stat->t_p = 0;
	return ;
}

void clear_all_traffic_data()
{
	pthread_mutex_lock(&mutex);
	clear_traffic_stat(&g_stat_data.today);
	clear_traffic_stat(&g_stat_data.yesterday);
	clear_traffic_stat(&g_stat_data.week.st);
	clear_traffic_stat(&g_stat_data.month.st);
	clear_traffic_stat(&last_day);
	clear_traffic_stat(&last_week);
	clear_traffic_stat(&last_month);
	g_stat_data.week.count = 0;
	g_stat_data.month.count = 0;
	g_stat_data.last_month.count = 0;
	unlink(TRAFFIC_METER_DATA_FILE);
	printf("12333333333333333\n");
	pthread_mutex_unlock(&mutex);
	
	return ;
}

void sig_handler(int signo)
{
	switch(signo)
	{
		case SIGINT:
		case SIGTERM:
			process_exit();
			break;
		case SIGUSR1:
			/* 使用流量超出，做出相对的处理 */
			handle_over_limit_bytes(HANDLE_OPEN);
			break;
		case SIGUSR2:
			handle_over_limit_bytes(HANDLE_CLOSE);
			break;
		case SIGIO:
			clear_all_traffic_data();
			break;
		default:
			return ;
	}

	return ;
}

void init_sigaction()
{
	struct sigaction act;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	act.sa_handler = sig_handler;

	sigaction(SIGINT, &act, NULL);
	sigaction(SIGTERM, &act, NULL);
	sigaction(SIGUSR1, &act, NULL);
	sigaction(SIGUSR2, &act, NULL);
	sigaction(SIGIO, &act, NULL);
	
	return ;
}

void save_pid_to_file()
{
	FILE *fp = NULL;
	pid_t pid = getpid();

	TRAFFIC_METER_PRINTF("pid = %d\n", pid);
	fp = fopen(TRAFFIC_METER_PID_FILE, "w");
	if(fp != NULL)
	{
		fprintf(fp, "%d", pid); 
		fclose(fp);
	}
	return ;
}

void handle_paramter(int argc, char *argv[])
{
	int ch = 0;

	while( (ch = getopt(argc, argv, "fDha:")) != -1 )
	{
		switch(ch)
		{
			case 'f':
				daemon_flag = 0;
				break;
			case 'D':
				debug_flag = 1;
				break;
			case 'a':
				if(optarg != NULL)
					strncpy(table_name, optarg, sizeof(table_name));
				break;
			case 'h':
				show_usage(argv[0]);
				exit(1);
				break;
			default:
				exit(1);
		}
	}
	
}

int init_sockopt_function(int argc, char *argv[])
{
	int ret = 0;
	struct ipt_account_context ctx;
	
	if(init_sockopt(&ctx) < 0)
	{
		printf("init sockopt failed!\n");
		return -1;
	}
	
	if(strcmp(argv[1], "set") == 0)
	{
		if(argc < 5)
		{
			show_usage(argv[0]);
			goto cleanup_ok;
		}
		if(strcmp(argv[2], "limit_all") == 0)
		{
			if(argv[3] != NULL)
			{
				strncpy(ctx.handle.name, argv[3], sizeof(ctx.handle.name));
				ctx.handle.data.size = atoll(argv[4]);
			}
			ret = ipt_account_set_all_limit_size_of_table(&ctx);
			goto cleanup_ok;
		}
		else if(strcmp(argv[2], "limit_src") == 0)
		{
			if(argv[3] != NULL)
			{
				strncpy(ctx.handle.name, argv[3], sizeof(ctx.handle.name));
				ctx.handle.data.size = atoll(argv[4]);
			}
			ret = ipt_account_set_upload_limit_size_of_table(&ctx);
			goto cleanup_ok;
		}
		else if(strcmp(argv[2], "limit_dst") == 0)
		{
			if(argv[3] != NULL)
			{
				strncpy(ctx.handle.name, argv[3], sizeof(ctx.handle.name));
				ctx.handle.data.size = atoll(argv[4]);
			}
			ret = ipt_account_set_download_limit_size_of_table(&ctx);
			goto cleanup_ok;
		}
		else if(strcmp(argv[2], "limit_not") == 0)
		{
			if(argv[3] != NULL)
			{
				strncpy(ctx.handle.name, argv[3], sizeof(ctx.handle.name));
				ctx.handle.data.size = atoll(argv[4]);
			}
			ret = ipt_account_set_not_limit_size_of_table(&ctx);
			goto cleanup_ok;
		}
		else if(strcmp(argv[2], "zero_time") == 0)
		{
			if(argv[3] != NULL)
			{
				strncpy(ctx.handle.name, argv[3], sizeof(ctx.handle.name));
				ctx.handle.data.size = atoll(argv[4]);
			}			
			ret = ipt_account_set_zero_time_of_table(&ctx);
			goto cleanup_ok;
		}
		goto cleanup_ok;
	}
	else if(strcmp(argv[1], "get") == 0)
	{
		if(argc < 3)
		{
			show_usage(argv[0]);
			goto cleanup_ok;
		}
		
		if(strcmp(argv[2], "table_name") == 0)
		{
			ret = ipt_account_get_name_of_table(&ctx);
			if(ret == 0)
			{
				printf("table: %s\n", ctx.data);
			}
		}
		else if(strncmp(argv[2], "table_data", 10) == 0)
		{
			if(argv[3] == NULL)
			{
				show_usage(argv[0]);
				goto cleanup_ok;
			}
			strncpy(ctx.handle.name, argv[3], sizeof(ctx.handle.name));
			ret = ipt_account_get_data_of_table(&ctx);
			if(ret == 0)
			{
				struct traffic_meter_info *data = (struct traffic_meter_info *)ctx.data;
				printf("%llu %llu %llu %llu %llu %llu %llu\n", data->src_packet, data->src_bytes,
					data->dst_packet, data->dst_bytes, data->total_packet, data->total_bytes, data->timespec);
			}
		}
		goto cleanup_ok;
	}
	else if(strcmp(argv[1], "clear") == 0)
	{
		if(argc < 3)
		{
			show_usage(argv[0]);
			goto cleanup_ok;
		}
		ret = ipt_account_clear_data_of_table(ctx.sockfd, argv[2]);
		goto cleanup_ok;
	}
	else if(strcmp(argv[1], "clearall") == 0)
	{
		ret = ipt_account_clear_data_of_all_table(ctx.sockfd);
		goto cleanup_ok;
	}
	else if(strcmp(argv[1], "sync") == 0)
	{
		read_table_all_data(&ctx.handle);
		ret = ipt_account_sync_data_of_table(&ctx);
		
		goto cleanup_ok;
	}
	
cleanup_ok:	
	destory_sockopt(&ctx);
	return ret;

}

int get_traffic_data_by_sockopt(struct ipt_account_context *ctx)
{		
	strncpy(ctx->handle.name, table_name, sizeof(ctx->handle.name));
	return ipt_account_get_data_of_table(ctx);	
}

void get_traffic_stat(struct traffic_meter_info *info, struct traffic_stat *st)
{
	memset(st, 0x0, sizeof(struct traffic_stat));
	get_current_systime(&st->tm_l);
	st->d_b = info->dst_bytes;
	st->u_b = info->src_bytes;
	st->t_b = info->total_bytes;	
	st->d_p = info->dst_packet;
	st->u_p = info->src_packet;
	st->t_p = info->total_packet;
	return ;
}

void init_traffic_stat_data()
{
	struct traffic_meter_info *info = NULL;

	get_traffic_data_by_sockopt(&g_ctx);

	info = (struct traffic_meter_info *)g_ctx.data;
	if(info != NULL)
	{
		get_traffic_stat(info, &last_day);		
		get_traffic_stat(info, &last_week);		
		get_traffic_stat(info, &last_month);
	}
	
	memset(&g_stat_data, 0x0, sizeof(struct traffic_stat_t));
	return ;
}

/*读取上次保存在flash里面的数据*/
int read_data_to_flash(struct traffic_stat_t *data)
{
	int len = 0;
	int fd = 0;

	if(data == NULL)
	{
		printf("data is null!\n");
		return -1;
	}
	
	memset(data, 0x0, sizeof(struct traffic_stat_t));
	fd = open(SAVE_TO_FLASH_OF_FLIE,  O_RDONLY);
	if(fd < 0)
	{
		printf("open %s file failed!\n", SAVE_TO_FLASH_OF_FLIE);
		return -1;
	}

	len = read(fd, data, sizeof(struct traffic_stat_t));

	close(fd);

	if(len <= 0)
	{
		printf("read %s filed!\n", SAVE_TO_FLASH_OF_FLIE);
		return -1;
	}
	
	return 0;
}


/*将数据保存在flash里面*/
int write_data_to_flash(struct traffic_stat_t data)
{
	int len = 0;
	int fd = 0;

	fd = open(SAVE_TO_FLASH_OF_FLIE,  O_WRONLY | O_CREAT);
	if(fd < 0)
	{
		printf("open %s file failed!\n", SAVE_TO_FLASH_OF_FLIE);
		return -1;
	}

	len = write(fd, &data, sizeof(struct traffic_stat_t));

	close(fd);

	if(len <= 0)
	{
		printf("write %s filed!\n", SAVE_TO_FLASH_OF_FLIE);
		return -1;
	}
	
	return 0;
}

void copy_traffic_data(struct traffic_stat *dst, struct traffic_stat *src)
{
	memcpy(&dst->tm_l, &src->tm_l, sizeof(struct tm));
	dst->d_b = src->d_b;
	dst->u_b = src->u_b;
	dst->t_b = src->t_b;	
	dst->d_p = src->d_p;
	dst->u_p = src->u_p;
	dst->t_p = src->t_p;

	return ;
}

void counter_traffic_data(struct traffic_stat *dst, struct traffic_meter_info *info, 
	struct traffic_stat last)
{
	memcpy(&dst->tm_l, &last.tm_l, sizeof(struct tm));
	
	dst->u_b = info->src_bytes - last.u_b;
	dst->d_b = info->dst_bytes - last.d_b;
	dst->t_b = info->total_bytes - last.t_b;	
	dst->d_p = info->src_packet - last.u_p;
	dst->u_p = info->dst_packet - last.d_p;
	dst->t_p = info->total_packet - last.t_p;
	return ;
}


int get_month_max_day(int year, int month)
{
	switch(month)
	{
		case 1:
		case 3:
		case 5:
		case 7:
		case 8:
		case 10:
		case 12:
			return 31;
		case 4:
		case 6:
		case 9:
		case 11:
			return 30;
		case 2:
			if( ((year % 4) == 0 && (year % 100) != 0) || (year % 400) == 0 )
				return 29;
			else
				return 28;
		default:
			return 31;
	}
}

void sync_data_to_kernel(struct traffic_stat data)
{
	struct ipt_account_context ctx;

	if (init_sockopt(&ctx) < 0)
	{
		printf("sync data to kernel failed!\n");
		return ;
	}

	strncpy(ctx.handle.name, table_name, sizeof(ctx.handle.name));
	ctx.handle.data.info.dst_bytes = data.d_b;
	ctx.handle.data.info.dst_packet = data.d_p;
	ctx.handle.data.info.src_bytes = data.u_b;
	ctx.handle.data.info.src_packet = data.u_p;
	ctx.handle.data.info.total_bytes = data.t_b;
	ctx.handle.data.info.total_packet = data.t_p;
	ctx.handle.data.info.timespec = mktime(&data.tm_l);

	ipt_account_sync_data_of_table(&ctx);

	destory_sockopt(&ctx);
	return;
}

void sync_all_data(struct traffic_stat_t data)
{
	int max_day_month = 0;
	struct tm today;

	get_current_systime(&today);

	/*如果上次的数据这个月时间和现在时间是同一个月，
		就将数据同步这个月*/
	if(data.month.st.tm_l.tm_year == today.tm_year)
	{
		if(data.month.st.tm_l.tm_mon == today.tm_mon)
		{
			copy_traffic_data(&g_stat_data.last_month.st, &data.last_month.st);
			g_stat_data.last_month.count = data.last_month.count;
			memcpy(&last_month.tm_l, &data.month.st.tm_l, sizeof(struct tm));

			/*如果上次数据的今天和今天是同一天, 就将今天和昨天的数据更新*/
			if(data.today.tm_l.tm_mday == today.tm_mday)
			{
				copy_traffic_data(&g_stat_data.yesterday, &data.yesterday);
				memcpy(&last_day.tm_l, &data.today.tm_l, sizeof(struct tm));
			}

			max_day_month = get_month_max_day(today.tm_year + 1900, today.tm_mon + 1);
			/*如果上次数据的今天和今天是差一天, 就将昨天的数据更新*/
			if(abs(today.tm_mday -data.today.tm_l.tm_mday) == 1 ||
				abs(today.tm_mday - data.today.tm_l.tm_mday) == max_day_month)
			{
				copy_traffic_data(&g_stat_data.yesterday, &data.today);
			}

			if( (data.week.st.tm_l.tm_wday == 0 && today.tm_mday == data.week.st.tm_l.tm_mday) ||
				(data.week.st.tm_l.tm_wday != 0 && abs(today.tm_mday - data.week.st.tm_l.tm_mday) == (today.tm_wday - data.week.st.tm_l.tm_wday)))
			{
				memcpy(&last_week.tm_l, &data.week.st.tm_l, sizeof(struct tm));
			}
				
			/*同步这个月的数据同步到内核*/
			sync_data_to_kernel(data.month.st);

		}
		/*如果上次的数据这个月时间和现在时间是差一个月，
			就将数据同步到上个月*/
		if( abs(today.tm_mon - data.month.st.tm_l.tm_mon) == 1 ||
			abs(today.tm_mon - data.month.st.tm_l.tm_mon) == 11)
		{
			copy_traffic_data(&g_stat_data.last_month.st, &data.month.st);
			g_stat_data.last_month.count = data.month.count;
		}
	}
}


void init_global_data()
{	
	struct traffic_stat_t data;

	pthread_mutex_init(&mutex, NULL);
	/*初始化全局sockopt*/
	init_sockopt(&g_ctx);
	
	/*初始化traffic全局数据*/
	init_traffic_stat_data();
	
	/*读取上次保存在flash里面的数据同步内核数据*/
	if(read_data_to_flash(&data) == 0)
	{
		pthread_mutex_lock(&mutex);
		/*同步数据*/
		sync_all_data(data);
		pthread_mutex_unlock(&mutex);
	}

	
	return ;
}

void count_day_traffic_data(struct traffic_meter_info *info, struct tm *today)
{
	/*今天的00:01:00更新上次数据*/
	int sec = today->tm_hour * 3600 + today->tm_min * 60 + today->tm_sec;
	if(abs(UPDATA_TIME_EVERYDAY - sec) < TRAFFIC_METER_COUNT_INTERVAL)
	{
		copy_traffic_data(&g_stat_data.yesterday, &g_stat_data.today);
		get_traffic_stat(info, &last_day);
	}

	counter_traffic_data(&g_stat_data.today, info, last_day);

	return ;
}

void count_week_traffic_data(struct traffic_meter_info *info, struct tm *today)
{
	/*这个星期最后一天的00:01:00更新上次数据*/
	int sec = today->tm_hour * 3600 + today->tm_min * 60 + today->tm_sec;
	if(today->tm_wday == 1 && abs(UPDATA_TIME_EVERYDAY - sec) < TRAFFIC_METER_COUNT_INTERVAL)
	{
		get_traffic_stat(info, &last_week);
	}

	counter_traffic_data(&g_stat_data.week.st, info, last_week);
	g_stat_data.week.count = today->tm_wday - last_week.tm_l.tm_wday + 1;
		
	return ;

}

void count_month_traffic_data(struct traffic_meter_info *info, struct tm *today)
{
	int sec = today->tm_hour * 3600 + today->tm_min * 60 + today->tm_sec;
	
	/*这个月第一天的00:01:00更新上次数据*/
	if(today->tm_mday == 1 && abs(UPDATA_TIME_EVERYDAY - sec) < TRAFFIC_METER_COUNT_INTERVAL)
	{
		copy_traffic_data(&g_stat_data.last_month.st, &g_stat_data.month.st);
		g_stat_data.last_month.count = g_stat_data.month.count;
		get_traffic_stat(info, &last_month);
	}

	counter_traffic_data(&g_stat_data.month.st, info, last_month);
	g_stat_data.month.count = today->tm_mday - last_month.tm_l.tm_mday + 1;
		
	return ;

}

/*根据时间来统计流量使用情况*/
void traffic_statistic_of_time(struct traffic_meter_info *info)
{
	struct tm today;
	if(info == NULL)
		return;

	get_current_systime(&today);

	TRAFFIC_METER_PRINTF("yesr=%d,mon=%d,day=%d, hour=%d, min=%d, sec=%d, week = %d\n",
		today.tm_year + 1900, today.tm_mon + 1, today.tm_mday, today.tm_hour, today.tm_min, today.tm_sec, today.tm_wday);

	count_day_traffic_data(info, &today);

	count_week_traffic_data(info, &today);

	count_month_traffic_data(info, &today);

	return;
}

void dump_traffic_data(struct traffic_stat_t data)
{
	if(debug_flag == 1)
	{
		printf("=================================================================================\n");
		printf("today: %llu %llu %llu %ld\n", data.today.u_b, data.today.d_b, 
			data.today.t_b, mktime(&data.today.tm_l));
		
		printf("yesterday: %llu %llu %llu %ld\n", data.yesterday.u_b, data.yesterday.d_b, 
			data.yesterday.t_b, mktime(&data.yesterday.tm_l));

		printf("week: %llu %llu %llu %d %ld\n", data.week.st.u_b, data.week.st.d_b, 
			data.week.st.t_b, data.week.count, mktime(&data.week.st.tm_l));
		
		printf("month: %llu %llu %llu %d %ld\n", data.month.st.u_b, data.month.st.d_b, 
			data.month.st.t_b, data.month.count, mktime(&data.month.st.tm_l));

		printf("last_month: %llu %llu %llu %d %ld\n", data.last_month.st.u_b, data.last_month.st.d_b, 
			data.last_month.st.t_b, data.last_month.count, mktime(&data.last_month.st.tm_l));
		printf("=================================================================================\n\n");
	}
	return ;
}


void write_traffic_data_to_file()
{
	FILE *fp = NULL;
	
	fp = fopen(TRAFFIC_METER_DATA_FILE, "w");
	if(fp != NULL)
	{
		fprintf(fp, "start timespec: %ld\n", mktime(&g_stat_data.month.st.tm_l));

		fprintf(fp, "today: %llu %llu %llu %02d:%02d\n", g_stat_data.today.u_b, g_stat_data.today.d_b,
			g_stat_data.today.t_b, g_stat_data.today.tm_l.tm_hour, g_stat_data.today.tm_l.tm_min);

		fprintf(fp, "yesterday: %llu %llu %llu %02d:%02d\n", g_stat_data.yesterday.u_b, g_stat_data.yesterday.d_b,
			g_stat_data.yesterday.t_b, g_stat_data.yesterday.tm_l.tm_hour, g_stat_data.yesterday.tm_l.tm_min);

		if(g_stat_data.week.count <= 0)
			g_stat_data.week.count = 1;
		fprintf(fp, "week: %llu %llu %llu %d %d %02d:%02d\n", 
			g_stat_data.week.st.u_b,
			g_stat_data.week.st.d_b,
			g_stat_data.week.st.t_b,
			g_stat_data.week.count,
			g_stat_data.week.st.tm_l.tm_wday,
			g_stat_data.week.st.tm_l.tm_hour, 
			g_stat_data.week.st.tm_l.tm_min);	

		if(g_stat_data.month.count <= 0)
			g_stat_data.month.count = 1;
		fprintf(fp, "month: %llu %llu %llu %d %d %02d:%02d\n", 
			g_stat_data.month.st.u_b,
			g_stat_data.month.st.d_b,
			g_stat_data.month.st.t_b,
			g_stat_data.month.count,
			g_stat_data.month.st.tm_l.tm_mday,
			g_stat_data.month.st.tm_l.tm_hour, 
			g_stat_data.month.st.tm_l.tm_min);
				
		if(g_stat_data.last_month.count <= 0)
			g_stat_data.last_month.count = 1;
		fprintf(fp, "last_month: %llu %llu %llu %d %d %02d:%02d\n", 
			g_stat_data.last_month.st.u_b,
			g_stat_data.last_month.st.d_b,
			g_stat_data.last_month.st.t_b,
			g_stat_data.last_month.count,
			g_stat_data.last_month.st.tm_l.tm_mday,
			g_stat_data.last_month.st.tm_l.tm_hour, 
			g_stat_data.last_month.st.tm_l.tm_min);

		fclose(fp);
	}
	return;
}

void loop_main()
{	
	struct traffic_meter_info *info = NULL;
	while(1)
	{
		/*获取流量统计数据*/
		if(get_traffic_data_by_sockopt(&g_ctx) == 0)
		{
			info = (struct traffic_meter_info *) g_ctx.data;
			
			pthread_mutex_lock(&mutex);
			/*根据时间来统计流量使用情况*/
			traffic_statistic_of_time(info);
			
			/*将数据写入文件中*/
			write_traffic_data_to_file();

			write_data_to_flash(g_stat_data);

			dump_traffic_data(g_stat_data);			
			pthread_mutex_unlock(&mutex);

		}		
		sleep(TRAFFIC_METER_COUNT_INTERVAL);
	}
}

int main(int argc, char *argv[])
{
	if(argc >= 2 && strchr(argv[1], '-') == NULL)
	{
		init_sockopt_function(argc, argv);
	}
	else
	{
		/*参数处理*/
		handle_paramter(argc, argv);
		
		if(daemon_flag == 1)
			daemon(0, 1);
			
		/*将pid保存文件中*/
		save_pid_to_file();

		/*初始化信号量*/
		init_sigaction();

		/*初始化全局变量数据*/
		init_global_data();
		
		loop_main();
	}
	return 0;		
}
