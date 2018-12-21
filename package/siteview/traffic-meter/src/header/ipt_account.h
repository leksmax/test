#ifndef __IPT_ACCOUNT_H
#define __IPT_ACCOUNT_H

#include <net/arp.h>
#include <linux/proc_fs.h>
#include <ipt_match_account.h>

#define DEBUG_IPT_ACCONT
#ifdef DEBUG_IPT_ACCONT
#define ACCOUNT_DEBUG_PRINTK(format, arg...) printk(KERN_INFO "[%s:%05d]: " format, __FUNCTION__, __LINE__, ##arg);
#else
#define ACCOUNT_DEBUG_PRINTK(format, arg...)
#endif

#define IPT_ACCOUNT_PROC_NAME			("account")
#define MAX_IPT_ACCOUNT_TABLE_HOST_NUM	500
#define HIPQUAD(addr) \
       ((unsigned char *)&addr)[3], \
       ((unsigned char *)&addr)[2], \
       ((unsigned char *)&addr)[1], \
       ((unsigned char *)&addr)[0]

#define HMACQUAD(addr) addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]

struct t_account_stat{
	uint64_t b_all;							//字节数 btypes
	uint64_t p_all;							//包数 pakages
};

struct t_account_host{
	struct list_head list;
	uint32_t ipaddr;						//IP地址
	unsigned char macaddr[ETH_ALEN];		//MAC地址
	struct timespec timespec;				//时间戳
	struct t_account_stat s, d, a;			//一个主机对应的流量统计
											//(src, dst, total)
};

struct t_account_table{
	struct list_head list;
	struct list_head host_list_head;
	uint32_t host_num;						//主机数
	uint32_t network;						//网络号
	uint32_t netmask;						//子网掩码
	struct timespec timespec;				//时间戳
	uint32_t zero_time;						//表数据归零时间
	uint64_t limit_size;					//表数据限制流量大小
	char name[IPT_ACCOUNT_NAME_LEN + 1]; 	//表名称
	struct t_account_stat s, d, a;			//整个子网的流量统计总和
											//(total_src, total_dst, total_all)
  	atomic_t use; /* use counter, the number of rules which points to this table */
  	rwlock_t stats_lock; /* lock, to assure that above union can be safely modified */										
};

/* recently used table head defination */
extern struct list_head *g_lru_table;
extern rwlock_t ipt_account_lock;
extern struct proc_dir_entry *ipt_account_procdir;
extern struct timer_list data_traffic_timer;

extern int clear_table_data(struct t_account_table *table);
extern int clear_one_table_data(char *name);
extern int clear_all_table_data(void);
extern int del_host_from_table(unsigned char *name, unsigned char *macaddr);
extern int set_limit_size_of_table(unsigned char *name, uint64_t size);
extern int set_zero_time_of_table(unsigned char *name, uint64_t zero_time);

extern int list_del_last_host(struct list_head *head);
extern void data_traffic_timer_init(void);
extern void ipt_account_table_destroy(struct t_account_table *table);
extern struct t_account_table *find_account_table_by_name(unsigned char *name);
extern int find_table_for_the_same_format(uint32_t network, uint32_t netmask);
extern struct t_account_host *
	find_host_by_mac_from_table(struct t_account_table *table, unsigned char *macaddr);

extern int account_set_ctl(struct sock *sk, int cmd, void *user, unsigned int len);
extern int account_get_ctl(struct sock *sk, int cmd, void *user, int *len);

#endif //__IPT_ACCOUNT_T
