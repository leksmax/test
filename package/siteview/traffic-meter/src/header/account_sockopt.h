#ifndef __ACCOUNT_SOCKOPT_H
#define __ACCOUNT_SOCKOPT_H

#define SOCK_ACCOUNT_BASE_CTL			80
#define IPT_ACCOUNT_NAME_LEN			64

#define SOCK_SET_ACCOUNT_MIN			(SOCK_ACCOUNT_BASE_CTL)
/* 限制双向流量大小 */
#define SOCK_SET_ACCOUNT_ALL_LIMIT_SIZE	(SOCK_ACCOUNT_BASE_CTL + 1)
/* 限制上传流量大小 */
#define SOCK_SET_ACCOUNT_SRC_LIMIT_SIZE	(SOCK_ACCOUNT_BASE_CTL + 2)
/* 限制下载流量大小 */
#define SOCK_SET_ACCOUNT_DST_LIMIT_SIZE	(SOCK_ACCOUNT_BASE_CTL + 3)
/* 限制下载流量大小 */
#define SOCK_SET_ACCOUNT_NOT_LIMIT_SIZE	(SOCK_ACCOUNT_BASE_CTL + 4)
/* 表中主机老化时间	*/
#define SOCK_SET_ACCOUNT_AGING_TIME		(SOCK_ACCOUNT_BASE_CTL + 5)
/* 删除某个主机 */
#define SOCK_SET_ACCOUNT_DEL_HOST		(SOCK_ACCOUNT_BASE_CTL + 6)
/* 清除一个表中所有数据 */
#define SOCK_SET_ACCOUNT_CLEAR_ONE_DATA	(SOCK_ACCOUNT_BASE_CTL + 7)
/* 清除所有表中的所有数据 */
#define SOCK_SET_ACCOUNT_CLEAR_ALL_DATA	(SOCK_ACCOUNT_BASE_CTL + 8)
/* 同步数据 */
#define SOCK_SET_ACCOUNT_SYNC_ALL_DATA	(SOCK_ACCOUNT_BASE_CTL + 9)
#define SOCK_SET_ACCOUNT_MAX			(SOCK_ACCOUNT_BASE_CTL + 10)

#define SOCK_GET_ACCOUNT_MIN			(SOCK_ACCOUNT_BASE_CTL + 20)
/* 获取所有表的名称 */
#define SOCK_GET_ACCOUNT_TABLE_LIST		(SOCK_ACCOUNT_BASE_CTL + 21)
/* 获取表的数据 */
#define SOCK_GET_ACCOUNT_TABLE_DATA		(SOCK_ACCOUNT_BASE_CTL + 22)
#define SOCK_GET_ACCOUNT_MAX			(SOCK_ACCOUNT_BASE_CTL + 23)

struct traffic_meter_info{
	unsigned long long src_packet;
	unsigned long long src_bytes;
	unsigned long long dst_packet;
	unsigned long long dst_bytes;
	unsigned long long total_packet;
	unsigned long long total_bytes;
	unsigned long long timespec;
};

struct account_handle_sockopt{
	unsigned char name[IPT_ACCOUNT_NAME_LEN + 1];
	union {
		unsigned long long size;
		char macaddr[6];
		struct traffic_meter_info info; 
	}data;
};


#endif //__ACCOUNT_SOCKOPT_H

