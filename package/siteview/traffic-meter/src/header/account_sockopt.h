#ifndef __ACCOUNT_SOCKOPT_H
#define __ACCOUNT_SOCKOPT_H

#define SOCK_ACCOUNT_BASE_CTL			80
#define IPT_ACCOUNT_NAME_LEN			64

#define SOCK_SET_ACCOUNT_MIN			(SOCK_ACCOUNT_BASE_CTL)
/* 限制流量大小 */
#define SOCK_SET_ACCOUNT_LIMIT_SIZE		(SOCK_ACCOUNT_BASE_CTL + 1)
/* 表数据归零时间	*/
#define SOCK_SET_ACCOUNT_ZERO_TIME		(SOCK_ACCOUNT_BASE_CTL + 2)
/* 删除某个主机 */
#define SOCK_SET_ACCOUNT_DEL_HOST		(SOCK_ACCOUNT_BASE_CTL + 3)
/* 清除一个表中所有数据 */
#define SOCK_SET_ACCOUNT_CLEAR_ONE_DATA	(SOCK_ACCOUNT_BASE_CTL + 4)
/* 清除所有表中的所有数据 */
#define SOCK_SET_ACCOUNT_CLEAR_ALL_DATA	(SOCK_ACCOUNT_BASE_CTL + 5)
#define SOCK_SET_ACCOUNT_MAX			(SOCK_ACCOUNT_BASE_CTL + 6)

#define SOCK_GET_ACCOUNT_MIN			(SOCK_ACCOUNT_BASE_CTL + 10)
/* 获取所有表的名称 */
#define SOCK_GET_ACCOUNT_TABLE_LIST		(SOCK_ACCOUNT_BASE_CTL + 11)
/* 获取表的数据 */
#define SOCK_GET_ACCOUNT_TABLE_DATA		(SOCK_ACCOUNT_BASE_CTL + 12)
#define SOCK_GET_ACCOUNT_MAX			(SOCK_ACCOUNT_BASE_CTL + 13)

struct account_handle_sockopt{
	unsigned char name[IPT_ACCOUNT_NAME_LEN + 1];
	union {
		unsigned long long size;
		char macaddr[6];
	}data;
};
#endif //__ACCOUNT_SOCKOPT_H

