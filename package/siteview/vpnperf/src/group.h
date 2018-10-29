
#ifndef __GROUP_H_
#define __GROUP_H_

/* 组内成员自动发现 */
#define GROUP_DISCOVERY_TIMES 5
#define GROUP_DISCOVERY_INTERVAL 10

/* 最大组内成员数 */
#define MAX_GROUP_MEMBER_NUM 16

typedef struct _member {
    char ip[16];
    char sn[33];
} member_t;

typedef struct _group {
    member_t *members;
    int member_nums;
} group_t;

#endif

