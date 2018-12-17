
#ifndef __SESSION_H_
#define __SESSION_H_

#define PRIV_NONE   0x00
#define PRIV_GUEST  0x01
#define PRIV_ADMIN  0x02

#define USER_LEN 64
#define PWD_LEN  64

#define SESSION_PATH "/tmp/AUTH_cgi"
#define SESSION_TIMEOUT (5 * 60)

enum {
    AUTH_OK,
    AUTH_TIMEOUT,
    AUTH_MULTI,
    AUTH_MULTI_GUEST,
};

/* 用户权限 */
typedef struct _user {
    int priv;
    char name[USER_LEN + 1];
    char pwd[PWD_LEN + 1];
} user_t;

/* 会话信息 */
typedef struct _session {
    int priv;
    char username[USER_LEN + 1];
    char ipaddr[46]; /* ipv4 or ipv6 */
    char macaddr[18];
    int last_active;
} session_t;

session_t *session_init();
void get_cgi_session(session_t * sess);
void update_cgi_session(session_t * sess);
void clear_cgi_session(session_t * sess);

#endif
