
/*
 * 基于ip and mac的认证机制
 * TODO: 基于cookie的认证机制
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "utils.h"
#include "session.h"

session_t *session_init()
{
    session_t *sess = NULL;

    sess = (session_t *)malloc(sizeof(session_t));
    if (!sess)
    {
        return NULL;
    }

    sess->priv = PRIV_NONE;
    memset(sess, 0x0, sizeof(session_t));
    
    return sess;
}

/* 获取会话信息 */
void get_cgi_session(session_t *sess)
{
    char line[128] = {0};

    strncpy(line, cat_file(SESSION_PATH), sizeof(line) - 1);

    if ((sscanf(line, "%s %d %s %s %d", sess->username, &sess->priv,
        sess->ipaddr, sess->macaddr, &sess->last_active)) != 5)
    {
        memset(sess, 0x0, sizeof(session_t));
    }
}

/* 更新会话信息 */
void update_cgi_session(session_t *sess)
{
    char line[128] = {0};

    snprintf(line, sizeof(line), "%s %d %s %s %d\n", sess->username, sess->priv, 
        sess->ipaddr, sess->macaddr, sess->last_active);

    echo_file(line, SESSION_PATH);
}

/* 清除会话信息 */
void clear_cgi_session(session_t *sess)
{
    echo_file("", SESSION_PATH);
}
