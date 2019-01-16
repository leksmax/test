
#ifndef __UTILS_H_
#define __UTILS_H_

#include <uci.h>

#include "list.h"
#include "cjson.h"

extern int cgi_errno;

#define CONFIG_MAX_PARAM_LEN	64
#define CONFIG_MAX_VALUE_LEN	4096

#define IS_ENABLED 1

enum CGI_ERRNO {
    CGI_ERR_OK = 0,
        
    CGI_ERR_PARAM = 101,            /* 参数格式错误 */
    CGI_ERR_CFG_PARAM = 102,        /* 配置参数不正确，缺少参数,或者参数校验不对 */
    CGI_ERR_CFG_OVERMUCH = 103,     /* 配置过多，已超过上限 */
    CGI_ERR_CFG_FILE = 104,         /* 配置文件错误 */
    CGI_ERR_CFG_DUPLICATE = 105,    /* 重复的配置 */
    CGI_ERR_CREATE_BACKUP = 106,    /* 生成配置文件出错 */
    CGI_ERR_BACKUP_CHECK = 107,     /* 配置文件检查失败 */
    
    CGI_ERR_UPLOAD = 110,           /* 文件上传出错 */
    
    CGI_ERR_FW_OVERSIZE = 190,      /* 固件超过最大大小限制 */
    CGI_ERR_FW_CHECK = 191,         /* 固件检查失败 */
    CGI_ERR_FW_NOT_FOUND = 192,     /* 找不到固件 */

    CGI_DUALWAN_DISABLED = 210,     /* dualwan功能为开启 */

    CGI_ERR_AUTH_REQUIRED = 401,    /* 需要登录 */
    CGI_ERR_AUTH_TIMEOUT = 402,     /* 登录超时 */
    CGI_ERR_AUTH_CHECK = 403,       /* 用户名或密码错误 */
    CGI_ERR_AUTH_REACHED = 404,     /* 尝试次数太多 */
    CGI_ERR_AUTH_MULTI = 405,       /* 多用户登录 */
    CGI_ERR_AUTH_FORBID = 406,      /* 拒绝访问 */
    
    CGI_ERR_INTERNAL = 500,         /* CGI内部错误 */
    CGI_ERR_NOT_FOUND = 501,        /* 找不到该接口 */
    CGI_ERR_REQUEST = 502           /* 错误的请求 */
};

enum CGI_METHOD {
    CGI_GET = 0,
    CGI_SET = 1,
    CGI_ADD = 2,
    CGI_DEL = 3
};

#define wp_t FILE

int sys_exec(const char * fmt, ...);
int fork_exec(int wait, const char *fmt, ...);

char *config_get(const char *name);
int config_get_int(const char *name);
int config_set(const char *name, const char *value);
int config_set_int(const char *name, int value);
int config_unset(const char * name);
int config_commit(const char * name);
int config_uncommit(const char * name);

int cjson_get_int(cJSON * obj, char * key, int * val);
int cjson_get_double(cJSON * obj, char * key, double * val);
char *cjson_get_string(cJSON * obj, char * key);

int cjson_get_int(cJSON * obj, char * key, int * val);
int cjson_get_double(cJSON * obj, char * key, double * val);
char *cjson_get_string(cJSON * obj, char * key);

void webs_file_header(wp_t * wp, const char * filename);
void webs_json_header(wp_t * wp);
void webs_text_header(wp_t * wp);
void webs_redirect(wp_t * wp, char *html);
void webs_write(wp_t * wp, char * fmt, ...);

char *cat_file(const char * file);
void echo_file(char * value, char * file);

int param_init(char * data, int * method, cJSON ** params);
void param_free();

#if 1
#define cgi_debug(fmt, args...) \
	{ \
		FILE *dout; \
		dout = fopen("/tmp/webcgi.log", "a"); \
		fprintf(dout, "[%25s]:[%05d] "fmt, __FUNCTION__, __LINE__, ##args); \
		fclose(dout); \
	}
#else
#define cgi_debug(fmt, args...)
#endif


#endif
