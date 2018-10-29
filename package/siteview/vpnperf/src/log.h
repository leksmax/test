
/*
 * 简单日志，调试头文件
 */

#ifndef __LOG_H_
#define __LOG_H_

#define LOG_NONE    0x0
#define LOG_DEBUG   0x1
#define LOG_WARN    0x2
#define LOG_ERROR   0x3
#define LOG_ALL     0x7 

extern int g_debug_level;

#define log_debug(fmt, args...) \
    if(g_debug_level & LOG_DEBUG) \
        fprintf(stderr, "[%25s]:[%05d] "fmt, __FUNCTION__, __LINE__, ##args);

#define log_warn(fmt, args...) \
    if(g_debug_level & LOG_WARN) \
        fprintf(stderr, "[%25s]:[%05d] "fmt, __FUNCTION__, __LINE__, ##args);

#define log_error(fmt, args...) \
    if(g_debug_level & LOG_ERROR) \
        fprintf(stderr, "[%25s]:[%05d] "fmt, __FUNCTION__, __LINE__, ##args);

#endif
