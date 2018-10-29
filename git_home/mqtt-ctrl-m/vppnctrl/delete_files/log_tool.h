#ifndef _SRC_LOG_TOOL_H_
#define _SRC_LOG_TOOL_H_

#ifdef __cplusplus
extern "C" {
#endif

void log_tool_init(const char* id, const char* prefix);
void log_tool_exit();
void log_tool_log(const char* fmt, ...);

#ifdef __cplusplus
}
#endif
#endif
