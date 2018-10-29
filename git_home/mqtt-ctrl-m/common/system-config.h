#ifndef _SRC_SYSTEM_CONFIG_H_
#define _SRC_SYSTEM_CONFIG_H_

#ifdef __cplusplus
extern "C" {
#endif
void system_config_get(const char *name, char *value);
void system_config_set(const char *name, char *value);
void system_config_unset(const char *name);
void system_config_commit();


#ifdef __cplusplus
}
#endif

#endif
