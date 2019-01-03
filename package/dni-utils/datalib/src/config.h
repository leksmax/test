
#ifndef __CONFIG_H_
#define __CONFIG_H_

#define CONFIG_FILE "nvram"
#define SECTION_TYPE CONFIG_FILE
#define UCI_PREFIX SECTION_TYPE".flash."

#define CONFIG_MAX_PARAM_LEN	64
#define CONFIG_MAX_VALUE_LEN	4096

struct config_pair {
    char *name;
    char *value;
};

char *config_get(const char * name);
int config_show();
int config_set(const char * name, const char * value);
int config_unset(const char * name);
int config_match(const char * name, char * match);
int config_inmatch(const char * name, char * invmatch);
int config_commit();
int config_uncommit();

#endif
