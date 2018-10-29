
#ifndef __UTILS_H_
#define __UTILS_H_

#include "cjson.h"

int cjson_get_int(cJSON *obj, char *key, int *val);
int cjson_get_double(cJSON *obj, char *key, double *val);
char *cjson_get_string(cJSON *obj, char *key);

#endif
