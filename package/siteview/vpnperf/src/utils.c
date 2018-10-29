
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "utils.h"

int cjson_get_int(cJSON *obj, char *key, int *val)
{
    cJSON *tmp = NULL;

    tmp = cJSON_GetObjectItem(obj, key);
    if(!tmp || tmp->type != cJSON_Number)
    {
        return -1;
    }

    *val = tmp->valueint;

    return 0;
}

int cjson_get_double(cJSON *obj, char *key, double *val)
{
    cJSON *tmp = NULL;

    tmp = cJSON_GetObjectItem(obj, key);
    if(!tmp || tmp->type != cJSON_Number)
    {
        return -1;
    }

    *val = tmp->valuedouble;

    return 0;
}

char *cjson_get_string(cJSON *obj, char *key)
{
    cJSON *tmp = NULL;

    tmp = cJSON_GetObjectItem(obj, key);
    if(!tmp || tmp->type != cJSON_String)
    {
        return NULL;
    }
    
    return tmp->valuestring;
}

