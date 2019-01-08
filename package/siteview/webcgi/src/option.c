
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "option.h"

int json_parse_int(void *ptr, const char *val, int is_arr)
{   
    *((int *)ptr) = *((int *)val);
    return true;
}

int json_parse_string(void *ptr, const char *val, int is_arr)
{   
    *((char **)ptr) = (char *)val;
    return true;
}

int json_parse_vals(void *s, const struct json_val *vals, cJSON *item)
{   
    char *p, *v;
    cJSON *json = NULL;
    cJSON *arr = NULL;
    const struct json_val *val;
    int ret = 0;
    
    json = item->child;
    while (json)
    {   
        for (val = vals; val->name; val ++)
        {   
            if (!val->parse)
            {   
                continue;
            }
            
            if (strcmp(val->name, json->string))
            {   
                continue;
            }
            
            if (json->type == cJSON_Array)
            {
            
            }
            
            if (json->type == cJSON_String)
            {   
                ret = val->parse((char *)s + val->offset, json->valuestring, false);
            }
            
            if (json->type == cJSON_Number)
            {   
                ret = val->parse((char *)s + val->offset, (char *)&json->valueint, false);
            }
        }
        
        json = json->next;
    }
    
    return 0;
}

