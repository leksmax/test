
#ifndef __OPTION_H_
#define __OPTION_H_

#include <stdbool.h>
#include <stdint.h>
#include "cjson.h"

#ifndef offsetof
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif

struct json_val {
    const char *name;
    int (*parse)(void *, const char *, bool);
    uintptr_t offset;
    size_t elem_size;
};

#define JSON_VAL(name, parse, structure, member) \
        { name, json_parse_##parse, offsetof(struct json_##structure, member) }

int json_parse_int(void * ptr, const char * val, int is_arr);
int json_parse_string(void * ptr, const char * val, int is_arr);
int json_parse_vals(void *s, const struct json_val *vals, cJSON *item);

#endif
