
#ifndef __CONFIG_H_
#define __CONFIG_H_

#include <stdbool.h>
#include <uci.h>
#include "cjson.h"

#ifndef offsetof
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif

#define size_offsetof(TYPE, MEMBER) (sizeof((TYPE *)0)->MEMBER)

struct _uci_opt {
    const char *name;
    bool (*parse)(void *ptr, size_t ptr_size, const char *val);
    uintptr_t offset;    
    size_t size;
};

struct json_val {
    const char *name;
    bool (*parse)(void *ptr, size_t ptr_size, const char *val);
    uintptr_t offset;
    size_t size;
};

#define _UCI_OPT(name, type, structure, member) \
    { name, _uci_parse_##type, offsetof(struct _uci_##structure, member), \
        size_offsetof(struct _uci_##structure, member) }

#define JSON_VAL(name, type, structure, member) \
    { name, json_parse_##type, offsetof(struct json_##structure, member), \
        size_offsetof(struct json_##structure, member) }

int _uci_parse_int(void *ptr, size_t ptr_size, const char *val);
int _uci_parse_string(void *ptr, size_t ptr_size, const char *val);
int _uci_parse_opts(void *s, const struct _uci_opt *opts, struct uci_section *sec);

int json_parse_int(void *ptr, size_t ptr_size, const char *val);
int json_parse_string(void *ptr, size_t ptr_size, const char *val);
int json_parse_vals(void *s, const struct json_val *vals, cJSON *item);

#endif
