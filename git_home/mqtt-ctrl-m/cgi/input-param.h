#ifndef __INPUT_PARAM_H__
#define __INPUT_PARAM_H__

#include <stdio.h>
#include <stdlib.h>
#include "cJSON.h"

#ifdef __cplusplus
extern "C" {
#endif

char *find_input_param(cJSON *root, char *name);
cJSON *gen_input_params(char *input);

#ifdef __cplusplus
}
#endif

#endif
