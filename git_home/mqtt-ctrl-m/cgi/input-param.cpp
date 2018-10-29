#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cJSON.h"
#include "input-param.h"

char *find_input_param(cJSON *root, char *name)
{
	cJSON *child = NULL;
	char *value = NULL;
	if (root)
	{
		child = root->child;
		while(child)
		{
			if (!strcmp(name, child->string))
			{
				value = child->valuestring;
				break;
			}
			child = child->next;
		}
	}
	return value;
}

cJSON *gen_input_params(char *input)
{
	cJSON *root = NULL;
	char *save_ptr1 = NULL;
	char *save_ptr2 = NULL;
	char *key;
	char *value;
	char *token;
	char *subtoken;

	root = cJSON_CreateObject();
	if (root)
	{
		if (input)
		{
			token = strtok_r(input, "&", &save_ptr1);
			while(token)
			{
				if (token)
				{
					subtoken = strtok_r(token, "=", &save_ptr2);
					if (subtoken)
					{
						key = subtoken;
						subtoken = strtok_r(NULL, "=", &save_ptr2);
						value = subtoken;
						if (key && value)
						{
							cJSON *param = cJSON_CreateString(value);
							if (param)
							{
								cJSON_AddItemToObject(root, key, param);
							}
						}
					}
				}
				token = strtok_r(NULL, "&", &save_ptr1);
			}
		}
	}
	return root;
}
