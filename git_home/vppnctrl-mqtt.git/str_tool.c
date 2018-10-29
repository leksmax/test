#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "str_tool.h"

int str_tool_replaceAll(char *str, char old_chr, char new_chr)
{
	int ret = 0;
	if (str)
	{
		int i;
		int len = strlen(str);
		for(i = 0; i < len; i++)
		{
			if (str[i] == old_chr)
			{
				str[i] = new_chr;
				ret++;
			}
		}
	}
	return ret;
}

int str_tool_replaceFirst(char *str, char old_chr, char new_chr)
{
	int ret = 0;
	if (str)
	{
		int i;
		int len = strlen(str);
		for(i = 0; i < len; i++)
		{
			if (str[i] == old_chr)
			{
				str[i] = new_chr;
				ret++;
				break;
			}
		}
	}
	return ret;
}
