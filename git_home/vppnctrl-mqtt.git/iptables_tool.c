#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "iptables_tool.h"

static void skip_crlf(char *str)
{
	int str_len = strlen(str);
	int i;
	for(i = 0; i < str_len; i++)
	{
		if (str[i] == '\r' || str[i] == '\n')
		{
			str[i] = 0;
			break;
		}
	}
	return;
}

void iptabels_create_chain(char *table, char *chain)
{
	char buf[200];
	sprintf(buf, "/usr/sbin/iptables -t %s -N %s", table, chain);
	system(buf);
	return;
}

void parse_on_rule(char *buf, struct iptables_rule_s *rule)
{
	memset(rule, 0, sizeof(*rule));
	char *token;
	char *str;
	char *save_str;
	int i;
	for(i = 0, str = buf, save_str = NULL; ;str = NULL, i++)
	{
		token = strtok_r(str, " ", &save_str);
		if (token)
		{
			switch (i)
			{
				case 2:
					strcpy(rule->target, token);
					break;
				case 5:
					strcpy(rule->in, token);
					break;
				case 6:
					strcpy(rule->out, token);
					break;
				case 7:
					strcpy(rule->src, token);
					break;
				case 8:
					strcpy(rule->dst, token);
					break;
				default:
					break;
			}
		}
		else
		{
			break;
		}
	}
	return;
}

int find_one_rule(char *buf, char *in, char *out, char *src, char* dst, char *target)
{
	struct iptables_rule_s one_rule;
	parse_on_rule(buf, &one_rule);
	if (in)
	{
		if (strcmp(one_rule.in, in) != 0)
		{
			goto not_found;
		}
	}
	if (out)
	{
		if (strcmp(one_rule.out, out) != 0)
		{
			goto not_found;
		}
	}
	if (src)
	{
		if (strcmp(one_rule.src, src) != 0)
		{
			goto not_found;
		}
	}
	if (dst)
	{
		if (strcmp(one_rule.dst, dst) != 0)
		{
			goto not_found;
		}
	}
	if (target)
	{
		if (strcmp(one_rule.target, target) != 0)
		{
			goto not_found;
		}
	}

	return 1;
not_found:
	return 0;
}


int iptables_find_rule(char *table, char *chain, char *in, char *out, char *src, char *dst, char *target)
{
	int ret = 0;
	char buf[200];
	char read_buf[1000];
	sprintf(buf, "/usr/sbin/iptables -t %s -L %s -v", table, chain);
	FILE *fp = popen(buf, "r");
	if (fp)
	{
		/* skip first two lines */
		fgets(read_buf, sizeof(read_buf), fp);
		fgets(read_buf, sizeof(read_buf), fp);
		while(fgets(read_buf, sizeof(read_buf), fp))
		{
			skip_crlf(read_buf);
			int find_ret = find_one_rule(read_buf, in, out, src, dst, target);
			if (find_ret)
			{
				ret = 1;
				break;
			}
			else
			{
				
			}
		}
		pclose(fp);
	}
	return ret;
}

void iptables_append_rule(char *table, char *chain, char *rule_str)
{
	char buf[200];
	sprintf(buf, "/usr/sbin/iptables -t %s -A %s %s", table, chain, rule_str);
	system(buf);
	return;
}


void iptables_insert_rule(char *table, char *chain, char *rule_str, int position)
{
	char buf[200];
	if (position)
	{
		sprintf(buf, "/usr/sbin/iptables -t %s -I %s %d %s", table, chain, position, rule_str);
	}
	else
	{
		sprintf(buf, "/usr/sbin/iptables -t %s -I %s %s", table, chain, rule_str);
	}
	system(buf);
	return;
}

void iptables_delete_rule(char *table, char *chain, char *rule_str)
{
	char buf[200];
	sprintf(buf, "/usr/sbin/iptables -t %s -D %s %s", table, chain, rule_str);
	system(buf);
	return;
}
