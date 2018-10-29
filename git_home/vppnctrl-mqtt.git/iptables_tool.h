#ifndef __IPTABLES_TOOL_H__
#define __IPTABLES_TOOL_H__

#define MAX_BUF_LEN (100)

struct iptables_rule_s
{
	char in[MAX_BUF_LEN];
	char out[MAX_BUF_LEN];
	char src[MAX_BUF_LEN];
	char dst[MAX_BUF_LEN];
	char target[MAX_BUF_LEN];
};


/**
 * @brief  :find a firewall rule whether exists in firewall
 *
 * @Param  :table
 * @Param  :chain
 * @Param  :in
 * @Param  :out
 * @Param  :src
 * @Param  :dst
 * @Param  :target
 *
 * @Returns  :0 on absent, 1 on present
 */
int iptables_find_rule(char *table, char *chain, char *in, char *out, char *src, char *dst, char *target);

/**
 * @brief  :append a firewall rule to the firewall
 *
 * @Param  :table
 * @Param  :chain
 * @Param  :rule_str
 */
void iptables_append_rule(char *table, char *chain, char *rule_str);

/**
 * @brief  :insert a firewall rule to the firewall
 *
 * @Param  :table
 * @Param  :chain
 * @Param  :rule_str
 * @Param  :position
 */
void iptables_insert_rule(char *table, char *chain, char *rule_str, int position);

/**
 * @brief  :delete a firewall rule from the firewall
 *
 * @Param  :table
 * @Param  :chain
 * @Param  :rule_str
 */
void iptables_delete_rule(char *table, char *chain, char *rule_str);

#endif
