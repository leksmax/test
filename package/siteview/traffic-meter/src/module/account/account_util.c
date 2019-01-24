#include <linux/vmalloc.h>
#include <linux/version.h>
#include <ipt_account.h>

/**************************************************
  Function:     list_del_last_host
  Description:  Get the last entry of the specified
                list and delte this host
  Input:        which table(list) to delete from
**************************************************/
int list_del_last_host(struct list_head *head)
{
	struct list_head *pos;
	struct t_account_host *entry;
	if (head->prev == head)
		return -1;
	else {
		pos = head->prev;
		list_del(head->prev);
	   	entry = list_entry(pos, struct t_account_host, list);
       	//free node
	   	kfree(entry);	
		return 0;
	}
}

struct t_account_host *
find_host_by_mac_from_table(struct t_account_table *table, unsigned char *macaddr)
{
	struct list_head *pos;

	list_for_each(pos, &table->host_list_head){
		struct t_account_host *h = list_entry(pos, struct t_account_host, list);

		if(h != NULL)
		{
			if(memcmp(macaddr, h->macaddr, ETH_ALEN) == 0)
				return h;
		}
	}
	return NULL;
}


static int __find_table_for_the_same_format(uint32_t network, uint32_t netmask) 
{
	struct list_head *pos;
	list_for_each(pos, g_lru_table) {
		struct t_account_table *table = list_entry(pos,
			struct t_account_table, list);
		if (table->network == network && table->netmask == netmask)
			return 1;
	}
	return 0;
}

int find_table_for_the_same_format(uint32_t network, uint32_t netmask)
{
	int ret = 0;
   
  	read_lock_bh(&ipt_account_lock);
  	ret = __find_table_for_the_same_format(network, netmask);
	read_unlock_bh(&ipt_account_lock);

	return ret;	
}

static struct t_account_table *
__find_account_table_by_name(unsigned char *name) 
{
	struct list_head *pos;
	list_for_each(pos, g_lru_table) {
		struct t_account_table *table = list_entry(pos,
			struct t_account_table, list);
		if (strncmp(table->name, name, IPT_ACCOUNT_NAME_LEN) == 0)
			return table;
	}
	return NULL;
}

struct t_account_table *
find_account_table_by_name(unsigned char *name)
{  
	struct t_account_table *table = NULL;
  	//ACCOUNT_DEBUG_PRINTK("name = %s\n", name);  
 
  	read_lock_bh(&ipt_account_lock);
  	table = __find_account_table_by_name(name);
	read_unlock_bh(&ipt_account_lock);
  	return table;	
}

static inline void del_host_by_mac(struct list_head *head, unsigned char *macaddr)
{
	struct list_head *pos, *n;
	struct t_account_host *h;
	
	list_for_each_safe(pos, n, head){
		h = list_entry(pos, struct t_account_host, list);
		if(memcmp(h->macaddr, macaddr, ETH_ALEN) == 0)
		{
			list_del(pos);
			//free node
			kfree(h);
		}
	}
}

static void ipt_account_host_destroy(struct list_head *head)
{
	struct list_head *pos, *n;
	struct t_account_host *h;

	list_for_each_safe(pos, n, head){
		//delete node
       	list_del(pos);
       	h = list_entry(pos, struct t_account_host, list);
       	//free node
	   	kfree(h);
	}
	return ;
}

void ipt_account_table_destroy(struct t_account_table *table)
{
	if(table != NULL)
	{
	  	if (atomic_dec_and_test(&table->use)) 
		{
	    	write_lock_bh(&ipt_account_lock);	
	    	list_del(&table->list);
			
			ipt_account_host_destroy(&table->host_list_head);	
			
	    	write_unlock_bh(&ipt_account_lock);
			remove_proc_entry(table->name, ipt_account_procdir);
			kfree(table);
	  	}
	}

	return;
}

int clear_table_data(struct t_account_table *table)
{
	if(table != NULL)
	{
		memset(&table->s, 0x0, sizeof(struct t_account_host));
		memset(&table->d, 0x0, sizeof(struct t_account_host));
		memset(&table->a, 0x0, sizeof(struct t_account_host));
		table->host_num = 0;
		table->signal_flag = 1;
		table->timespec = CURRENT_TIME_SEC;
		atomic_set(&table->use, 1);

	  	write_lock_bh(&table->host_lock);
		ipt_account_host_destroy(&table->host_list_head);		
	  	write_unlock_bh(&table->host_lock);

		return 0;
	}
	return -1;
}

int clear_one_table_data(char *name)
{
	int ret = 0;
	struct t_account_table *table = NULL;

	table = find_account_table_by_name(name);
	write_lock_bh(&table->table_lock);
	ret = clear_table_data(table);
	write_unlock_bh(&table->table_lock);
	return ret;
}

int clear_all_table_data(void)
{
	int ret = -1;
	struct list_head *pos;
	write_lock_bh(&ipt_account_lock);
	list_for_each(pos, g_lru_table) {
		struct t_account_table *table = list_entry(pos, struct t_account_table, list);
		write_lock_bh(&table->table_lock);
		ret = clear_table_data(table);
		write_unlock_bh(&table->table_lock);
	}
	write_unlock_bh(&ipt_account_lock);
	return ret;
}

int del_host_from_table(unsigned char *name, unsigned char *macaddr)
{
	struct t_account_table *table = NULL;

	table = find_account_table_by_name(name);

	if(table != NULL)
	{
	  	write_lock_bh(&table->host_lock);
		del_host_by_mac(&table->host_list_head, macaddr);		
	  	write_unlock_bh(&table->host_lock);
		return 0;
	}
	return -1;
}

int set_limit_size_of_table(uint8_t limit_direction, unsigned char *name, uint64_t size)
{
	struct t_account_table *table = NULL;
	
	ACCOUNT_DEBUG_PRINTK("size = %llu\n", size);
	
	table = find_account_table_by_name(name);
	if(table != NULL)
	{
	  	write_lock_bh(&table->table_lock);
		table->limit_size = size;
		table->limit_direction = limit_direction;
		table->signal_flag = 1;
	  	write_unlock_bh(&table->table_lock);
		return 0;
	}
	return -1;
}

int set_aging_time_of_table(unsigned char *name, uint64_t aging_time)
{
	struct t_account_table *table = NULL;

	ACCOUNT_DEBUG_PRINTK("aging_time = %llu\n", aging_time);
	
	table = find_account_table_by_name(name);
	if(table != NULL)
	{
	  	write_lock_bh(&table->table_lock);
		table->aging_time = aging_time ? aging_time : MAX_AGING_TIME;
	  	write_unlock_bh(&table->table_lock);
		return 0;
	}
	return -1;
}

int get_account_data_of_table(unsigned char *name, struct traffic_meter_info *data)
{
	struct t_account_table *table = NULL;

	table = find_account_table_by_name(name);
	if(table != NULL)
	{
	  	read_lock_bh(&table->table_lock);
		data->src_bytes = table->s.b_all;
		data->src_packet = table->s.p_all;
		data->dst_bytes = table->d.b_all;
		data->dst_packet = table->d.p_all;
		data->total_bytes = table->a.b_all;
		data->total_packet = table->a.p_all;
		data->timespec = table->timespec.tv_sec;
	  	read_unlock_bh(&table->table_lock);
		return 0;
	}

	return -1;
}

int get_table_name_list(unsigned char *data, int data_len)
{
	int len = 0;
	struct list_head *pos;
	
  	read_lock_bh(&ipt_account_lock);
	list_for_each(pos, g_lru_table) {
		struct t_account_table *table = list_entry(pos,
			struct t_account_table, list);
		len += snprintf(data + len, data_len - len, "%s ", table->name);
	}
  	read_unlock_bh(&ipt_account_lock);

	return 0;
}

int sync_data_of_table(struct account_handle_sockopt handle)
{
	struct t_account_table *table = NULL;
	
	table = find_account_table_by_name(handle.name);
	if(table != NULL)
	{
  		write_lock_bh(&table->table_lock);	
		table->s.b_all += handle.data.info.src_bytes;
		table->s.p_all += handle.data.info.src_bytes;
		table->d.b_all += handle.data.info.dst_bytes;
		table->d.p_all += handle.data.info.dst_bytes;
		table->a.b_all += handle.data.info.total_bytes;
		table->a.p_all += handle.data.info.total_bytes;
		table->timespec.tv_sec = handle.data.info.timespec;
	  	write_unlock_bh(&table->table_lock);
		return 0;
	}
	
	return -1;
}
