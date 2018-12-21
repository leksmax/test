
#include <ipt_account.h>

struct timer_list data_traffic_timer;

/********************************************************************
  Function:     data_traffic_timer_function
Description:    zero speed parameters every second, if a hsot doesn't
                have data traffic in a long period, delete it
*********************************************************************/
static void data_traffic_timer_function(unsigned long data)
{
	struct list_head *pos;
	struct timespec now = CURRENT_TIME_SEC;
	
	list_for_each(pos, g_lru_table) {
		struct t_account_table *t = list_entry(pos, struct t_account_table, list);
		if(t != NULL)
		{
			if(t->zero_time != 0 && t->zero_time == now.tv_sec)
			{
				write_lock_bh(&ipt_account_lock);
				clear_table_data(t);
				write_unlock_bh(&ipt_account_lock);
			}
		}
	}
	data_traffic_timer.expires = jiffies + HZ;
	add_timer(&data_traffic_timer);
}

/*********************************************************
  Function:     data_traffic_timer_init
  Description:  initialize timer, set the interval 1 second
**********************************************************/
void data_traffic_timer_init(void)
{
	data_traffic_timer.expires = jiffies + HZ;
	data_traffic_timer.data = 0;
	data_traffic_timer.function = data_traffic_timer_function;
	init_timer(&data_traffic_timer);
}


