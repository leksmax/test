#include <linux/timer.h>
#include <linux/timex.h>
#include <linux/rtc.h>
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
	struct timespec now_time = CURRENT_TIME_SEC;
	
  	read_lock_bh(&ipt_account_lock);
	list_for_each(pos, g_lru_table) {
		struct t_account_table *t = list_entry(pos, struct t_account_table, list);
		if(t != NULL)
		{
			struct list_head *pos1, *n;
			write_lock_bh(&t->host_lock);
			list_for_each_safe(pos1, n, &t->host_list_head){
				struct t_account_host *h = list_entry(pos1, struct t_account_host, list);
				ACCOUNT_DEBUG_PRINTK("ip = 0x%x nowspec = %ld, aging_time = %llu\n", h->ipaddr, (now_time.tv_sec - h->timespec.tv_sec), t->aging_time);
				if( (now_time.tv_sec - h->timespec.tv_sec) > t->aging_time )
				{
					list_del(pos1);
					kfree(h);
				}
			}
			write_unlock_bh(&t->host_lock);
		}
	}
  	read_unlock_bh(&ipt_account_lock);
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


