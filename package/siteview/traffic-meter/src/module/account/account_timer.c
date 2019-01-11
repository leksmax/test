#include <linux/timer.h>
#include <linux/timex.h>
#include <linux/rtc.h>
#include <ipt_account.h>

struct timer_list data_traffic_timer;

static uint64_t get_current_time(void)
{
	struct timex txc;
	struct rtc_time tm;
	
	do_gettimeofday(&(txc.time));
	txc.time.tv_sec -= sys_tz.tz_minuteswest * 60;
	rtc_time_to_tm(txc.time.tv_sec, &tm);

	return (tm.tm_mday * 24 * 3600L + tm.tm_hour * 3600 + tm.tm_min * 60 + tm.tm_sec);
}
	

/********************************************************************
  Function:     data_traffic_timer_function
Description:    zero speed parameters every second, if a hsot doesn't
                have data traffic in a long period, delete it
*********************************************************************/
static void data_traffic_timer_function(unsigned long data)
{
#if 0
	struct list_head *pos;
	uint64_t now_time = get_current_time();

	list_for_each(pos, g_lru_table) {
		struct t_account_table *t = list_entry(pos, struct t_account_table, list);
		if(t != NULL)
		{
			//ACCOUNT_DEBUG_PRINTK("zero_time = %llu, now_time:%llu\n", t->zero_time, now_time);
			if(t->zero_time != 0 && t->zero_time == now_time)
			{
				write_lock_bh(&ipt_account_lock);
				clear_table_data(t);
				write_unlock_bh(&ipt_account_lock);
			} 
		}
	}
#endif
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


