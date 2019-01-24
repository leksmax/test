#include <linux/module.h>
#include <linux/version.h>
#include <linux/skbuff.h>
#include <linux/vmalloc.h>
#include <linux/seq_file.h>
#include <linux/ip.h>
#include <net/arp.h>
#include <linux/in.h>
#include <linux/netfilter/x_tables.h>
#include <ipt_account.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Piotr Gasidlo <quaker@barbara.eu.org>");
MODULE_DESCRIPTION("Traffic accounting module");

DEFINE_MUTEX(ipt_account_mutex);

/* defaults, can be overriden */
static unsigned int netmask = 8; /* Safe netmask, if you try to create table
                                     for larger netblock you will get error. 
                                     Increase by command line only when you
                                     known what are you doing. */
static struct list_head ipt_account_tables;
struct list_head *g_lru_table = &ipt_account_tables;
struct proc_dir_entry *ipt_account_procdir;
rwlock_t ipt_account_lock = __RW_LOCK_UNLOCKED(ipt_account_lock); /* lock, to assure that table list can be safely modified */

static void *ipt_account_seq_start (struct seq_file *file, loff_t *pos)
{
	struct t_account_table *table = file->private;
	
	seq_printf(file, "table name:%s\ntotal:%llu %llu %llu %llu %llu %llu %ld\n", 
		table->name, table->s.p_all, table->s.b_all, table->d.p_all,
		table->d.b_all, table->a.p_all, table->a.b_all, table->timespec.tv_sec);
	
	read_lock_bh(&table->table_lock);
    if (*pos >= table->host_num)
		return NULL;
	
	return table->host_list_head.next;
}

static void *ipt_account_seq_next (struct seq_file *file, void *v, loff_t *pos)
{
  	struct t_account_table *table = file->private;
    struct list_head *entry = (struct list_head *)v;
	
    (*pos)++;
	if (entry->next == &table->host_list_head)
		return NULL;
	else
		return entry->next;

}

static void ipt_account_seq_stop (struct seq_file *file, void *v)
{
	struct t_account_table *table = file->private;
	read_unlock_bh(&table->table_lock);
	return ;
}

static int ipt_account_seq_show (struct seq_file *file, void *v)
{
	struct list_head *head = (struct list_head *)v;
	struct t_account_host *entry =
		list_entry(head, struct t_account_host, list);

	if(entry != NULL)
	{				
		seq_printf(file, "%02X:%02X:%02X:%02X:%02X:%02X\t", HMACQUAD(entry->macaddr));
		seq_printf(file, "%u.%u.%u.%u\t", HIPQUAD(entry->ipaddr));
		
		seq_printf(file, "%llu\t", entry->s.p_all);
		seq_printf(file, "%llu\t", entry->s.b_all);
		seq_printf(file, "%llu\t", entry->d.p_all);		
		seq_printf(file, "%llu\t", entry->d.b_all);
		seq_printf(file, "%llu\t", entry->a.p_all);
		seq_printf(file, "%llu\t", entry->a.b_all);
		seq_printf(file, "%ld\t\n", entry->timespec.tv_sec);
	}

	return 0;
}

	
static struct seq_operations ipt_account_seq_ops = {
	.start = ipt_account_seq_start,
	.next = ipt_account_seq_next,
	.stop = ipt_account_seq_stop,
	.show = ipt_account_seq_show
};


static int ipt_account_proc_open(struct inode *inode, struct file *file)
{
	int ret = seq_open(file, &ipt_account_seq_ops);
	if( ret == 0 )
	{
		struct seq_file *sf = file->private_data;
		struct t_account_table *table = PDE_DATA(inode);
	
		sf->private = PDE_DATA(inode);
		atomic_inc(&table->use);
	}
	return ret;

}

static int ipt_account_proc_release (struct inode *inode, struct file *file)
{
	int ret;
	struct t_account_table *table = ((struct seq_file *)file->private_data)->private;

	ret = seq_release(inode, file);
	if (!ret)
	{	
	  	ipt_account_table_destroy(table);
	}
	return ret;
}

static struct file_operations ipt_account_proc_fops = {
	.owner = THIS_MODULE,
	.open = ipt_account_proc_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = ipt_account_proc_release
};

static void send_signal_to_user(struct work_struct *work)
{
	struct file *fp;
	char pid[8];
	struct t_account_table *table = NULL;
	struct task_struct *p = NULL;

	fp = filp_open("/var/run/traffic_meter.pid", O_RDONLY, 0);
	if(IS_ERR(fp))
		return;

	if(fp->f_op && fp->f_op->read)
	{
		if(fp->f_op->read(fp, pid, 8, &fp->f_pos) > 0)
		{
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,35)
			p = pid_task(find_get_pid(simple_strtoul(pid, NULL, 10)), PIDTYPE_PID);
#else
			p = find_task_by_pid(simple_strtoul(pid, NULL, 10));
#endif
			if( NULL != p )
			{
				table = container_of(work, struct t_account_table, account_work);
				write_lock_bh(&table->table_lock);

				if(table->signal_flag == 1)
				{
					ACCOUNT_DEBUG_PRINTK("flag = %d, size:%llu\n", table->signal_flag, table->limit_size);
					table->signal_flag = 0;
					send_sig(SIGUSR1, p, 0); // 关闭
				}
				write_unlock_bh(&table->table_lock);
			}
		}
	}
	filp_close(fp, NULL);
	return;
}

static int ipt_account_table_init(struct xt_match_ipt_account *match)
{ 
	struct t_account_table *table;

	ACCOUNT_DEBUG_PRINTK("name = %s\n", match->name);

	table = kmalloc(sizeof(struct t_account_table), GFP_KERNEL);
	if (table == NULL) {
		printk(KERN_ERR "vmalloc failed.\n");
		return -1;
	}
	
	
	/*init table*/
	strncpy(table->name, match->name, IPT_ACCOUNT_NAME_LEN); 
	table->name[IPT_ACCOUNT_NAME_LEN] = '\0';

	table->network = match->network;
	table->netmask = match->netmask;
	table->host_num = 0;
	table->timespec = CURRENT_TIME_SEC;
	table->limit_direction = NOT_LIMIT;
	table->signal_flag = 1;
	table->limit_size = 0;
	table->aging_time = MAX_AGING_TIME;
	
	memset(&table->s, 0x0, sizeof(struct t_account_host));
	memset(&table->d, 0x0, sizeof(struct t_account_host));
	memset(&table->a, 0x0, sizeof(struct t_account_host));
	
	table->host_lock = __RW_LOCK_UNLOCKED(table->host_lock);
	table->table_lock = __RW_LOCK_UNLOCKED(table->table_lock);
	atomic_set(&table->use, 1);
	
	write_lock_bh(&ipt_account_lock);
	list_add(&table->list, g_lru_table);	
	INIT_LIST_HEAD(&table->host_list_head);
	write_unlock_bh(&ipt_account_lock);

	if(proc_create_data(table->name, S_IWUSR | S_IRUSR, 
		ipt_account_procdir, &ipt_account_proc_fops, table) == NULL)
	{
		kfree(table);
		printk(KERN_ERR "pror create data failed.\n");
		return -1;
	}
	INIT_WORK(&table->account_work, send_signal_to_user);

	return 0;
}

static int account_checkentry(const struct xt_mtchk_param * par)
{
	struct xt_match_ipt_account *info = (struct xt_match_ipt_account *)par->matchinfo;
	struct t_account_table *table = NULL;

	ACCOUNT_DEBUG_PRINTK("name = %s\n", info->name);

	if(info->netmask < ((~0L << (32 - netmask) & 0xffffffff)))
	{
		printk(KERN_ERR "account_checkentry: too big netmask (increase module 'netmask' parameter).\n");
		return -EINVAL;
	}

	if((info->network & info->netmask) != info->network)
	{
		printk(KERN_ERR "account_checkentry: wrong network/netmask.\n");
		return -EINVAL;
	}

	if(info->name[0] == '\0')
	{
		printk(KERN_ERR "account_checkentry: wrong table name.\n");
		return -EINVAL;
	}

	mutex_lock(&ipt_account_mutex);
	table = find_account_table_by_name(info->name);
	if(table) // exist table 
	{
		atomic_inc(&table->use);
      	if (table->network != info->network || table->netmask != info->netmask)
      	{
			ACCOUNT_DEBUG_PRINTK("table found, checking: name = %s, netmask = 0x%x, network = 0x%x\n", table->name, table->netmask, table->network);
			printk(KERN_ERR "account_checkentry: table name is exist\n");
			mutex_unlock(&ipt_account_mutex);
			return -EINVAL;
      	}
	}
	else
	{
		if(find_table_for_the_same_format(info->network, info->netmask) == 0)
		{
			if(ipt_account_table_init(info) < 0)
			{
				printk(KERN_ERR "account_checkentry: init table error.\n");
				mutex_unlock(&ipt_account_mutex);
				return -EINVAL;
			}
		}
		else
		{
			printk(KERN_ERR "account_checkentry: table name is exist\n");
			mutex_unlock(&ipt_account_mutex);
			return -EINVAL;
		}
	}
	mutex_unlock(&ipt_account_mutex);

	return 0;
}

static
void update_or_add_host_to_table(struct t_account_table *table, struct t_account_host *host)
{
	struct t_account_host *h = NULL;
	
	write_lock_bh(&table->host_lock);
	h = find_host_by_mac_from_table(table, host->macaddr);
	if(h == NULL)
	{
		h = (struct t_account_host *)kmalloc(sizeof(struct t_account_host), GFP_KERNEL);
		if(h == NULL)
		{
			printk(KERN_ERR "kmalloc failed!\n");
			return ;
		}
		h->s.b_all = host->s.b_all;
		h->s.p_all = host->s.p_all;
		h->d.b_all = host->d.b_all;
		h->d.p_all = host->d.p_all;
		h->a.b_all = host->a.b_all;
		h->a.p_all = host->a.p_all;
		h->timespec = host->timespec;
		h->ipaddr = host->ipaddr;
		memcpy(h->macaddr, host->macaddr, ETH_ALEN);

		if(table->host_num >= MAX_IPT_ACCOUNT_TABLE_HOST_NUM)
		{
			list_del_last_host(&table->host_list_head);
			table->host_num --;
		}
		
		list_add(&h->list, &table->host_list_head);

		table->host_num ++;

	}
	else
	{
		h->s.b_all += host->s.b_all;
		h->s.p_all += host->s.p_all;
		h->d.b_all += host->d.b_all;
		h->d.p_all += host->d.p_all;
		h->a.b_all += host->a.b_all;
		h->a.p_all += host->a.p_all;
		h->timespec = host->timespec;
		h->ipaddr = host->ipaddr;
	}
	write_unlock_bh(&table->host_lock);
}

void check_limit_data_size(struct t_account_table *t)
{
	if(t != NULL)
	{
		//ACCOUNT_DEBUG_PRINTK("signal_flag = %d limit_direction = %d, all:%llu, size:%llu\n", t->signal_flag, t->limit_direction, t->a.b_all, t->limit_size);
		if(t->limit_direction != NOT_LIMIT && t->limit_size != 0)
		{
			if( (t->limit_direction == LIMIT_ALL && t->limit_size <= t->a.b_all) ||
				(t->limit_direction == LIMIT_DOWNLOAD && t->limit_size <= t->d.b_all) ||
				(t->limit_direction == LIMIT_UPLOAD && t->limit_size <= t->s.b_all) )
			{
				if(t->signal_flag == 1)
				{
					//ACCOUNT_DEBUG_PRINTK("flag = %d, size:%llu\n", t->signal_flag, t->limit_size);
					// 发信号给应用层，开启相对的动作
					schedule_work(&t->account_work);
				}
			}
		}
	}
}

static bool account_match(const struct sk_buff *skb, struct xt_action_param *par)
{
	bool ret = false;
	struct xt_match_ipt_account *info = (struct xt_match_ipt_account *)par->matchinfo;
	struct t_account_table *table = NULL;
	struct t_account_host host;
	struct neighbour *neighbour = NULL;	
	struct ethhdr *mac_header = eth_hdr(skb);
	uint32_t address;

	//ACCOUNT_DEBUG_PRINTK("name = %s\n", info->name);

	memset(&host, 0x0, sizeof(struct t_account_host));
	
	address = ntohl(ip_hdr(skb)->saddr);
	if(address && ((address & info->netmask) == info->network))
	{
		host.ipaddr = address;
		memcpy(host.macaddr, mac_header->h_source, ETH_ALEN);
		host.s.b_all = skb->len;
		host.s.p_all = 1;
		host.a.b_all = skb->len;
		host.a.p_all = 1;
		host.timespec = CURRENT_TIME_SEC;
		
		ret = true;
	}
	
	address = ntohl(ip_hdr(skb)->daddr);
	if(address && ((address & info->netmask) == info->network))
	{
		host.ipaddr = address;

		neighbour = neigh_lookup(&arp_tbl, &ip_hdr(skb)->daddr, par->out);
		if (neighbour == NULL) {
			printk(KERN_ERR "can not find macaddr!\n");
			return ret;
        }
		memcpy(host.macaddr, neighbour->ha, ETH_ALEN);
		neigh_release(neighbour);
		
		host.d.b_all = skb->len;
		host.d.p_all = 1;
		host.a.b_all = skb->len;
		host.a.p_all = 1;
		host.timespec = CURRENT_TIME_SEC;

		ret = true;
	}

	if(ret == true)
	{
		table = find_account_table_by_name(info->name);
		if(table != NULL && table->signal_flag != 0)
		{	
			check_limit_data_size(table);

			write_lock_bh(&table->table_lock);
			
			table->a.b_all += host.a.b_all;
			table->a.p_all += host.a.p_all;
			table->s.b_all += host.s.b_all;
			table->s.p_all += host.s.p_all;
			table->d.b_all += host.d.b_all;
			table->d.p_all += host.d.p_all;

			update_or_add_host_to_table(table, &host);
			write_unlock_bh(&table->table_lock);
		}
	}

	return ret;
}

static void account_destroy(const struct xt_mtdtor_param * par)
{
	struct xt_match_ipt_account *info = (struct xt_match_ipt_account *)par->matchinfo;
	
	//ACCOUNT_DEBUG_PRINTK("name = %s, network = 0x%x, netmask = 0x%x\n", info->name, info->network, info->netmask);
	struct t_account_table *table = find_account_table_by_name(info->name);
	ipt_account_table_destroy(table);
	
	return;
}

static struct xt_match xt_ipt_account_match_reg __read_mostly = { 
  	.name = "account", 
  	.family = NFPROTO_IPV4,
  	.match = account_match, 
  	.checkentry = account_checkentry, 
  	.matchsize = sizeof(struct xt_match_ipt_account),
  	.destroy = account_destroy, 
  	.me = THIS_MODULE
};

static struct nf_sockopt_ops ipt_account_sockopt = {
	.pf = PF_INET,
	.set_optmin = SOCK_SET_ACCOUNT_MIN,
	.set_optmax = SOCK_SET_ACCOUNT_MAX,
	.set = account_set_ctl,
	.get_optmin = SOCK_GET_ACCOUNT_MIN,
	.get_optmax = SOCK_GET_ACCOUNT_MAX,
	.get = account_get_ctl
};

static void global_data_init(void)
{
	/* init lru table */
	INIT_LIST_HEAD(g_lru_table);
	return ;
}

static int __init ipt_account_init(void)
{	

	global_data_init();
	
	/* create dev dir */
  	ipt_account_procdir = proc_mkdir(IPT_ACCOUNT_PROC_NAME, init_net.proc_net);
	if(ipt_account_procdir == NULL)
	{
		printk(KERN_ERR "proc mkdir failed.\n");
		goto cleanup_none;
	}

	/* register setsockopt */
	if(nf_register_sockopt(&ipt_account_sockopt) < 0)
	{
		printk(KERN_ERR "Can't register sockopt. Aborting\n");
		goto cleanup_dir;
	}

	if(xt_register_match(&xt_ipt_account_match_reg) < 0)
	{
		printk(KERN_ERR "Register account match failed.\n");
		goto cleanup_sockopt;
	}
	
	printk(KERN_INFO "Start account timer\n");
	data_traffic_timer_init();
	add_timer(&data_traffic_timer);

	return 0;
	
cleanup_sockopt:
	nf_unregister_sockopt(&ipt_account_sockopt);
cleanup_dir:
	remove_proc_entry(IPT_ACCOUNT_PROC_NAME, init_net.proc_net);
cleanup_none:
	return -EINVAL;
}

static void ipt_account_exit(void)
{
	printk(KERN_INFO "Delete account timer\n");
	del_timer(&data_traffic_timer);
	
	nf_unregister_sockopt(&ipt_account_sockopt);
	
	remove_proc_entry(IPT_ACCOUNT_PROC_NAME, init_net.proc_net);
	
	xt_unregister_match(&xt_ipt_account_match_reg);

	return ;
}

module_init(ipt_account_init);
module_exit(ipt_account_exit);
