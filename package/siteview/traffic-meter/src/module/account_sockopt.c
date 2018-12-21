#include <linux/netfilter/x_tables.h>
#include <account_sockopt.h>
#include <ipt_account.h>

int account_set_ctl(struct sock *sk, int cmd, void *user, unsigned int len)
{
	int ret = -EINVAL;
	struct account_handle_sockopt handle;
	char table_name[IPT_ACCOUNT_NAME_LEN + 1] = {0};

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	memset(&handle, 0x0, sizeof(struct account_handle_sockopt));
	switch(cmd){
		case SOCK_SET_ACCOUNT_LIMIT_SIZE:
			if(len != sizeof(struct account_handle_sockopt))
			{
				printk(KERN_ERR "account_set_ctl: wrong data size (%u != %zu) "
					"for SOCK_SET_ACCOUNT_LIMIT_SIZE\n",
					len, sizeof(struct account_handle_sockopt));
				break;
			}

			if(copy_from_user(&handle, user, len))
			{
				printk(KERN_ERR "account_set_ctl: copy_from_user failed "
					"for SOCK_SET_ACCOUNT_LIMIT_SIZE\n");
				break;
			}

			ret = set_limit_size_of_table(handle.name, handle.data.size);			
			break;
		case SOCK_SET_ACCOUNT_ZERO_TIME:
			if(len != sizeof(struct account_handle_sockopt))
			{
				printk(KERN_ERR "account_set_ctl: wrong data size (%u != %zu) "
					"for SOCK_SET_ACCOUNT_ZERO_TIME\n",
					len, sizeof(struct account_handle_sockopt));
				break;
			}

			if(copy_from_user(&handle, user, len))
			{
				printk(KERN_ERR "account_set_ctl: copy_from_user failed "
					"for SOCK_SET_ACCOUNT_ZERO_TIME\n");
				break;
			}

			ret = set_zero_time_of_table(handle.name, handle.data.size);			
			break;
		case SOCK_SET_ACCOUNT_DEL_HOST:
			if(len != sizeof(struct account_handle_sockopt))
			{
				printk(KERN_ERR "account_set_ctl: wrong data size (%u != %zu) "
					"for SOCK_SET_ACCOUNT_DEL_HOST\n",
					len, sizeof(struct account_handle_sockopt));
				break;
			}

			if(copy_from_user(&handle, user, len))
			{
				printk(KERN_ERR "account_set_ctl: copy_from_user failed "
					"for SOCK_SET_ACCOUNT_DEL_HOST\n");
				break;
			}

			ret = del_host_from_table(handle.name, handle.data.macaddr);
			break;		
		case SOCK_SET_ACCOUNT_CLEAR_ONE_DATA:
			if(copy_from_user(table_name, user, len))
			{
				printk(KERN_ERR "account_set_ctl: copy_from_user failed "
					"for SOCK_SET_ACCOUNT_CLEAR_ONE_DATA\n");
				break;
			}
			ret = clear_one_table_data(table_name);
			break;
		case SOCK_SET_ACCOUNT_CLEAR_ALL_DATA:
			ret = clear_all_table_data();
			break;
		default:
			printk(KERN_ERR "account_set_ctl: unknown request %i\n", cmd);
	}
	return ret;
}

int account_get_ctl(struct sock *sk, int cmd, void *user, int *len)
{
	int ret = -EINVAL;
	
	if (!capable(CAP_NET_ADMIN))
		return -EPERM;
	
	switch(cmd){
		case SOCK_GET_ACCOUNT_TABLE_LIST:
			break;
		case SOCK_GET_ACCOUNT_TABLE_DATA:
			break;
		default:
			printk(KERN_ERR "account_get_ctl: unknown request %i\n", cmd);
	}

	return ret;
}


