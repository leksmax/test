#include <linux/netfilter/x_tables.h>
#include <ipt_account.h>

int account_set_ctl(struct sock *sk, int cmd, void *user, unsigned int len)
{
	int ret = -EINVAL;
	uint8_t limit_direction = NOT_LIMIT;
	struct account_handle_sockopt handle;
	char table_name[IPT_ACCOUNT_NAME_LEN + 1] = {0};

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	memset(&handle, 0x0, sizeof(struct account_handle_sockopt));
	switch(cmd){
		case SOCK_SET_ACCOUNT_ALL_LIMIT_SIZE:
		case SOCK_SET_ACCOUNT_DST_LIMIT_SIZE:
		case SOCK_SET_ACCOUNT_SRC_LIMIT_SIZE:
		case SOCK_SET_ACCOUNT_NOT_LIMIT_SIZE:
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
			
			if(cmd == SOCK_SET_ACCOUNT_ALL_LIMIT_SIZE)
				limit_direction = LIMIT_ALL;
			else if(cmd == SOCK_SET_ACCOUNT_DST_LIMIT_SIZE)
				limit_direction = LIMIT_DOWNLOAD;
			else if(cmd == SOCK_SET_ACCOUNT_SRC_LIMIT_SIZE)
				limit_direction = LIMIT_UPLOAD;
			else
				limit_direction = NOT_LIMIT;
			
			ret = set_limit_size_of_table(limit_direction, handle.name, handle.data.size);
			break;
			
		case SOCK_SET_ACCOUNT_AGING_TIME:
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

			ret = set_aging_time_of_table(handle.name, handle.data.size);			
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
		
		case SOCK_SET_ACCOUNT_SYNC_ALL_DATA:
			if (len < sizeof(struct account_handle_sockopt)) 
			{
				printk("account_get_ctl: wrong data size (%u != %zu)"
					" for SOCK_SET_ACCOUNT_SYNC_ALL_DATA\n",
					len, sizeof(struct account_handle_sockopt));
				break;
			}

			if (copy_from_user(&handle, user, sizeof(struct account_handle_sockopt)))
			{
				return -EFAULT;
			}
			ret = sync_data_of_table(handle);
			break;
			
		default:
			printk(KERN_ERR "account_set_ctl: unknown request %i\n", cmd);
	}
	return ret;
}

int account_get_ctl(struct sock *sk, int cmd, void *user, int *len)
{
	int ret = -EINVAL;
	char data_buf[512] = {0};
	struct account_handle_sockopt handle;
	struct traffic_meter_info data;

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	memset(&handle, 0x0, sizeof(struct account_handle_sockopt));

	switch(cmd){
		case SOCK_GET_ACCOUNT_TABLE_LIST:

			ret = get_table_name_list(data_buf, sizeof(data_buf));
	
			if (copy_to_user(user, data_buf, sizeof(data_buf)))
			{
				printk("account_get_ctl: copy data to user (%u != %zu)"
					" for SOCK_GET_ACCOUNT_TABLE_LIST\n",
					*len, sizeof(struct account_handle_sockopt));
				return -EFAULT;
			}

			break;
		case SOCK_GET_ACCOUNT_TABLE_DATA:
			if (*len < sizeof(struct account_handle_sockopt)) 
			{
				printk("account_get_ctl: wrong data size (%u != %zu)"
					" for SOCK_GET_ACCOUNT_TABLE_DATA\n",
					*len, sizeof(struct account_handle_sockopt));
				break;
			}

			if (copy_from_user(&handle, user, sizeof(struct account_handle_sockopt)))
			{
				return -EFAULT;
			}

			memset(&data, 0x0, sizeof(struct traffic_meter_info));
			ret = get_account_data_of_table(handle.name, &data);

			if (copy_to_user(user, &data, sizeof(struct traffic_meter_info)))
			{
				printk("account_get_ctl: copy data to user (%u != %zu)"
					" for SOCK_GET_ACCOUNT_TABLE_DATA\n",
					*len, sizeof(struct account_handle_sockopt));
				return -EFAULT;
			}
			break;
		default:
			printk(KERN_ERR "account_get_ctl: unknown request %i\n", cmd);
	}

	return ret;
}
