#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include "attachdevice.h"
#include "process_tool.h"

char *attach_info = NULL;
pthread_mutex_t attach_lock;

void *update_attach_device(void *arg)
{
	pthread_detach(pthread_self());
	while(1)
	{
		char *new_attach = process_tool_run_cmd("soap-tool get_attachdevice");
		if (new_attach)
		{
			pthread_mutex_lock(&attach_lock);
			if (attach_info)
			{
				free(attach_info);
			}
			attach_info = new_attach;
			pthread_mutex_unlock(&attach_lock);
		}
		sleep(30);
	}
	return NULL;
}

int create_attach_device_thread()
{
	int ret = -1;
	pthread_mutex_init(&attach_lock, NULL);
	pthread_t nid;
	ret = pthread_create(&nid, NULL, update_attach_device, NULL);
	return ret;
}

char* fetch_attach_device()
{
	char *ret = NULL;
	pthread_mutex_lock(&attach_lock);
	if (attach_info)
	{
		ret = strdup(attach_info);
	}
	pthread_mutex_unlock(&attach_lock);
	return ret;
}
