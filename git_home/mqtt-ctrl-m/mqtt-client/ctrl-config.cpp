#include "system-config.h"
#include "ctrl-config.h"
#include "cJSON.h"

void config_set_members(cJSON* members)
{
	//TODO:set current members to config file
	//TODO:tell vppnctrl reload config
}

cJSON* config_get_members()
{
	//TODO:get current members from config file
	cJSON* ret = NULL;
	return ret;
}

void config_add_member(cJSON* add_member)
{
	cJSON* members = config_get_members();
	if (!members)
	{
		members = cJSON_CreateArray();
	}
	//TODO:Add add_member to members
	config_set_members(members);
	return;
}

void config_del_member(cJSON* del_member)
{
	cJSON* members = config_get_members();
	if (!members)
	{
		members = cJSON_CreateArray();
	}
	//TODO:Del del_member from members
	config_set_members(members);
	return;
}
