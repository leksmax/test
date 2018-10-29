/*
 * timer_tool.h
 *
 *  Created on: Jun 19, 2017
 *      Author: pp
 */

#ifndef _TIMER_TOOL_H_
#define _TIMER_TOOL_H_

#include <sys/time.h>

typedef struct Timer
{
    struct timeval end_time;
} Timer;

void timer_tool_init(Timer* timer);
char timer_tool_is_expired(Timer* timer);
void timer_tool_countdown_ms(Timer* timer, unsigned int timeout);
void timer_tool_countdown(Timer* timer, unsigned int timeout);
int timer_tool_left_ms(Timer* timer);

#endif /* GIT_HOME_VPPNCTRL_GIT_PROTOBUF_TIMER_TOOL_H_ */
