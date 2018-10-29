/*
 * timer_tool.c
 *
 *  Created on: Jun 19, 2017
 *      Author: pp
 */

#include <stdio.h>
#include "timer_tool.h"

void timer_tool_init(Timer* timer)
{
    timer->end_time = (struct timeval){0, 0};
}

char timer_tool_is_expired(Timer* timer)
{
    struct timeval now, res;
    gettimeofday(&now, NULL);
    timersub(&timer->end_time, &now, &res);
    return res.tv_sec < 0 || (res.tv_sec == 0 && res.tv_usec <= 0);
}

void timer_tool_countdown_ms(Timer* timer, unsigned int timeout)
{
    struct timeval now;
    gettimeofday(&now, NULL);
    struct timeval interval; 
   	interval.tv_sec = timeout / 1000;
	interval.tv_usec = (timeout % 1000) * 1000;
    timeradd(&now, &interval, &timer->end_time);
}

void timer_tool_countdown(Timer* timer, unsigned int timeout)
{
    struct timeval now;
    gettimeofday(&now, NULL);
    struct timeval interval;
   	interval.tv_sec = timeout;
	interval.tv_usec = 0;
    timeradd(&now, &interval, &timer->end_time);
}

int timer_tool_left_ms(Timer* timer)
{
    struct timeval now, res;
    gettimeofday(&now, NULL);
    timersub(&timer->end_time, &now, &res);
    //printf("left %d ms\n", (res.tv_sec < 0) ? 0 : res.tv_sec * 1000 + res.tv_usec / 1000);
    return (res.tv_sec < 0) ? 0 : res.tv_sec * 1000 + res.tv_usec / 1000;
}
