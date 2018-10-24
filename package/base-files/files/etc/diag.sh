#!/bin/sh
# Copyright (C) 2006-2009 OpenWrt.org

set_state() { 
    case "$1" in
    preinit)
        insmod leds-gpio
        insmod ledtrig-default-on
        insmod ledtrig-timer
        ledcontrol -n power -c amber -s blink
        ;;
    failsafe)
        ledcontrol -n power -c amber -s fast_blink
        ;;
    done)
        ledcontrol -n power -c green -s on
        ;;
    esac
}
