#!/bin/sh

start()
{
	bird &
}

stop()
{
	killall bird
}

usage()
{
	echo "bird.sh start | stop"
}

case "$1" in
	"start")
		start
	;;
	"stop")
		stop
	;;
	*)
		usage
	;;
esac
