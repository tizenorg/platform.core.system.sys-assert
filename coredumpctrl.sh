#!/bin/sh
MODE=none
VAL=none
#echo "tizen_platform_coredump_control"
case "$1" in
get)
	MODE=get
;;
set)
	MODE=set
;;

*)
echo "Usage: coredumpctrl.sh {get|set} {1|0}"
exit 1
esac

if [ "$MODE" = "set" ]; then
	case "$2" in
	1)
		VAL=1
	;;
	0)
		VAL=0
	;;
	*)
		echo "Usage: coredumpctrl.sh {get|set} {1|0}"
	exit 1
	esac
fi

source /etc/tizen-platform.conf
file="${TZ_SYS_ETC}/.coredump"

if [ "$MODE" = "set" ]; then
	if [ "$VAL" = "1" ] ; then
		touch "$file" 2>/dev/null
	elif [ "$VAL" = "0" ] ; then
		rm -f "$file" 2>/dev/null
	fi
	echo "You must reboot this target to apply the change!"
else
	if [ -e "$file" ]; then
		echo 1
	else
		echo 0
	fi
fi

exit 0
