#!/bin/sh
export DISPLAY=:0
echo t > /proc/sysrq-trigger
/usr/bin/lockupinfo
