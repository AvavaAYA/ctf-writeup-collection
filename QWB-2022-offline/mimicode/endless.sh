#!/bin/bash
step=30 #间隔的秒数，不能大于60
for (( i = 0; i < 60; i=(i+step) )); do
    $(python3 ./test.py)
    sleep $step
done
exit 0
