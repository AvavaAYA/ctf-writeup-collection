#!/bin/bash
echo -n 'index: '
read arg1
echo -n 'value: '
read arg2
./runme "$arg1" "$arg2"
