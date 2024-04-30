#!/bin/bash

# 设置环境变量，模拟HTTP请求
export REQUEST_METHOD="POST"
export CONTENT_TYPE="application/x-www-form-urlencoded"
export CONTENT_LENGTH="236" # 需要与实际POST数据的长度匹配

# 提供POST数据并调用CGI程序
echo -n "cmd=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" | gdbserver localhost:6666 ./check-ok.cgi
