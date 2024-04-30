#!/usr/bin/env python3
#-*- coding: utf-8 -*-

import requests
import subprocess

myuser = "18017887729"
mypwd  = "XUqHJNS#"

def get_question_status():
    command = f"curl -k -X GET --user {myuser}:{mypwd} https://172.20.1.11/api/get_question_status".split()
    subprocess.run(command)

def sub_answer(ans_flag):
    command = f'curl -k -d "answer={ans_flag}" -X POST -v --user {myuser}:{mypwd} https://172.20.1.11/api/sub_answer'.split()
    print(command)
    subprocess.run(command)

def reset_question(chal_id):
    command = f'curl -k -d "ChallengeID={chal_id}" -X POST -v --user {myuser}:{mypwd} https://172.20.1.11/api/reset_question'.split()
    #  print(command)
    subprocess.run(command)

def get_machines_info():
    command = f'curl -k -X GET --user {myuser}:{mypwd} https://172.20.1.11/api/get_machines_info'.split()
    subprocess.run(command)

def get_ranking():
    command = f'curl -k -X GET --user {myuser}:{mypwd} https://172.20.1.11/api/get_ranking'.split()
    subprocess.run(command)


def run():
    print("1 - 获取题目、积分信息")
    print("2 - 提交答案")
    print("3 - 重置题目")
    print("4 - 获取机器信息")
    print("5 - 获取排行榜数据")
    print("cmd> ")
    cmd = int(input())
    if cmd == 1:
        get_question_status()
    elif cmd == 2:
        sub_answer(input("flag> "))
    elif cmd == 3:
        reset_question(input("chal_id> "))
    elif cmd == 4:
        get_machines_info()
    elif cmd == 5:
        get_ranking()
    else:
        exit()

if __name__ == '__main__':
    while 1:
        run()

