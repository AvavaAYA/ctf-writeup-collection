from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UcError, UC_HOOK_MEM_READ
from unicorn.x86_const import UC_X86_REG_RIP
from unicorn.unicorn_const import UC_ERR_READ_PROT
import hashlib
import sys, random, string, struct
import json
from filelock import FileLock
import time


CODEADDR = 0x1000000
DATAADDR = 0x2000000

def hook_mem_access(uc, access, address, size, value, user_data):
    if address < DATAADDR:
        raise UcError(UC_ERR_READ_PROT)

def run(CODE):
    mu = Uc(UC_ARCH_X86, UC_MODE_64)

    mu.mem_map(CODEADDR, 2 * 1024 * 1024)
    mu.mem_map(DATAADDR, 4096)
    mu.mem_write(CODEADDR, CODE)
    
    mu.hook_add(UC_HOOK_MEM_READ, hook_mem_access)

    try:
        rip = CODEADDR
        while True:
            mu.emu_start(rip, CODEADDR + len(CODE), count=1)
            ip = mu.reg_read(UC_X86_REG_RIP)
            if ip > rip:
                rip = ip
            else:
                break
    except UcError as e:
        print("ERROR: %s at 0x%x" % (e, rip))

    p = int.from_bytes(mu.mem_read(DATAADDR, 32), "little")
    q = int.from_bytes(mu.mem_read(DATAADDR + 32, 32), "little")
    assert abs(len(bin(p))-len(bin(q))) < 10

    target = int.from_bytes(hashlib.shake_128(CODE[2:]).digest(16) + hashlib.sha256(CODE[2:]).digest() + hashlib.md5(CODE[2:]).digest(), 'little')
    return abs(target - p*q)

def proof_of_work_okay(chall, solution, hardness):
    h = hashlib.sha256(chall.encode('ASCII') + struct.pack('<Q', solution)).hexdigest()
    return int(h, 16) < 2**256 / hardness

def random_string(length = 10):
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for _ in range(length))

def check_data_and_add_timestamp(data):
    ranklist=[]
    tokenlist=[]
    for it in data['data']:
        if it["teamtoken"] in tokenlist:
            print("dup teamtokoen")
            return False
        tokenlist.append(it["teamtoken"])
        ranklist.append(it["rank"])
    ranklist.sort()
    for i in range(len(ranklist)):
        if ranklist[i]!=i+1 and ranklist[i]!=ranklist[i-1]:
            print("wrong rank")
            return False

    data['updatetime']=time.time()
    return data

print("Can you factor the hash of yourself? Let's see how close you can get.")
print("Plz choose options:\n\t1. View leaderboard\n\t2. Run program")
choice = int(input("Your choice [1/2]: "))
if choice == 1:
    time.sleep(1)
    with FileLock("scores.json.lock", timeout=1):
        leaderb = json.load(open('scores.json','r'))
    print('------------LEADERBOARD------------')
    temp = sorted(leaderb.values())
    for t,s in sorted(leaderb.items(), key=lambda x:x[1]):
        print("{0:2} | {1:15} | {2}".format(temp.index(s)+1,teams[t], s))
    print('-----------------------------------')
elif choice == 2:
    challenge = random_string()
    print('Proof of work challenge: {}_{}'.format(2**20, challenge))
    sys.stdout.write('Your response? ')
    sys.stdout.flush()
    sol = int(input())
    if not proof_of_work_okay(challenge, sol, 2**20):
        print('Wrong :(')
        exit(1)
    token = input("Please input your team token: ")
    if token not in teams:
        print("No such team!")
        exit(1)
    with FileLock("scores.json.lock", timeout=1):
        leaderb = json.load(open('scores.json','r'))
    code = input("Give me your shellcode in HEX format: ")
    score = run(bytes.fromhex(code))
    if token not in leaderb or score < leaderb[token]:
        leaderb[token] = score
        with FileLock("scores.json.lock", timeout=1):
            json.dump(leaderb, open('scores.json','w'))
        data = {'data':[],'challenge':'hashrsa'}
        temp = sorted(leaderb.values())
        for t in leaderb:
            data['data'].append({"teamtoken":t, "rank":temp.index(leaderb[t])+1})
        data=check_data_and_add_timestamp(data)
        with FileLock("rank.json.lock", timeout=1):
            json.dump(data, open('rank.json','w'))
    print(score)
exit(0)
