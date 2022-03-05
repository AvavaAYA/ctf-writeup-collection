import subprocess
import time

with open('hello', 'rb') as f:
    hello_bytes = f.read()

print('Starting challenge...')
p = subprocess.Popen(["chroot", "--userspec=pwn:pwn", "/home/pwn", "./overflow"])

while True:
    time.sleep(1)
    print('Checking...')
    if subprocess.check_output(['su', 'pwn', '-c', f'/bin/cat /proc/{p.pid}/exe']) == hello_bytes:
        print(open('/root/flag').read())
        exit()
