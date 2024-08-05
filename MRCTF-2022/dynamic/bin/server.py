from sys import modules
from DynaFunc import DynaFunc

def func(fd):
	return 0

print("Please enter your code, EOF to finish")
max_length=10000
code=""
if_ok=False

while(len(code)<max_length):
	user_input=input("> ")
	if user_input == "EOF":
		if_ok=True
		break
	code+=user_input+"\n"

if(not if_ok):
	print("max length exceeded")
	sys.exit(42)

del modules['os']
builtin_keys = list(__builtins__.__dict__.keys())
for x in builtin_keys:
	if(x != 'id' and x != 'hex' and x != 'print' and x != 'range'):
		del __builtins__.__dict__[x]

pwn=DynaFunc(func)
pwn.set(code)
pwn(1)