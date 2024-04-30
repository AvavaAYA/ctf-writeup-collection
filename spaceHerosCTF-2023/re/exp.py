import time
from subprocess import *
import string
import sys

# Establish the command to count the number of instructions, pipe output of command to /dev/null
command = "perf stat -x : -e instructions:u '" + sys.argv[1] + "' 1>/dev/null"


#we assume the flag is less than 60 in length
lenDi = dict.fromkeys(range(6,60),0)

for i in range(6,60):
    #6 trials of each possibility, the counts returned are nondeterministic
    for _ in range(6):

        # Give the program the new input to test, and grab the store the output of perf-stat in target_output
        inp = f"{i * 's'}\n".encode("ASCII")
        target = Popen(command, stdout=PIPE, stdin=PIPE, stderr=STDOUT, shell=True)
        target_output, _ = target.communicate(input=inp)

        # Filter out the instruction count
        try:
            instructions = int(target_output.split(b':')[0])
        except ValueError as e:
            print(target_output)
            raise e

        lenDi[i] += instructions

length = max(lenDi, key=lenDi.get )



# we
print(length)
#Iterate through the flag character by character to get desired output
flag = 'a'*length
flag = list(flag)
v = [c for c in string.printable.split()[0]]
for i in range(len(flag)):
    di = dict.fromkeys(v,0)
    for l in v:
            flag[i] = l
            att = "".join(flag)

            li = [0] * 5
            for _ in li :
                # Start a new process for the new character

                # Give the program the new input to test, and grab the store the output of perf-stat in target_output
                inp = f'{att}\n'.encode("ASCII")
                target = Popen(command, stdout=PIPE, stdin=PIPE, stderr=STDOUT, shell=True)
                target_output, _ = target.communicate(input=inp)
                target.terminate()
                # Filter out the instruction count
                try:
                    instructions = int(target_output.split(b':')[0])
                    di[l] += instructions
                #sometimes perf doesnt work so if it fails just iterate again lol
                except ValueError as e:
                    print(target_output)
                    li.append(1)

    print(di)
    flag[i] = max(di, key=di.get )

    # Add the character with the highest instruction count to flag, print it, and restart

    print(f"".join(flag))
