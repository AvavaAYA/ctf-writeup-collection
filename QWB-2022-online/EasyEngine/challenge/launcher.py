import sys
import io
import subprocess
from random import choice, seed, randint
from string import hexdigits
from time import sleep

def main():

  reader = io.BufferedReader(sys.stdin.buffer, buffer_size=1)
  '''
  part_hash = ''.join([choice(hexdigits) for _ in range(5)]).lower()
  salt = ''.join([choice(hexdigits) for _ in range(4)]).lower()
  print('[*] Please find a string that md5(str + ' + salt + ')[0:5] == ' + part_hash, flush=True)
  print('> ')
  string = reader.readline()
  if (md5(string + salt).hexdigest()[:5] != part_hash):
    print('[-] Wrong hash, exit...', flush=True)
    return
  '''
  print('File size: ', flush=True)
  input_size = int(reader.readline())
  if input_size <= 0 or input_size > 65536:
    print('Invalid file size.', flush=True)
    return

  print('File data: ', flush=True)
  input_data = reader.read(input_size)
  with open('/tmp/data', 'wb') as f:
    f.write(input_data)

  print('Start to execute...', flush=True)
  process = subprocess.Popen(
      ['/challenge/njs', '/tmp/data'],
      stdin=subprocess.DEVNULL,
      stdout=subprocess.PIPE,
      stderr=subprocess.PIPE)
  outs, errs = process.communicate()
  sys.stdout.buffer.write(outs)
  sys.stdout.buffer.write(errs)
  sys.stdout.flush()


if __name__ == '__main__':
  main()

