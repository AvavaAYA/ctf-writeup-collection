import base64
import tempfile
import subprocess

import time

def main():
    print('Enter base64 encoded mixtape bytecode')

    data = input('>> ')
    try:
        data = base64.b64decode(data)
    except:
        print('invalid base64 encoding')
        return

    if len(data) > 8000:
        print('bytecode to long')
        return

    with tempfile.NamedTemporaryFile('wb') as f:
        f.write(data)
        f.flush()
        subprocess.run(['./mixtape', f.name])


if __name__ == '__main__':
    main()