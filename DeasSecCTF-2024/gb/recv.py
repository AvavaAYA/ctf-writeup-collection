#!/usr/bin/python3

import tempfile
import os
import subprocess
import random
import string
import base64

def generate_temp_filename() -> str:
    random_string = ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))
    return os.path.join(tempfile.gettempdir(), random_string)

def main():
    filename = generate_temp_filename()
    with open(filename, "wb+") as f:
        blob = input("");
        blob = base64.b64decode(blob)
        f.write(blob)
    
    print(filename)


if __name__ == "__main__":
    main()
