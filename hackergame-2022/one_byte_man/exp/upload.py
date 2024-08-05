#!/usr/bin/python3

import gzip
import base64
import sys


def raw_to_b64gzip(raw):
    # since we have gzip, we do not need upx any more
    # suitable for:
    # base64 -d <<EOF|gzip -d > out
    # ...
    # EOF
    return base64.b64encode(gzip.compress(raw)).decode('ascii')

if __name__=='__main__':
    if len(sys.argv) < 2:
        print('Convenient script for shell command to drop a file.')
        print('Usage:\n\t', sys.argv[0],
              'file_to_upload [target_path]', file=sys.stderr)
        exit(1)

    filename = sys.argv[1]
    with open(filename, 'rb') as f:
        raw = f.read()

    if len(sys.argv) > 2:
        target_filename = sys.argv[2]
    else:
        target_filename = filename

    cmd = []
    cmd.append('/busybox base64 -d <<EOF | /busybox gzip -d > '+target_filename)

    payload = raw_to_b64gzip(raw)
    split = 80

    for i in range(0, len(payload), split):
        cmd.append(payload[i:i+split])
    cmd.append('EOF')
    cmd.append('# chmod a=rx '+target_filename+' && ./'+target_filename)

    print('\n'.join(cmd))
