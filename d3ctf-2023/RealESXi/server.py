import os
import subprocess
import socket
import struct


def Challenge(s):
    dom = 4  # globalVMDom
    sz = struct.unpack("<I", s.recv(4))[0]
    if sz > 1024 * 256:
        s.send(b"File too big.")
        s.close()
        return
    data = b''
    while len(data) < sz:
        data += s.recv(sz - len(data))
        print(len(data))
    try:
        os.unlink("/usr/lib/test")
    except:
        pass
    open("/usr/lib/test", "wb").write(data)
    os.chmod("/usr/lib/test", 0o755)
    try:
        resp = subprocess.check_output(["/usr/lib/test", "++securitydom=%d" % dom])
        s.send(struct.pack("<I", len(resp)))
        s.send(resp)
    except:
        msg = b"exec failed"
        s.send(struct.pack("<I", len(msg)))
        s.send(msg)
    s.close()


os.system('esxcli network firewall set --enabled false')
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 1000))
s.listen(5)

while True:
    (client, addr) = s.accept()
    print("Got connection from", addr)
    Challenge(client)
