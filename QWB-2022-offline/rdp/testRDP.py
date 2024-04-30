#!/usr/bin/env python3
"""Fake RDP Server"""
import socket
import time


def fake_server():
    """Start a socket on port 3389 and send init packets"""
    serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serversocket.bind(('0.0.0.0', 3389))
    serversocket.listen(5)
    while True:
        try:
            connection, address = serversocket.accept()
            print('Recieved connection from {}'.format(address))
            connection.recv(256)
            # Init packet of an NLA-enabled RDP server
            bts = bytearray.fromhex('030000130ed000001234000209080002000000')
            connection.send(bts)
            connection.recv(256)
            bts = 'arbitrary string'
            # Wait before sending a response (resulting in a client-side error)
            time.sleep(2)
            connection.send(bts.encode())
        except Exception:
            pass


if __name__ == "__main__":
    fake_server()