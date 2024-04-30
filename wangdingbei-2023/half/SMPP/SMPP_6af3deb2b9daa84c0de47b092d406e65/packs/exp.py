#!/usr/bin/python3

import warnings
import pytest

from smpplib.client import Client
from smpplib.smpp import make_pdu
from smpplib import consts
from smpplib import exceptions


def run():
    client = Client("172.16.9.37", 2775)
    client.bind_transceiver("admin", "wdbsmpp@")

def main():
    run()

main()

