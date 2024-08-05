#!/usr/bin/env python3
#-*- coding: utf-8 -*-

from smpplib.client import Client
from smpplib.smpp import make_pdu
from smpplib import consts
from smpplib import exceptions
from smpplib import consts, exceptions
from smpplib.command import DeliverSM
from smpplib.gsm import gsm_encode
client = Client("172.16.9.37", 2775)
client.connect()

# client.bind_receiver()
b = make_pdu("bind_transmitter")
b.password = "wdbsmpp@"
b.system_id = "admin"
client.send_pdu(b)
resp = client.read_pdu()
print(resp.command, resp.status, consts.DESCRIPTIONS.get(resp.status, 'Unknown code'))


client.send_message(
    source_addr_ton=consts.SMPP_TON_INTL,
            source_addr="20086",
            dest_addr_npi=consts.SMPP_NPI_ISDN,
            dest_addr_ton=consts.SMPP_TON_INTL,
            destination_addr="1234",
            short_message=b"\x04\x4f\x04\x60\x04\x4e\x04\x2d\x04\x59\x04\x56\x04\x4e"
)

a = make_pdu('submit_sm', client=client,
    source_addr_ton=consts.SMPP_TON_INTL,
            source_addr="20086",
            dest_addr_ton=consts.SMPP_TON_INTL,
            destination_addr="1234",
            short_message=b"\x04\x4f\x04\x60\x04\x4e\x04\x2d\x04\x59\x04\x56\x04\x4e")

#  a.destination_addr
#  print(a.destination_addr)
resp = client.read_pdu()
print(resp.command, resp.status, consts.DESCRIPTIONS.get(resp.status, 'Unknown code'))
client.send_message(
    source_addr_ton=consts.SMPP_TON_ABBREV,
            source_addr="boss",
            dest_addr_ton=consts.SMPP_TON_INTL,
            destination_addr="1234",
            short_message=b"\x04\x52\x04\x30\x04\x62\x04\x11\x04\x52\x04\x9e\x04\x51\x04\x6c\x04\x5b\x04\xa4\x04\x67\x04\x65\x04\x4e\x04\x00\x04\x4e\x04\x0b"
)
resp = client.read_pdu()
print(resp.command, resp.status, consts.DESCRIPTIONS.get(resp.status, 'Unknown code'))
# ssm = make_pdu('submit_sm',     source_addr_ton=consts.SMPP_TON_INTL,
#             source_addr="20086",
#             dest_addr_ton=consts.SMPP_TON_INTL,
#             destination_addr="1234",
#             short_message="你中奖了")
# # ssm.status = consts.SMPP_CLIENT_STATE_OPEN
# client.send_pdu(ssm)
