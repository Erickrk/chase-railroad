import pyshark
import socket
from construct import *
import time
import binascii


# Define the FEnet structure
FEnet = Struct(
    'Company_ID' / Bytes(8),
    'Reserved' / Int16ul,
    'PLC_Info' / Int16ul,
    'CPU_Info' / Int8ul,
    'Source_Frame' / Int8ul,
    'Invoke_ID' / Int16ul,
    'Length' / Int16ul,
    'FEnet_Position' / Int8ul,
    'Reserved2' / Int8ul,
    'Instruction' / Int16ul,
    'Data_Type' / Int16ul,
    'Reserved3' / Int16ul,
    'Variable_Count' / Int16ul,
    'Variable_Length' / Int16ul,
    'Variable' / Bytes(4),
    'Data_Length' / Int16ul,
    'Data_Value' / Int8ul,
)

TARGET_IP = "192.168.1.4"
TARGET_PORT = 2004

VALID_BLACKOUT_PACKET = b'\x4c\x53\x49\x53\x2d\x58\x47\x54\x00\x00\x11\x12\x34\x22\x3d\x6c\x11\x00\x00\xda\x58\x00\x00\x00\x00\x00\x01\x00\x04\x00\x25\x4d\x58\x31\x01\x00\x01'

def send_recovery_flood():
    clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    clientSocket.connect((TARGET_IP, TARGET_PORT))
    recovery_packet = FEnet.parse(VALID_BLACKOUT_PACKET)
    recovery_packet['Variable'] = '%MX1'.encode()
    recovery_packet['Data_Value'] = 1
    for _ in range(100):  # Flood with 100 recovery packets
        clientSocket.send(FEnet.build(recovery_packet))
        time.sleep(0.01)  # Small delay to avoid overwhelming the network
    clientSocket.close()

def packet_handler(pkt):
    try:
        print(pkt.tcp.payload)
        #print(f'pkt value: {pkt}')
        raw_data = bytes(pkt.tcp.payload)
        print(f'Recv pkt: {raw_data}')
        parsed_packet = FEnet.parse(raw_data)
        print(f'Recv pkt: {parsed_packet}')
        
        if parsed_packet['Instruction'] == 0x0058 and parsed_packet['Variable'] == b'%MX2'.encode() and parsed_packet['Data_Value'] == 1:
            if raw_data == VALID_BLACKOUT_PACKET:
                print("Valid blackout event detected.")
            else:
                print("Invalid blackout packet detected. Triggering recovery flood...")
                send_recovery_flood()
    except Exception as e:
        print(f"Error processing packet: {e}")

def main():
    capture = pyshark.LiveCapture(interface='enp7s0', bpf_filter='tcp port 2004')
    capture.apply_on_packets(packet_handler)

if __name__ == "__main__":
    main()
