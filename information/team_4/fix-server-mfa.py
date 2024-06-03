
# Date      : 2022-12-01
# Version   : 1.3
VERSION = 1.3

import serial
import random
import string
from socket import *
from select import *
from threading import *
#from hexdump import * 
import sys
import time
import sqlite3
import os.path 
import os 

# SQLite3
conn = sqlite3.connect('/home/pi/db/fp.db')
c = conn.cursor()
sql = "SELECT value FROM acs_users WHERE username='acs'"

# Fingerprint Value
fp_certification = "0xe5828c564f71fea3a12dde8bd5d270639e2bef9f260bd315cf00d25c75b32d7b"

CLI_port = 11451
door_id = "DOOR1234"
OPEN_DOOR_FILE = "/home/pi/open_gate" 

keypad_ser = serial.Serial(port='/dev/ttyKEYPAD', baudrate=9600, timeout=5)
rfid_ser   = serial.Serial(port='/dev/ttyRFID', baudrate=9600, timeout=5)
lcd_ser    = serial.Serial(port='/dev/ttyLCD', baudrate=9600, timeout=5)
finger_ser = serial.Serial(port='/dev/ttyFINGER', baudrate=9600, timeout=5)

generate_otp = lambda: ''.join(random.choice(string.digits) for _ in range(6))
message = generate_otp()

class Communicator(Thread):
    sock = None
    def __init__(self, sock):
        Thread.__init__(self)
        self.sock = sock

    def run(self):
        print("[Thr] Thread start ----------------------")
        exe = True

        while exe :
            try :
                rSock, wSock, eSock = select([self.sock], [], [], 1)
                for sock in rSock:
                    if sock == self.sock:
                        data = sock.recv(0x100)
                        

                        if message in data :
                            print("[Thr] Open the gate!")
                            f = open(OPEN_DOOR_FILE ,'wb')
                            f.close()
                            continue 

                        if "ENROLL_FP" in data : 
                            finger_ser.write('[CTRL] ENROLL_FP$') 
                            continue 

                        if data:
                            print("[Thr] {}".format(data))
                            lcd_ser.write(data)
                            lcd_ser.flush()
                        else :
                            exe = False 
            except e as Exception : 
                print("[Thr] except {}".format(e) )
                break 
                
        print("[Thr] Thread close ------------------------")
        self.sock.close()
        return

def report(msg):
    print "[+] REPORT:", msg 
    
    if 0 : 
        cs = socket(AF_INET, SOCK_STREAM)
        cs.settimeout(1)
        try: 
            cs.connect((addr, port))
            cs.send(msg)
        except:
            print("Could not connect %s:%d" % (addr, port))
        finally:
            cs.close() 

open_time = 0
wrong_time = 0
def ctrl_OPEN_DOOR() : 
    global open_time 
    if open_time + 3 < time.time() : 
        lcd_ser.write("[CTRL] DOOR_OPEN$")
        open_time = time.time() 

def ctrl_WRONG_PASS() : 
    global wrong_time 
    if wrong_time + 3 < time.time() : 
        lcd_ser.write("[CTRL] WRONG_PASS$")
        wrong_time = time.time()


def write_lcd_message(lcd_ser, message, display_time=5):
    lcd_ser.write("[CTRL] START_INPUT$")
    time.sleep(1)
    for i in message:
        print(i, "[CTRL] KEYIN=" + i + "$")
        lcd_ser.write("[CTRL] KEYIN=" + i + "$")
        time.sleep(0.1)
    time.sleep(display_time)
    lcd_ser.write("[CTRL] END_INPUT$") 

serverSock = socket(AF_INET, SOCK_STREAM)
serverSock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
serverSock.bind(('', CLI_port))
serverSock.listen(10)
connectionList = [serverSock]

print("[PPS_Server] Access Control (%s)" % (VERSION))

pw = '' 
check_passwd = 0 
fingerprint_validated = False

try:
    while True:
        # -------------------------------
        # Handle client connection  
        # -------------------------------
        if connectionList :
            #print("[+] server.select")
            rSock, wSock, eSock = select(connectionList, [], [], 0.25)
            for sock in rSock:
                if sock == serverSock:
                    clientSock, addrInfo = serverSock.accept()
                    generate_otp = lambda: ''.join(random.choice(string.digits) for _ in range(6))
                    message = generate_otp()
                    write_lcd_message(lcd_ser, message, 5)
                    comm = Communicator(clientSock)
                    comm.start()

        # -------------------------------
        # Checking keypad input 
        # -------------------------------
        if keypad_ser.inWaiting() > 0:
            # Read key one by one to display "*" on LCD screen 
            ch  = keypad_ser.read(); 
            print "[+] Keyin :", ch
            if not ch :
                continue
                
            # Password check start from keypad
            if ch == '*' :
                pw = ''
                check_passwd = 1 
                lcd_ser.write("[CTRL] START_INPUT$")
            elif ch == '#' : 
                if check_passwd == 1 : 
                    # check password 
                    if pw == "114514" :
                        if fingerprint_validated:
                            print "[+] [Keypad] Open door"  
                            ctrl_OPEN_DOOR()
                            fingerprint_validated = False
                        else:
                            print "[+] [Keypad] No fingerprint authentication"
                            fingerprint_validated = False
                            message = "FINGERPRINT NEEDED"
                            write_lcd_message(lcd_ser, message)
                    else : 
                        print "[-] [Keypad] Wrong pass"  
                        ctrl_WRONG_PASS()
                        time.sleep(1) 
                        lcd_ser.write("[CTRL] END_INPUT$")

                    pw = ''
                    check_passwd = 0 

            elif ch >= '0' and ch <= '9':
                if check_passwd == 1 : 
                    pw += ch 
                    lcd_ser.write("[CTRL] KEYIN=*$")

        # -------------------------------
        # Access try with fingerprint
        # -------------------------------
        if finger_ser.inWaiting() > 0:
            line = ''
            line  = finger_ser.readline();

            granted = False
            if len(line) > 1:
                if line.split()[0] == "Found" and line.split()[1] == "ID" and not fingerprint_validated:
                    print "[+] Message from [Finger]:", line.strip()
                    score = int(line.split()[-1])
                    if score > 200:
                        granted = True
                        print "[+] [Finger] Confidence score is high - Enter password"
                        message = "ENTER CODE"
                        write_lcd_message(lcd_ser, message)
                        fingerprint_validated = True
                    else : 
                        granted = False
                        print "[-] [Finger] Confidence score is too low"  
                elif "[DATA] FP_MISMATCH" in line : 
                    granted = False
                    print "[-] [Finger] Wrong pass"  
                    ctrl_WRONG_PASS()
                    report("UA")
                else : 
                    print "[+] Message from [Finger]:", line.strip() 
                    
            # DB 
            '''
            sql = "insert into access_log(acc_kind, acc_passwd, door_id, granted) values ('FG', '"+pw+"', '"+door_id+"', "+ str(granted) + ")"
            cur.execute(sql)
            db.commit();
            oldLine = line[0:-2] 
            '''

	# --------------------------------------------
	# File check 
	# --------------------------------------------
	if os.path.exists(OPEN_DOOR_FILE) : 
		print "[+] File Open door"
		ctrl_OPEN_DOOR()
		os.remove(OPEN_DOOR_FILE) 


        # -------------------------------
        # Register/Delete fingerprint
        # -------------------------------
        # TODO 
        # 

except KeyboardInterrupt:
    keypad_ser.close()


