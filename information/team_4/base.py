# Date      : 2022-12-01
# Version   : 1.3
VERSION = 1.3

import serial
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

CLI_port = 9999
door_id = "DOOR1234"
OPEN_DOOR_FILE = "/home/pi/open_gate" 

keypad_ser = serial.Serial(port='/dev/ttyKEYPAD', baudrate=9600, timeout=5)
rfid_ser   = serial.Serial(port='/dev/ttyRFID', baudrate=9600, timeout=5)
lcd_ser    = serial.Serial(port='/dev/ttyLCD', baudrate=9600, timeout=5)
finger_ser = serial.Serial(port='/dev/ttyFINGER', baudrate=9600, timeout=5)

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

                        if "create" in data : 
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

serverSock = socket(AF_INET, SOCK_STREAM)
serverSock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
serverSock.bind(('', CLI_port))
serverSock.listen(10)
connectionList = [serverSock]

print("[PPS_Server] Access Control (%s)" % (VERSION))

pw = '' 
check_passwd = 0 

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
                    if pw == "3164970" :
                        print "[+] [Keypad] Open door"  
                        ctrl_OPEN_DOOR()
                    else : 
                        print "[-] [Keypad] Wrong pass"  
                        ctrl_WRONG_PASS()
                        time.sleep(1) 
                        lcd_ser.write("[CTRL] END_INPUT$")

                    pw = ''
                    check_passwd = 0 

                    # DB update 
                    '''
                    sql = "select * from kp_pass where passwd='"+pw+"'" 
                    n = cur.execute(sql)
                    if n > 0 :
                        row = cur.fetchone()
                        ctrl_OPEN_DOOR()
                        if row[2] == 1 :
                            report("PP")
                    else :
                        ctrl_WRONG_PASS()
                        lcd_ser.write("[CTRL] END_INPUT$")
                        report("UA")

                    sql = "insert into access_log(acc_kind, acc_passwd, door_id, granted) values ('KP', '"+pw+"', '"+door_id+"', "+str(n>0)+")"
                    cur.execute(sql)
                    db.commit();
                    '''
            elif ch >= '0' and ch <= '9':
                if check_passwd == 1 : 
                    pw += ch 
                    lcd_ser.write("[CTRL] KEYIN=*$")
                        

        # -------------------------------
        # Access try with rfid 
        # -------------------------------
        if rfid_ser.inWaiting() > 0:
            line = ''
            line  = rfid_ser.readline();

            if "[DATA] UID=" in line : 
                pw = line[len("[DATA] UID="):]
                
                # Hardcoded password --------------------
                if "fe1337" in pw :  #3609598
                #if "4b374651" in pw : # 1261913681 
                    print "[+] Door open"
                    ctrl_OPEN_DOOR()
                else :
                    ctrl_WRONG_PASS()
                    print "[-] [RFID] WRONG_PASS:", pw 
            else : 
                print "[+] Message from [RFID] :", line 

            # DB 
            '''
            sql = "select * from rf_pass where passwd='"+pw+"'" 
            n = cur.execute(sql)
            if n > 0 :
              ctrl_OPEN_DOOR()
              row = cur.fetchone()

             # if row[2] == 1 :
             #   report("PP")
            else :
              ctrl_WRONG_PASS()
              report("UA")

            sql = "insert into access_log(acc_kind, acc_passwd, door_id, granted) values ('RF', '"+pw+"', '"+door_id+"', "+str(n>0)+")"
            cur.execute(sql)
            db.commit();
            '''

        # -------------------------------
        # Access try with fingerprint
        # -------------------------------
        if finger_ser.inWaiting() > 0:
            line = ''
            line  = finger_ser.readline();

            granted = False 
            if "[DATA] FP=" in line : 
                pw = line[len("[DATA] FP="):]
                pw = int(pw) 
                print "[+] FP : {} (pw={})".format( line, pw )
                if pw >= 1 and pw <= 127:
                    '''
                    if pw == 123 or pw == 4: # For CTF
                        for row in c.execute(sql):
                            print ">>>>>>>", row[0]
                            if fp_certification == row[0]:
                                granted = True
                                print "[+] [Finger] DB Open door"
                                ctrl_OPEN_DOOR()
                            else:
                                granted = False
                                ctrl_WRONG_PASS()
                                report("UA")
                    elif pw == 2 or pw == 3 or pw == 5 or pw == 6:
                        granted = True
                        print "[+] [Finger] Open door"
                        ctrl_OPEN_DOOR()
                    '''
                    granted = True
                    print "[+] [Finger] Open door"
                    ctrl_OPEN_DOOR()
                else : 
                    granted = False
                    print "[-] [Finger] Wrong pass"  
                    ctrl_WRONG_PASS()
                    report("UA")
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