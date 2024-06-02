import sys,os 
import socket
import time
import binascii
from random import *
from hexdump import * 

# python ReadingRegData.py -w 0 25000
IP  = "192.168.2.3"
PORT    = 502

delay = 0.1

def parseReceivedData(data):
    value = int(data[-2:], 16)
    return value

#000000000006 0106 0002 0001
def buildWriteCommand(slaveID, regIndex, newData):
    commandList = []
    for index in xrange(regIndex, regIndex+1):
        indexStr = hex(index)[2:].zfill(4)
        # 000000000006 0106 0002 0001
        newData = 0 if newData==0 else 0xff
        command = "{prefix}{slaveID}{action}{indexStr}{payload:02X}00".format(prefix = "0e1200000006", slaveID = slaveID, 
                                                                              action = "05", indexStr = indexStr, payload=newData )
        #command = "{prefix}{slaveID}{action}{indexStr}{payload:02X}00".format(prefix = "00000006", slaveID = slaveID, action = "05", indexStr = indexStr, payload=newData )

        print "[+] Writting to ModBus Slave: Building & Sending data {}".format(command.decode()), index, indexStr, newData
        commandList.append(command)
    return commandList

#01 1
#000000000006010110001
def buildReadCommand(slaveID, regIndex):
    commandList = []
    indexStr = hex(regIndex)[2:].zfill(4)
    command = "{prefix}{slaveID}{action}{indexStr}0001".format(prefix = "000000000006", slaveID = slaveID, 
                                                               action = "01", indexStr = indexStr)
    commandList.append(command)
    return commandList

def createSocket():
    try:
        skt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        return skt
    except socket.error as msg:
        print(msg)

def sendData(commandList):
    #skt = createSocket()
    #skt.connect((IP,PORT))

    for command in commandList:
        try:
            time.sleep(delay)
            hexdump(command.decode('hex'))
            skt.send(command.decode('hex'))
        except KeyboardInterrupt:
            print("[-] Exiting...")

def writeFileToModBusSlave(regIndex, newData):
    commandList = buildWriteCommand("01", regIndex, newData)
    sendData(commandList)

def readFromToModBusSlave(regIndex):
    commandList = buildReadCommand("01", regIndex)    
    skt.send(commandList[0].decode('hex'))
    print "[+] Reading from ModBus Slave: Index - ", 9, " - ", commandList[0]
    dataReceived = skt.recv(1024)
    recievedRegData = parseReceivedData(dataReceived.encode("hex"))
    print "[+] Received Data    " + dataReceived.encode("hex") + " => " + str(recievedRegData), "(", hex(recievedRegData), ")"
    return recievedRegData
     
     
# python ReadingCoilData.py -w 0 1
if __name__ == '__main__':
        if len(sys.argv) < 3 : 
            print "Usage : {} [-r coil_address]".format(sys.argv[0]) 
            print "                       [-w coil_address]"
            print "command:"
            print "-r address               : Read Coil"
            print "-w address value         : Write Coil"
            sys.exit(1) 
        elif len(sys.argv) == 3 :       # read
            option = sys.argv[1]
            regIndex = int(sys.argv[2])
        elif len(sys.argv) == 4 :
            option = sys.argv[1]
            regIndex = int(sys.argv[2]) # Write
            newData = int(sys.argv[3])
        
        skt = createSocket()
        skt.connect((IP,PORT))

        if option == "-r":
            RegData = readFromToModBusSlave(regIndex)
            print RegData
                        
        elif option == "-w" :
            writeFileToModBusSlave(regIndex, newData)                    
                    
