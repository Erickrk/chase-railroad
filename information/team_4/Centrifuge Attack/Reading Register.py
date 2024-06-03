import sys,os 
import socket
import time
import binascii
from random import * 

IP  = "192.168.2.111"
#IP  = "127.0.0.1"
PORT    = 502

delay = 0.01

def parseReceivedData(data):
    value = int(data[-2:], 16)
    return value

def buildWriteCommand(slaveID, regIndex, newData):
    commandList = []
    for index in xrange(regIndex, regIndex+1):
        indexStr = hex(index)[2:].zfill(4)
        # 000000000006 0106 0002 0000
        newData = 0 if newData==0 else 0xff
        command = "{prefix}{slaveID}{action}{indexStr}{payload:02X}00".format(prefix = "000000000006", slaveID = slaveID, action = "05", indexStr = indexStr, payload=newData )

        print "[+] Writting to ModBus Slave: Building & Sending data {}".format(command.decode()), index, indexStr, newData
        commandList.append(command)
    return commandList

def buildReadCommand(slaveID, regIndex):
    commandList = []
    indexStr = hex(regIndex)[2:].zfill(4)
    command = "{prefix}{slaveID}{action}{indexStr}0001".format(prefix = "000000000006", slaveID = slaveID, action = "03", indexStr = indexStr)
    commandList.append(command)
    return commandList

def createSocket():
    try:
        skt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        return skt
    except socket.error as msg:
        print(msg)

def sendData(commandList):
    for command in commandList:
        try:
            time.sleep(delay)
            skt.send(command.decode('hex'))
        except KeyboardInterrupt:
            print("[-] Exiting...")

def writeFileToModBusSlave(regIndex, newData):
    commandList = buildWriteCommand("01", regIndex, newData)
    sendData(commandList)

def readFromToModBusSlave(regIndex):
    commandList = buildReadCommand("01", regIndex)
    skt.send(commandList[0].decode('hex'))
    print "[+] Reading from ModBus Slave: Index - ", regIndex, " - ", commandList[0]
    dataReceived = skt.recv(1024)
    recievedRegData = parseReceivedData(dataReceived.encode("hex"))
    print "[+] Received Data    " + dataReceived.encode("hex") + " => " + str(recievedRegData), "(", hex(recievedRegData), ")"
    return recievedRegData
     
     
if __name__ == '__main__':
    skt = createSocket()
    skt.connect((IP,PORT))
    for i in xrange(0, 100):
    	regIndex = i
    	readFromToModBusSlave(regIndex)
    
    writeFileToModBusSlave(regIndex, 0)
    time.sleep(5)
    skt.shutdown(socket.SHUT_RDWR)
    #while (1) : 
     #   writeFileToModBusSlave(regIndex, 0)                    
      #  for i in range(4) : 
       #     print "[+] Increasing Moter speed ... "
        #    time.sleep(0.5) 
        #writeFileToModBusSlave(regIndex, 1)                    
        #for i in range(4) : 
         #   print "[+] Decreasing Moter speed ... "
          #  time.sleep(0.5) 
        
