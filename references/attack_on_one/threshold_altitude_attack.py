import os, sys 
import time
import socket
import binascii
from random import *
from hexdump import * 

IP 	= "192.168.2.3"
PORT 	= 502

current_altitude = 35000

def parseReceivedData(data):
	value = int(data[-4:], 16)
	return value

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


def buildWriteCommand(slaveID, regIndex, newData):
    commandList = []
    for index in xrange(regIndex, regIndex+1):
        indexStr = hex(index)[2:].zfill(4)
        # 000000000006 0106 0002 0001
        newData = 0 if newData==0 else 0xff
        command = "{prefix}{slaveID}{action}{indexStr}{payload:02X}00".format(prefix = "0e1200000006", slaveID = slaveID, action = "05", indexStr = indexStr, payload=newData )
        #command = "{prefix}{slaveID}{action}{indexStr}{payload:02X}00".format(prefix = "00000006", slaveID = slaveID, action = "05", indexStr = indexStr, payload=newData )

        print "[+] Writting to ModBus Slave: Building & Sending data {}".format(command.decode()), index, indexStr, newData
        commandList.append(command)
    return commandList


def sendData(commandList):
    for command in commandList:
        try:
            time.sleep(0.1)
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

if __name__ == '__main__':
    while True:
        skt = createSocket()
        skt.connect((IP,PORT))
        current_altitude = readFromToModBusSlave(0)
        print(current_altitude)
        if int(current_altitude) < 2000:
            writeFileToModBusSlave(0, 0) 
        skt.close()
        time.sleep(1)
        
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
