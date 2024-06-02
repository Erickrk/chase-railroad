import os, sys 

def print_menu() :
    print "\t1) status  "
    print "\t2) turn off runway light"
    print "\t3) turn on runway light"
    print "\t4) read altitue "
    print "\t5) manuplate altitue "
    print "\t6) exit"

def status() : 
    print "[+] Runway Status ----------------------------------" 
    print "[+] Left Runway Light Status : "
    os.system("python2.7 ReadingCoilData.py -r 0")
    #print "[+] Right Runway Light Status : "
    #os.system("python ReadingCoilData.py -r 1")
    #print "[+] Runway Number : "
    #os.system("python ReadingRegData.py -r 1")
    print "[+] Runway Altitue : "
    os.system("python2.7 ReadingRegData.py -r 0")

def turn_off() :
    os.system("python2.7 ReadingCoilData.py -w 0 0")
    #os.system("python ReadingCoilData.py -w 1 0")

def turn_on() :
    os.system("python2.7 ReadingCoilData.py -w 0 1")
    #os.system("python ReadingCoilData.py -w 1 1")

status() 

while 1 : 
    print_menu() 
    m = raw_input("> ") 
    m = int(m)
    if m == 1 : 
        status() 
    elif m == 2 : 
        turn_off() 
    elif m == 3 : 
        turn_on() 
    elif m == 4 : 
        print "[+] Runway Altitue : "
        os.system("python2.7 ReadingRegData.py -r 0")
    elif m == 5 : 
        alt = raw_input("altitude = ") 
        os.system("python2.7 ReadingRegData.py -w 0 {}".format(alt))
    elif m == 6 : 
        break
    else : 
        pass 



