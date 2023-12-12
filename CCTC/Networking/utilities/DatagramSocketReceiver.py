#!/usr/bin/python3
import socket
import os
port = 2222
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM,0)
s.bind(('', port))
os.system("clear")
print ("Awaiting UDP Messages")
while True:
    data, addr = s.recvfrom(1024)
    address, port = addr
    print ("\nMessage Received: '%s'" % data.decode())
    print ("Sent by -", address, "port", port)
    s.sendto(b"Message received by the UDP Message Server!", addr)
