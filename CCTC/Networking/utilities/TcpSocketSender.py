#!/usr/bin/python3
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
ip_addr = '10.1.1.25'
port = 4869
s.connect((ip_addr, port))
message = b"Hi"
s.send(message)
data, conn = s.recvfrom(1024)
print(data.decode('utf-8'))
s.close()