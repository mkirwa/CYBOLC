#!/usr/bin/python3
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
ip_addr = '172.16.1.15'
port = 5309
message = b"Jenny"
s.sendto(message, (ip_addr, port))
data, addr = s.recvfrom(1024)
print(data.decode())


#!/usr/bin/python3
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
ip_addr = '172.16.1.15'
port = 5309
s.connect((ip_addr, port))
message = b"Jenny"
s.send(message)
data, conn = s.recvfrom(1024)
print(data.decode('utf-8'))
s.close()