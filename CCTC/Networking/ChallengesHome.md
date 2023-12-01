# Network Recon # 

Field                       Command

Hostname                    cat /etc/hostname

Usrname,                    pass should already have. It'll be usrname password

Ip address & mac addr       ip addr

OS                          uname -a

Open ports                  tcp ports: netstat -antp | grep -i listen or nc localhost 23 or telnet localhost 23

Copy the scan.sh file

Run the file: ./scan.sh

Network addr: 172.16.120

Host range: 1

Ending host range: 1

Ports: 21-23 80

This will give the IP of the next host/router

Now, we know the IP let get into that IP

Ssh vyos@172.16.120.1

To start the flag

1. dig txt networking-ctfd-1.server.vta

On answer section there is a file: cmVhZHlfc2V0X3NjYW4=

Decode rhis: from base64 to UTF-8

2. To get the hostname 

ssh net{N}_studentX@provided_ip_address # provided in the notification i.e. ssh net4_student25@10.50.24.163 then enter the password25

after that, 

Ssh vyos@172.16.120.1 # Enter the provided password

3. How many host(s) did you discover on the DMZ Net? (excluding the router)

nmap –sn 172.16.101.30/27 --- gives how many hosts are up


results: 

Starting Nmap 7.70 ( https://nmap.org ) at 2023-11-30 02:07 UTC
Nmap scan report for 172.16.101.2
Host is up (0.0042s latency).
Nmap scan report for 172.16.101.30
Host is up (0.0047s latency).
Nmap done: 32 IP addresses (2 hosts up) scanned in 1.98 seconds

4.How many well-known open TCP ports did you discover on the device(s)?

- 1

nmap -sT -p- 172.16.101.30 and nmap -sT -p- 172.16.101.2

There is tcp port 22 open

6. What well-known port(s) are open on the system(s)?

Port 22


7. Donovian Man in the Middle 5
    Level I Challenge

What is it’s hostname of the device directly connected to the Donovian boundary on eth1?

example:
student@HOSTNAME-student-1-7cgpe

Copy only the name where HOSTNAME is at


show configuration commands



7. Hostname Ssh@172.16.101.2 --- red-dmz-host-1



vyos@172:~$ show configuration commands
set interfaces ethernet eth0 address '172.16.120.1/30'
set interfaces ethernet eth0 description 'INTERNET'
set interfaces ethernet eth1 address '172.16.120.6/30'
set interfaces ethernet eth1 description 'REDNET'
set interfaces ethernet eth1 ip ospf authentication md5 key-id 120 md5-key 'red'
set interfaces ethernet eth2 address '172.16.101.30/27'
set interfaces ethernet eth2 description 'DMZ'

nmap –sn 172.16.120.6/30


net4_student25@red-internet-host:~$ for i in {1..29}; do nc -nvzw1  172.16.120.$i 20-23 80 2>&1 & done | grep -E 'succ|open'
(UNKNOWN) [172.16.120.2] 22 (ssh) open
(UNKNOWN) [172.16.120.1] 22 (ssh) open
(UNKNOWN) [172.16.120.6] 22 (ssh) open
(UNKNOWN) [172.16.120.5] 22 (ssh) open
(UNKNOWN) [172.16.120.9] 22 (ssh) open
(UNKNOWN) [172.16.120.10] 22 (ssh) open




8. Donovian Inner Boundary: What is the hostname of the device directly connected to teh system discovered in Donovian Man in the Middle, on eth1?

show int and loook at ip address for eth1

look up subnet mask

realize the only other available address is a .9 because its a /30 ssh vyos@172.16.120.9

RED-POP

9. HOSTS Discovery: How many host(s) did you discover on the HOSTS Net? (Excluding the router)

show int on 172.16.120.9

eth1 has ip address 172.16.182.126/27

run ./scan.sh and enter: -172.16.182, 97,125, 21-23 80 (remember to use subnet calculator)

4 unique hosts found (look at ip's some may have multiple ports open)

./scan.sh 

-> image avail 



net4_student25@red-internet-host:~$ for i in {97..127}; do nc -nvzw1  172.16.182.$i 20-23 80 2>&1 & done | grep -E 'succ|open'

172.16.182.126/27  


RUN THIS ---
for i in {97..127}; do nc -nvzw1  172.16.182.$i 20-23 80 2>&1 & done | grep -E 'succ|open'




10. What well-known port(s) are open on the system? (Separate ports with a comma and no space)

netstat -antp 

22,80

-> image avail 

11. What is the Hostname of the system? T4

example:

student@HOSTNAME-student-1-7cgpe

cat /etc/hostname

-> image avail 

12. Interface with the web service on the 172.16.182.110 host. The hint provides a suggestion on the ports above the well-known that you will need to recon. What is the range?

example:

xxxx-xxxx

wget -r 172.16.182.110

Pcmanfm-----open the folder 172.16.182.110 --- open the file hint-01.png

1980-1989 --- the range of only 80 so it will be 80-89

13. What UDP ports did you find that were open? (List them in in order and separate the ports with a comma and no space.) NOTE: Look in the same port range mentioned in your hint for this target.

sudo nmap -sU -p 1980-1989 -v 172.16.182.110

-> image avail 

Open|filtered: Nmap places ports in this state when it is unable to determine whether a port is open or filtered.

14. What instrument was being played on UDP port 1984?

To figure this out we need to listen to the port 1984... so using netcat

nc -u 172.16.182.110 1984 # Enter this command....

Here, -u means listen on UDP port

GET / #this means get the request from the IP 110 port 1984

Answ: saxophone_highlighted part

-> image avail 

15. What color were the socks on the person in the left changing room on UDP port 1989?

nc -u 172.16.182.110 1989 # Etner this command the color is answer Blue 

-> image avail 

16. What TCP ports in the range did you find that were open? (List them in order and separate the ports with a comma and no space)

./scan.sh

-> image avail 

17. What was on the license plate in the link on TCP port 1980?

nc -u 172.16.182.110 1980

5JB-738_091_

-> image avail 

18. Where did it say to bless the rains on TCP port 1982?

a. Africa_

19. How many (total) miles did they go on TCP port 1988?

a. 1000

20. Who joined the ARMY on TCP port 1989?

elvis

21. What is the Hostname of the system? T4

hostname # Enter this command 

-> image avail 

22. What well-known port(s) are open on the system? (separate ports with a comma and no space)

./scan.sh # Enter this command 

-> image avail 

23. What is the Hostname of the system?

a. Red-host-3

24. What well-known port(s) are open on the system? (separate ports with a comma and no space) T6

./scan.sh # Enter this command 

-> image avail 

25. What is the hostname of the device directly connected to the system discovered in Donovian Inner boundary, on eth2? ssh@172.16.140.5

red-pop2

26. What are the host ip address(s) in the DMZ2 network? (list only the last octet separated by commas and no spaces and in order from lowest to highest)

./scan.sh # Enter this command 

-> image avail 


for i in {1..5}; do nc -nvzw1  172.16.140.$i 20-23 80 2>&1 & done | grep -E 'succ|open'


27. Well known ports on T3

for i in {65...95}; do nc -nvzw1  172.16.140.$i 20-23 80 2>&1 & done | grep -E 'succ|open'

172.16.140.62/27

28. 22,80

29. Interface with the web service on T3. The hint provides a suggestion on the ports above the well-known that you will need to recon. What is the range? (provide the range in the format of the example below)

open the html file:

1999-2999

wget -r 172.16.140.33 # Enter this command 

30. Which TCP ports were open in the range? List them in numerical order and separate the ports with a comma and no space.

./scan.sh # Enter this command 

-> image avail 

31. What UDP port(s) did you find that were open? (List them in in order and separate the ports with a comma and no space) NOTE: Look in the same port range mentioned in your hint for this target.

sudo nmap -sU -p 1999-2999 -v 172.16.140.33

-> image avail 

student@internet-host-student-11:~/socket.d$ sudo nmap -sUF -p 1999-2999 --min-rate 5000 
172.16.140.33 
[sudo] password for student: Starting Nmap 7.40 ( https://nmap.org ) at 2021-11-30 21:10 UTC
Nmap scan report for 172.16.140.33 
Host is up (0.0026s latency). 
Not shown: 1004 closed ports, 993 open|filtered ports 
PORT STATE SERVICE 
2000/udp open cisco-sccp 
2011/udp open servserv 
2200/udp open ici 
2250/udp open remote-collab 
2999/udp open remoteware-un 
Nmap done: 1 IP address (1 host up) scanned in 1.71 seconds

-> image avail 

32. On TCP port 2305, What day is it according to Spider-man?

nc 172.16.140.33 2305

-> image avail 

Wednesday

33. Watch your ______ on TCP port 2800?

Profanity

34. T7 Hostname:

red-int-dmz2-host-2-s

nc -u 172.16.140.33 2200 # Enter this command

nc -u 172.16.140.33 2250 # Enter this command

-> image avail 





Relay 3
10
Utilize the targets T2 and RELAY to develop the following netcat relays for use by Gorgan Cyber Forces. The use of names pipes should be utilized on RELAY:

Syntax for steghide tool:
steghide extract -sf [image name]
Passphrase: password

The Donovian Insider provided a image called 3steg.jpg on T2 listening for a connection from RELAY on TCP port 6789. Establish a Netcat relay on RELAY to make this connection and forward to T1. Once the images are downloaded you will use a command-line tool called steghide to extract the message. Perform an MD5SUM on this message to create flag3.

File should be 177444 bytes in size.






Ans -> 
nc -lvp 3333 > 3steg.jpg
nc 172.16.82.115 6789 < mypipe | nc 10.10.0.40 3333 > mypipe

Relay 4
10
Utilize the targets T2 and RELAY to develop the following netcat relays for use by Gorgan Cyber Forces. The use of names pipes should be utilized on RELAY:

Syntax for steghide tool:
steghide extract -sf [image name]
Passphrase: password

The Donovian Insider provided a image called 4steg.jpg on T2 listening for a connection from RELAY on TCP port 9876. Establish a Netcat relay on RELAY to make this connection and forward to T1. Once the images are downloaded you will use a command-line tool called steghide to extract the message. Perform an MD5SUM on this message to create flag4.

File should be 204283 bytes in size.

Answ - > 
nc -lvp 3333 > 4steg.jpg
nc 172.16.82.115 9876 < mypipe | nc 10.10.0.40 3333 > mypipe


What is the word "localhost" associated with? (Max 2 Attempts)
A. Loopback address
B. 127.0.0.1
C. Both A and B.
D. None of the above.
Both A & B
2. Using the following syntax:
OPS$ ssh cctc@10.50.1.150 -p 1111
What is 1111? (Max 2 Attempts)
A. nothing. Incorrect syntax
B. alternate ssh port on 10.50.1.150
C. local listening port on OPS
D. port mapped to localhost on 10.50.1.150
- C
4. Using the Tunnels Prep Diagram provided in the start to this task, please fill in the blanks to complete
the following ssh command.
Which IP would we use to SSH to PC1 from OPS?
ssh cctc@__________
10.50.1.150
5. Using the Tunnels Prep Diagram provided in the start to this task, please fill in the blanks to
complete the following ssh command.
Which ssh syntax would properly setup a Dynamic tunnel to PC1? (Max 2 Attempts)
A. ssh -D 9050 cctc@localhost -NT
B. ssh cctc@100.1.1.1 -D 9050 -NT
C. ssh cctc@10.50.1.150 -D 9050 -NT
D. ssh -L 9050cctc@10.50.1.150 -NT
-C
6. Using the Tunnels Prep Diagram provided in the start to this task, please fill in the blanks to
complete the following ssh command.
Which ssh syntax would properly setup a Local tunnel to PC1 SSH port? (Max 2 Attempts)
A. ssh -L 1111:localhost:22 cctc@10.50.1.150 -NT
B. ssh cctc@10.50.1.150 -L 1111:10.50.1.150:22 -NT
C. ssh cctc@100.1.1.1 -L 1111:localhost:22 -NT
D. ssh -R 1111:localhost:22 cctc@10.50.1.150 -NT
-C
7. Using the Tunnels Prep Diagram provided in the start to this task, please fill in the blanks to
complete the following ssh command. Which ssh syntax would properly setup a Local tunnel to PC1
HTTP port? (Max 2 Attempts)
A. ssh cctc@100.1.1.1 -L 1111:10.50.1.150:80-NT
B. ssh cctc@10.50.1.150 -L 1111:localhost:80-NT
C. ssh cctc@100.1.1.1 -L 1111:localhost:80-NT
D. ssh -L 1111:100.1.1.1:80 cctc@localhost-NT
-B
8. d
9.Using the Tunnels Prep Diagram provided in the start to this task, please fill in the blanks to complete
the following ssh command.
Which syntax would allow us to download the webpage of PC1 using the Local tunnel created in
Question 7? (Max 2 Attempts)
A. wget -r http://100.1.1.1:1111
B. wget -r http://100.1.1.1
C. wget -r http://localhost:1111
D. wget -r http://localhost -p 1111
-A (we are telling the to listen on port 111)


10. Using the Tunnels Prep Diagram provided in the start to this task, please fill in the blanks to
complete the following ssh command.
Which syntax would allow us to download the webpage of PC2 using the Dynamic tunnel created in
Question 8? (Max 2 Attempts)
A. proxychains wget -r http://100.1.1.2:1111
B. proxychains wget -r http://100.1.1.2
C. proxychains curl http://100.1.1.2
D. wget -r http://localhost:1111
B (here we know http is running on 80)

11. Using the Tunnels Prep Diagram provided in the start to this task, please fill in the blanks to
complete the following ssh command.
Which ssh syntax would properly setup a Local tunnel to PC2 SSH port using PC1 as your pivot?
(Max 2 Attempts)

A. ssh cctc@10.50.1.150 -L 1111:192.168.2.1:22 -NT
B. ssh -L 1111:100.1.1.2:22 cctc@100.1.1.1 -NT
C. ssh -L 1111:100.1.1.2:22 cctc@10.50.1.150 -p 1111 -NT
D. ssh cctc@10.50.1.150 -L 1111:100.1.1.2:22 -NT
-D

12. A

13. A

14. A

15. C

16. A

17. D

18. B 

19. C

20. A 


Task 3 

