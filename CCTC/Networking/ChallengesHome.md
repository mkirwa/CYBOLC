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
- B


2. Tunnel Prep – Alternate port 1
5
Using the following syntax:

OPS$ ssh cctc@10.50.1.150 -p 1111

What is 1111? (Max 2 Attempts)

A. nothing. Incorrect syntax
B. alternate ssh port on 10.50.1.150 (Answ)
C. local listening port on OPS
D. port mapped to localhost on 10.50.1.150

3. Tunnel Prep – Alternate port 2
5
Using the following syntax:

OPS$ ssh cctc@localhost -p 1111

What is 1111? (Max 2 Attempts)

A. nothing. Incorrect syntax
B. alternate ssh port on 10.50.1.150 
C. local listening port on OPS (Ans)
D. port mapped to localhost on 10.50.1.150

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
-A

7. Using the Tunnels Prep Diagram provided in the start to this task, please fill in the blanks to
complete the following ssh command. Which ssh syntax would properly setup a Local tunnel to PC1
HTTP port? (Max 2 Attempts)
A. ssh cctc@100.1.1.1 -L 1111:10.50.1.150:80-NT
B. ssh cctc@10.50.1.150 -L 1111:localhost:80-NT
C. ssh cctc@100.1.1.1 -L 1111:localhost:80-NT
D. ssh -L 1111:100.1.1.1:80 cctc@localhost-NT
-B

8. Tunnel Prep – Dynamic thru 1st Local
5
Using the Tunnels Prep Diagram provided in the start to this task, please fill in the blanks to complete the following ssh command.

Which ssh syntax would allow us to establish a Dynamic tunnel using the Local tunnel created in Question 6? (Max 2 Attempts)

A. ssh -D 9050 cctc@localhost -NT
B. ssh cctc@100.1.1.1 -p 1111 -D 9050 -NT
C. ssh -p 1111 cctc@10.50.1.150 -D 9050 -NT
D. ssh -D 9050 cctc@localhost -p 1111 -NT (Answ)


9. Using the Tunnels Prep Diagram provided in the start to this task, please fill in the blanks to complete
the following ssh command.
Which syntax would allow us to download the webpage of PC1 using the Local tunnel created in
Question 7? (Max 2 Attempts)
A. wget -r http://100.1.1.1:1111
B. wget -r http://100.1.1.1
C. wget -r http://localhost:1111 (C)
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


# For a Dynamic tunnel:

ssh -D [local_port] [user]@[[remotehost]]

# Local Forwarding
ssh -L [local_port]:[destination_host]:[destination_port] [user]@[SSH_server]

# Remote Forwarding
ssh -R [remote_port]:[destination_host]:[destination_port] [user]@[SSH_server]


# For a Dynamic tunnel to A:
ssh -D 9050 student_A@10.50.30.99 # -> This should be killed scan
proxychains ./scan.sh

# For a Local tunnel to A to tgt B:
ssh student_A@10.50.30.99 -L 1234:192.168.1.39:22

# For a Dynamic tunnel to B:
ssh student_B@127.0.0.1 -p 1234 -D 9050
proxychains ./scan.sh


12. Tunnel Prep – 2nd Local thru 1st Local SSH 5
Using the Tunnels Prep Diagram provided in the start to this task, please fill in the blanks to complete the following ssh command.

Which ssh syntax would properly setup a 2nd Local tunnel to PC2 SSH port using the tunnel made in Question 6 as your first tunnel? (Max 2 Attempts)

A. ssh -L 2222:100.1.1.2:22 cctc@localhost -p 1111 -NT (Ans)
B. ssh -L 2222:100.1.1.2:22 cctc@10.50.1.150 -p 1111 -NT
C. ssh cctc@100.1.1.1 -p 1111 -L 2222:100.1.1.2:22 -NT
D. ssh cctc@localhost -p 1111 -L 2222:192.168.2.1:22 -NT


13. Tunnel Prep – 2nd Local thru 1st Local HTTP
5
Using the Tunnels Prep Diagram provided in the start to this task, please fill in the blanks to complete the following ssh command.

Which ssh syntax would properly setup a 2nd Local tunnel to PC2 HTTP port using the tunnel made in Question 6 as your first tunnel? (Max 2 Attempts)

A. ssh -L 2222:192.168.2.1:80 cctc@localhost -p 1111 -NT (Ans)
B. ssh cctc@localhost -p 1111 -L 2222:100.1.1.2:80 -NT
C. ssh cctc@10.50.1.150 -p 1111 -L 2222:100.1.1.2:80 -NT
D. ssh -L 2222:100.1.1.2:80 cctc@100.1.1.1 -p 1111 -NT

ssh -L 2222:100.1.1.2:22 cctc@localhost -p 1111 -NT (Ans)

ssh -L 1111:localhost:22 cctc@10.50.1.150 -NT

pc_2 -> 192.168.2.1


14. Tunnel Prep – Dynamic thru 2nd Local 5

Using the Tunnels Prep Diagram provided in the start to this task, please fill in the blanks to complete the following ssh command.

Which ssh syntax would allow us to establish a Dynamic tunnel using the Local tunnel created in Question 12? (Max 2 Attempts)

A. ssh -D 9050 cctc@localhost -p 2222 -NT (A)
B. ssh cctc@100.1.1.1 -p 2222 -D 9050 -NT
C. ssh -p 2222 cctc@10.50.1.150 -D 9050 -NT
D. ssh -D 9050 cctc@localhost -p 1111 -NT

15. Tunnel Prep – What’s Wrong 1
5
Using the Tunnels Prep Diagram provided in the start to this task, please fill in the blanks to complete the following ssh command.

An Admin created the following tunnels but found that the Dynamic tunnel would not connect. Where did the Admin make the error? (Max 2 Attempts)

1.ssh cctc@10.50.1.150 -L 1234:100.1.1.2:22 -NT
2.ssh -D 9050 cctc@100.1.1.2 -p 1234 -NT

A. targeted wrong IP in line 1
B. authenticated to wrong IP in line 1
C. authenticated to wrong IP in line 2 (C)
D. called wrong port in line 2


16. Tunnel Prep – What’s Wrong 2
5
Using the Tunnels Prep Diagram provided in the start to this task, please fill in the blanks to complete the following ssh command.

An Admin created the following tunnels but found that the Dynamic tunnel would not connect. Where did the Admin make the error? (Max 2 Attempts)

1.ssh cctc@10.50.1.150 -L 1234:192.168.2.1:22 -NT
2.ssh -L 4321:192.168.2.2:22 cctc@localhost -p 1234 -NT
3.ssh cctc@localhost -p 4321 -D 9050 -NT

A. targeted wrong IP in line 1 (A)
B. targeted wrong IP in line 2
C. called wrong port in line 2
D. called wrong port in line 3


17. Tunnel Prep – Local to 3rd Pivot TELNET
5
Using the Tunnels Prep Diagram provided in the start to this task, please fill in the blanks to complete the following ssh command.

Which ssh syntax would properly setup a 3rd Local tunnel to PC3 TELNET port using the tunnels made in Question 6 and Question 12? (Max 2 Attempts)

A. ssh -L 3333:192.168.2.2:23 -p 2222 cctc@100.1.1.1 -NT
B. ssh -p 2222 cctc@localhost -L 3333:192.168.2.1:23 -NT
C. ssh -L 3333:192.168.2.2:23 cctc@localhost -NT
D. ssh -p 2222 cctc@localhost -L 3333:192.168.2.2:23 -NT (Ans)

18. Tunnel Prep – Telnet to 3rd Pivot
5
Using the Tunnels Prep Diagram provided in the start to this task, please fill in the blanks to complete the following ssh command.

Which syntax would allow us to telnet to PC3 using the tunnel make in Question 17? (Max 2 Attempts)

A. telnet localhost:3333
B. telnet localhost 3333 (B)
C. telnet 192.168.2.2 3333
D. telnet localhost -p 3333

19. Tunnel Prep – Remote
5
Using the Tunnels Prep Diagram provided in the start to this task, please fill in the blanks to complete the following ssh command.

Which syntax would properly setup a Remote tunnel from PC3 back to PC2 using PC3 SSH port as the target? (Max 2 Attempts)

A. ssh cctc@localhost -p 3333 -R 4444:localhost:22 -NT
B. ssh cctc@192.168.2.1 -R 4444:localhost:23 -NT
C. ssh -R 4444:localhost:22 cctc@192.168.2.1 -NT (C)
D. ssh -R 4444:192.168.2.2:22 cctc@localhost -NT


20. Tunnel Prep – Local to Remote
5
Using the Tunnels Prep Diagram provided in the start to this task, please fill in the blanks to complete the following ssh command.

Which syntax would properly setup a Local tunnel to map to the tunnel made in Question 19 using the tunnel made in Question 6 and Question 12? (Max 2 Attempts)

A. ssh cctc@localhost -p 2222 -L 5555:localhost:4444 -NT (Ans)
B. ssh cctc@localhost -p 2222 -L 5555:100.1.1.1:4444 -NT
C. ssh -L 5555:localhost:4444 -p 2222 cctc@100.1.1.1 -NT
D. ssh -L 5555:192.168.2.2:22 -p 4444 cctc@100.1.1.1 -NT

Task 3 

T3 is the authorized initial pivot
Conduct passive recon on the Target T3, it appears to have access to the 10.3.0.0/24 subnet.
Create a Local Port Forward from your Internet_Host to T3 targeting:
ip: 10.3.0.27
port: `HTTP``
Initial ssh request was denied
To create a tunnel, need to use the float IP as ssh to T3 is denied so,
Ssh
Need to create a local port to T3

ssh net25_student25@10.50.33.143 -L 50511:10.3.8.27:80 -N

After tunneling we can do the banner grab or listen to the port we created

nc localhost 50511

here we are using netcat to listen to the port and GET to grab the http

Flag: We are not interested int he possibilities of defeat 

T3 is the authorized initial pivot
Conduct passive recon on the Target T3, it appears to have access to the 10.3.0.0/24
subnet.
Create a Dynamic Port Forward from Internet_Host to T3 then use proxychains to pull the
flag.
Target ip: 10.3.0.1
Identify the flag on Cortina's FTP Server
- **** when creating a port if you get error stating port already created delete the port using the command
below
Kill –9 pid

ss -antlp

-> img

step 1 -> Create dynamic tunneling using t3 float ip 

ssh net25_student25@10.50.33.143 -D 9050 -NT


(UNKNOWN) [10.50.42.216] 22 (ssh) open

ssh net4_student11@10.50.42.216 -R 1234:localhost:22 -NT



##### Conduct passive recon on the Target T4, it appears to have access to the 10.2.0.0/25 subnet. #####

1. Ran `./scan.sh` 
2. 10.52.42         # Network address
3. 216              # starting host range
4. 216              # Ending host range
5. 21-23 80         # Ports space-delimited

ssh net4_student11@10.50.42.216 -L 1234:localhost:1234 -NT      # Establish Remote Port Forwarding from T4 to T3:

(UNKNOWN) [10.50.44.211] 23 (telnet) open


##### Create a Remote Port Forward from T4 to T3 binding the source as one of Your authorized ports, from the Mission Prompt, targeting: ip: 10.2.0.2 port: HTTP #####

ssh net4_student11@10.3.0.10 -R 41144:localhost:22 -NT      # Establish a remote SSH tunnel from T4 to T3. Command (run on T4): This forwards port 1234 on T3 (10.50.44.211) to SSH (port 22) on T4.

###### Create a Local Port Forward from Internet_Host to T3 targeting the port you just established. ######

ssh net4_student11@10.50.42.216 -L 41144:localhost:41144 -NT   # Local Port Forwarding from Internet_Host to T3:Create a tunnel from Internet_Host to T3.Command (run on Internet_Host): 
                                                             # This forwards port 41144 on Internet_Host to port 41144 on T3 (10.50.42.216).

##### When creating tunnels your authorized port ranges to utilize are NssXX (N = Net number, ss = Student Number and XX = is student assigned port number) #####

##### Accessing T4's Resource via Tunnel: #####

ssh net4_student11@localhost -p 1234 -L 1234:10.50.44.211:23 -NT        # Create an SSH tunnel from Internet_Host to access the telnet service on T4 through T3. Command (run on Internet_Host): is sets up a tunnel from port 1234 on your 
                                                                        # localhost (Internet_Host) to the telnet service (port 23) on T4 (10.50.44.211) through T3.


##### Use curl or wget to pull the flag. #####

curl http://localhost:1234          # Retrieve the Flag Using curl or wget: Using curl:
wget -r http://localhost:1234       # Retrieve the Flag Using curl or wget: Using wget:


##### Identify the flag on Mohammed Web Server #####







1. step 1 -> Draw a map of what you have 
2. Step 2 -> ssh into the pivots
3. Step 3 -> passive scanning -> ip address, ss -antlp # this would check the service ports open... look for what's listening on quad 0, e.g. 0.0.0.0:  except for anything from 6010 on upwards..
4. Step 4 


ssh [user]@[remotehost] -D [local_port]

##### 5. Tunnels Training - Mohammed FTP 5 #####
Level I Challenge
T3 is the authorized initial pivot

Build a Dynamic tunnel to T4 and conduct active recon to find the ``Mohammed" host.
Identify the flag on Mohammed's FTP Server

Hint
internet_host$ ssh netX_studentX@localhost -p NssXX -D 9050 -NT
proxychains ./scan.sh
proxychains wget -r ftp://{mohammed_ip}


###### Answer ######

telnet 10.50.44.211                                         # telnet to the pineland
ssh net4_student11@10.3.0.10 -R 41144:localhost:22          # Create a remote connection from pineland 
ssh net4_student11@10.50.42.216 -L 41144:localhost:41144    # Create a connection to Atropia from the host 
proxychains wget -r ftp://10.2.0.2                          # Connect to the server
cat 10.2.0.2/flag.txt                                       # Cat the flag



ssh net4_student11@10.50.44.211 -D 9050


Window 1
>>ssh net4_student15@localhost -p 41501 -D 9050
Window 2
>>proxychains wget -r ftp://10.2.0.2
Window 3
cat 10.2.0.2/flag.txt
I'm sorry, Dave. I'm afraid I can't do that-Hal, A Space Odyssey!

Telnet Internet Host to Host A:
	>> telnet userA@10.50.29.19
	Host A  Internet Host SSH IP
	ssh me@10.50.23.21 -R 1111:localhost:22      ------ REMOTE

	Window 2
	Internet Host to Host A
	>> ssh userA@localhost -p 1111 -D 9050      ------ CLOSE 9050 2x1

	Window 3 scan window Internet Host
	--proxyChains 10.1.2.16.16/28
	--proxychains nmap -Pn -sT 10.1.2.16.16 -p 21-23,80,2222

	Window 2x1 (2)
	Internet Host to Host A acc to B
	>> ssh userA@localhost -p 1111 -L 1222:10.1.2.16.18:2222

	Window 4
	Internet Host to Host B
	>> ssh userB@127.0.0.1 -p 1222 -D 9050      ------ CLOSE 9050 2x2

	Window 3 Internet Host
	--proxychains 172.16.10.96/27
	--proxychains nmap -Pn -sT 172.16.10.96 -p 21-23,80,2323

	Window 2x2 (3)
	Internet Host  to Host B acc to C
	ssh userB@localhost -p 1222 -L 3333:172.16.10.121:2323

	Window 4 Internet Host to Host C
	ssh userC@127.0.0.1 -p 3333 -D 9050      ------ CLOSE 9050 2x3

	Window 3  Internet Host
	--proxychains 192.168.10.64/26
	--proxychains nmap -Pn -sT 192.168.10.69 -p 21-23,80

	Window 2x3 (4)
	ssh userC@localhost -p 3333 -L 4444:192.168.10.69:22

	Window 5
	Internet Host
	ssh userD@127.0.0.1 -p4444 -D 9050

ssh net4_student11@10.50.42.216 -D 1080 


Window1 - pineland-insider
telnet 10.50.44.211
ssh net4_student1@10.3.0.10 -R 41500:localhost:22
Window2 - atropia-pivot
ssh net4_student15@10.50.42.216 -L 41501:localhost:41500
Window3- pineland-insider
ssh net4_student15@localhost -p 41501 -L 41500:10.2.0.2:80
Window4 - internet-host-student
use curl or wget to pull the flag:
curl http://localhost:41500
Millennium Falcon!



##### 6. Tunnels Training - Cortina HTTP 5 #####

T3 is the authorized initial pivot

Build a Dynamic tunnel to T3 and conduct active recon to find the Cortina host.
Identify the flag on Cortina's HTTP Server

hint: 
internet_host$ ssh netX_studentX@{T3_float_ip} -D 9050 -NT
proxychains ./scan.sh
proxychains wget -r http://{cortina_ip}

###### Answer ######
ssh net4_student11@Localhost -p 41144 -D 9050 -NT
proxychains ./scan.sh
proxychains wget -r


Create a tunnel to Atropia 
ssh net4_student11@10.50.42.216 -L 41144:localhost:41144
ip a # To check the subnets 
proxychains ./scan.sh # Scan for the ip using the subnet
cat 10.3.0.27/flag.txt # To get the flag 


##### 8. Tunnels Training - Mojave FTP 10 #####

T3 is the authorized initial pivot

You will need to conduct a search for clues for the network address of the Mojave host.
Identify the flag on Mojave's FTP Server

Hint 
find hint in the 10.2.0.0/24 network
proxychains ./scan.sh
Scan for new network
internet_host$ ssh netX_studentX@{T3_float_ip} -L NssXX:{next_pivot_ip}:22 -NT
internet_host$ ssh netX_studentX@localhost -p NssXX -D 9050 -NT
proxychains ./scan.sh
proxychains wget -r ftp://{mojave_ip}



From 


7. find / -name hint* 2> /dev/null
8. cat /usr/share/cctc/hint.txt
#You have accessed the Atlantica government server.
#There is nothing interesting on this server, however, it used to have access to the
#10.4.0.0/24 and 10.5.0.0/24 networks until the admins shut it down.
#Try to access those networks through another way.
#W4
#(FROM INTERNET HOST to BAJA-REPUBLIC)
9. ssh net4_student15@10.50.42.216
#(FROM T3)
10. ssh 10.4.0.1
11. find / -name hint* 2> /dev/null
12. cat /usr/share/cctc/hint.txt
#You have accessed tunnels-training-baja-republic-pivot at via login.
#Good job. There are no other devices of interest in this subnet,
#but this device has access to another network that only it can access.
#Give it a try!
Window 1 (Baja Republic):

(UNKNOWN) [10.4.0.1] 22 (ssh) open : Operation now in progress




ssh net4_student11@10.50.42.216 -L 41164:10.4.0.1:22 # Local to get T3 to target Baja.....
ssh net4_student11@localhost -p 41164 -D 9050 # Creating a dynamic channel after establishing the local channel... 























ssh net4_student15@10.50.39.135 -R 41510:localhost:22
ssh net4_student15@localhost -D 9050












# Reverse SSH Tunnel to Baja Republic
13. ssh net4_student15@10.3.0.10 -R 41510:localhost:22
Window 2 (Internet Host):
# Forward SSH Tunnel to Baja Republic
14. ssh net4_student15@10.50.42.216 -L 41511:localhost:41510
Window 3 (Internet Host):
# SSH Tunnel to Baja Republic through Forwarded Port
15. ssh net4_student15@localhost -p 41511 -L 41512:10.4.0.1:22
Window 4 (Internet Host):
# Dynamic Tunnel to Baja Republic through Forwarded Port
16. ssh net4_student15@localhost -p 41512 -D 9060
#I had to change the /proxychains.conf to 9060)
Window 5 (Internet Host):
# Run Script on 10.5.0 Network using ProxyChains:
17. proxychains ./scan.sh
Window 5 (Internet Host):
# Retrieve Files from Mojave FTP Server:
18. >>proxychains wget -r ftp://10.5.0.1
############ProxyChains configuration file###############
sudo nano /etc/proxychains.conf
#socks4 127.0.0.1 9060
/home/net4_student15/.ssh/known_hosts
>>cat 10.5.0.1/flag.txt 
I find your lack of faith disturbing.


# Reverse SSH Tunnel to Baja Republic
13. ssh net4_student11@10.3.0.10 -R 41157:localhost:22
Window 2 (Internet Host):
# Forward SSH Tunnel to Baja Republic
14. ssh net4_student11@10.50.42.216 -L 41158:localhost:41157
Window 3 (Internet Host):

sh net4_student11@localhost -p 41157 -D 9060






# SSH Tunnel to Baja Republic through Forwarded Port
15. ssh net4_student11@localhost -p 41158 -L 41159:10.4.0.1:22
Window 4 (Internet Host):
# Dynamic Tunnel to Baja Republic through Forwarded Port
16. ssh net4_student11@localhost -p 41159 -D 9060
#I had to change the /proxychains.conf to 9060)
Window 5 (Internet Host):
# Run Script on 10.5.0 Network using ProxyChains:
17. proxychains ./scan.sh
Window 5 (Internet Host):
# Retrieve Files from Mojave FTP Server:
18. >>proxychains wget -r ftp://10.5.0.1
############ProxyChains configuration file###############
sudo nano /etc/proxychains.conf
#socks4 127.0.0.1 9060
/home/net4_student11/.ssh/known_hosts
>>cat 10.5.0.1/flag.txt 
I find your lack of faith disturbing.



ssh -D [local_port] net4_student11@10.4.0.4

ssh net4_student11@10.50.42.216 -L 41144:localhost:41144

ssh net4_student11@10.4.0.1 -p 41156 -D 9050



ssh netX_studentX@localhost -p NssXX -D 9050 -NT



##### Tunnels Training - Mojave FTP 10 #####

Level II Challenge
T3 is the authorized initial pivot

You will need to conduct a search for clues for the network address of the Mojave host.
Identify the flag on Mojave's FTP Server

##### Tunnels Training - Mojave FTP 10 #####


ssh net4_student11@10.50.42.216 -L 41164:10.4.0.1:22 # Local to get T3 to target Baja.....
ssh net4_student11@localhost -p 41164 -D 9050 # Creating a dynamic channel after establishing the local channel... 
ssh net4_student11@10.50.42.216 -L 41144:localhost:41144    # Create a connection to Atropia from the host 
proxychains ./scan.sh with 10.5.0 range to from 0 to 100 -> use these to answer 8,9,10,11



##### Data Collection - Task 4 Start 5 #####
 
Level I Challenge
Your initial target is T5

You will need to find a way to connect.

Provide the port number that allowed initial access to the target.

Credentials for this environment are:

netY_studentX:passwordX
(netY = Networking Class Identifier & studentX = Student Number & passwordX = Student Number)

###### Answer ######

port 23

##### 1 . Data Collection - Initial Ports #####

What flag did you find on Net-SSH-01 after identifying it's additional open ports?

The flag is hosted on a port that can not be seen from the outside.

###### Answer ######

telnet 10.50.40.12                                      # Telnet to the location 
ssh student@10.50.39.135 -R 41190:localhost:22          # Create a Reverse shell to the internet host 
ssh net4_student11@localhost -p 41190 -D 9050           # Create a dynamic channel to the main the internet host
ip a                                                    # Find the number of open ips 


student@blue-internet-host-student-11:~$ proxychains ./scan.sh 
ProxyChains-3.1 (http://proxychains.sf.net)
Enter network address (e.g. 192.168.0): 
192.168.0
Enter starting host range (e.g. 1): 
1
Enter ending host range (e.g. 254): 
90
Enter ports space-delimited (e.g. 21-23 80): 
21-23 80

###### Additional Ports ######

(UNKNOWN) [192.168.0.10] 23 (telnet) open : Operation now in progress
(UNKNOWN) [192.168.0.10] 22 (ssh) open : Operation now in progress
(UNKNOWN) [192.168.0.10] 80 (http) open : Operation now in progress
(UNKNOWN) [192.168.0.20] 21 (ftp) open : Operation now in progress
(UNKNOWN) [192.168.0.20] 80 (http) open : Operation now in progress
(UNKNOWN) [192.168.0.30] 80 (http) open : Operation now in progress
(UNKNOWN) [192.168.0.40] 80 (http) open : Operation now in progress
student@blue-internet-host-student-11:~$ 

student@blue-internet-host-student-11:~$ proxychains wget -r http://192.168.0.10 

Answer -> Please do not throw sausage pizza away

##### 2. Data Collection - High port 10 #####

Net-SSH-03 has a flag being hosted on a high port, what country is it referring to with the question?

###### Answer ######

student@blue-internet-host-student-11:~$ `proxychains ./scan.sh` 
ProxyChains-3.1 (http://proxychains.sf.net)
Enter network address (e.g. 192.168.0): 
192.168.0
Enter starting host range (e.g. 1): 
30
Enter ending host range (e.g. 254): 
30
Enter ports space-delimited (e.g. 21-23 80): 
1-60000
(UNKNOWN) [192.168.0.30] 4444 (?) open : Operation now in progress
(UNKNOWN) [192.168.0.30] 80 (http) open : Operation now in progress
student@blue-internet-host-student-11:~$ `proxychains wget -r http://192.168.0.30:4444`

Look for 

2023-12-05 15:27:04 (6.81 MB/s) - ‘192.168.0.30:4444/index.html’ saved [60]


##### 3.  Data Collection - 1st Pivot #####
10
Level II Challenge
What is the IP Address of Net-SSH-02.

It has HTTP & FTP open and has access to a single machine hidden behind it?

###### Answer ######

192.168.0.20

##### 4. Data Collection - 1st Pivot Flag #####

In relation to Data Collection - 1st Pivot question.

What is the flag found on Net-SSH-02?

###### Answer ######

student@blue-internet-host-student-11:~$ proxychains wget -r ftp://192.168.0.20

Ansr -> <> <> <> <>

##### 6. Data Collection - 2nd Pivot 5 #####

Net-SSH-04 is another potential pivot.

This system has several open ports. What is the flag on it's HTTP port?

###### Answer ######

student@blue-internet-host-student-11:~$ proxychains wget -r ftp://192.168.0.20

Ansr -> <> <> <> <>

##### 7. Data Collection - 2nd Pivot Access 5 #####


Continuing from Data Collection - 2nd Pivot question.

What other subnet does Net-SSH-04 have access to?

Example:

10.10.0.0/29

###### Answer ######

Look at the hint on the 192.168.0.4 folder 

Hint -> This machine has Acess to the 172.16.0.0/24 network. You will have to find the alternate sshd port like on net-ssh-02 to progress further. 

##### 7. Data Collection - 2nd Pivot Access 5 #####

What host IP Address did you find (past Net-SSH-04) that you can login to using a well known port?

###### Answer ######

172.16.0.60

##### 9. Data Collection - Inner Flag 10 #####

What is the flag found on Net-SSH-06 that was identified in the Inner Net Challenge".

The flag can be found hosted on one of its open service ports.

###### Answer ######

Build a tunnel to  net-SSH-04

    >> ssh net4_student11@10.50.40.12 -p 22 -D 9050
    >> ssh net4_student11@10.50.40.12 -p 22 -L 1111:192.168.0.40:22


Internet Host to Host A
    >> ssh userA@10.50.29.89 -p 1234 -D 9050
    >> ssh userA@10.50.29.89 -p 1234 -L 1111:172.17.17.28:23

###### Prior Steps ######
###### Establishing a Tunnel back to IH ######

1. Telnet to 10.50.40.12 
    `telnet 10.50.40.12 `
2. Create a remote host back to IH 
    `ssh net4_student11@10.50.39.135 -R 41163:localhost:22`
    `ssh net4_student@localhost -p 41163 -D 9050`

    Do a -L to 19.168.0.40 and a dynamic channel and just run it!!

###### Establishing a Tunnel back to 192.168.0.40 ######
1. ssh net4_student11@localhost -p 22 -L 1111:192.168.0.40:22


1. ssh net4_student@192.168.0.40 -p 1222 -D 9050


ssh net4_student11@localhost -p 41163 -D 9050


Re-run 172.16.0.60-150 with high ports tomorrow for the flag



Two addresses to be found from 172.16.0.60

    172.16.0.80
        OS: Linux
        IP:
        HN: Net-SSH-8
        UN: net4_comrade11
        PW: privet11
        ports: 80,3389
        The fals is the PDI for UDP at the transport layer
        Flag: datagram

        HINTS
            FTP: You have entered the network space for Donovia, Credentials for this network are netN_comradeX, (N = your Net # X = Your student # )
            HTTP: This machine is a possible pivot to access more machines in the network, but SSh is not open to hosts outside of this network 


    172.16.0.70/.80?
        OS: Linux
        IP: 
        HN: Net-SSH-7
        UN: net4_comrade11
        PW: privet11
        ports: 80,1337
        Flag: Who uses leet speak anymore?

        HINTS 
            HTTP: To get the flag for net-ssh-07, you will need to look for and connect to a port commonly used iwth a leet speak 
            HTTP: To get the flag for this machine, you will need to look for and connect to the port commonly used for RDP 

    172.16.0.90
        OS: Linux
        HN: Net-SSH-90
        UN: net4_comrade11
        PW: privet11
        ports: 21,80, 2222 (ssh)
        Flag: Http: Peanut Butter Jelly Time

        HINTS
            FTP: This is the only machine that can reach net-ssh-01. You will have to use an alternate port on this machine to identify ports on the final machine. 

        # To ssh to this address from the Internet Host
        # Create a local tunnel to 172.16.0.90
        ssh net4_comrade11@localhost -p 41167 -L 41168:172.16.0.90:2222(confirm destination port...)
        ssh net4_comrade11@localhost -p 41168 -D 9050 # For running proxy scans....was not there ..... check what else is available 

        -> presume that after running scans, I will find 172.16.0.100 ports 23 and 80

        # if we telnet to 172.16.0.100 we will need a local host 
        ssh net4_comrade11@localhost -p 41168 -L 41169:172.16.0.100:23
        telnet localhost 41169 # if this doesn't work, try the telnet below
        run tcpdump -X icmp

        # wrong way to telnet
        telnet localhost -p 33007


    172.16.0.100
        THIS HAS A CONNECTION FROM 172.16.0.90
        OS: Linux
        HN: Net-SSH-10
        UN: net4_comrade11
        PW: privet11
        ports: 23,80
        Flag: Http:

        HINTS
            FTP: The flag for this machine is being sent from net-ss-09. While logged into net-ssh-10. use tcpdump and ignore telnet traffic to look for the 8 character hidden in the message being repeated. 
