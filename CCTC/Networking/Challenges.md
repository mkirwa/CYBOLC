# Networking - 1 - Fundamentals -Task 3 - Basic Analysis # 

## Basic Analysis - ttl 5 ##
Level I Challenge
What is the Berkeley Packet Filter, using tcpdump, to capture all packets with a ttl of 64 and less, utilizing the IPv4 or IPv6 Headers? There should be 8508 packets.

Enter the Filter syntax with no spaces

Answ -

sudo tcpdump -n "ip[8]<=64||ip6[7]<=64" -r /home/activity_resources/pcaps/BPFCheck.pcap | wc -l 

## Basic Analysis - dont fragment 5 ##

What is the Berkeley Packet Filter, using tcpdump, to capture all IPv4 packets with at least the Dont Fragment bit set? There should be 2321 packets.

Enter the Filter syntax with no spaces

Answ - 

Answ -> 
sudo tcpdump -n "ip[6] & 0x40 !=0" -r /home/activity_resources/pcaps/BPFCheck.pcap | wc -l 

## Basic Analysis - high port 5 ##

What is the Berkeley Packet Filter, using tcpdump, to capture traffic with a Source Port higher than 1024, utilizing the correct Transport Layer Headers? There should be 7805 packets.

Enter the Filter syntax with no spaces

Answ -> 
sudo tcpdump -n "tcp[0:2] > 1024 || udp[0:2] > 1024" -r /home/activity_resources/pcaps/BPFCheck.pcap | wc -l # 

## Basic Analysis - udp 5 ##

What is the Berkeley Packet Filter, using tcpdump, to capture all Packets with UDP protocol being set, utilizing the IPv4 or IPv6 Headers? There should be 1277 packets.

Enter the Filter syntax with no spaces

Answ -> 
sudo tcpdump -n "ip[9]=17 || ip6[6]=17" -r /home/activity_resources/pcaps/BPFCheck.pcap | wc -l

## Basic Analysis - tcp flags 5 ##

What is the Berkeley Packet Filter, using tcpdump, to capture only packets with the ACK/RST or ACK/FIN flag set, utilizing the correct Transport Layer Header? There should be 1201 packets.

Enter the Filter syntax with no spaces

Answ -> 
sudo tcpdump -n "tcp[13]=0x14 || tcp[13]=0x11" -r /home/activity_resources/pcaps/BPFCheck.pcap | wc -l

## Basic Analysis - id 5 ##

What is the Berkeley Packet Filter, using tcpdump, to capture all packets with an IP ID field of 213? There should be 10 packets.

Enter the Filter syntax with no spaces

Answ -> 
sudo tcpdump -n "ip[4:2]=213" -r /home/activity_resources/pcaps/BPFCheck.pcap | wc -l

## Basic Analysis - vlan 5 ##

What is the Berkeley Packet Filter, using tcpdump, to capture all traffic that contains a VLAN tag? There should be 182 packets.

Enter the Filter syntax with no spaces

Answ -> 
sudo tcpdump -n "ether[12:2]=0x8100" -r /home/activity_resources/pcaps/BPFCheck.pcap | wc -l

## Basic Analysis - dns 5 ##

What is the Berkeley Packet Filter, using tcpdump, to capture all IPv4 packets relating to DNS? There should be 63 packets.

Enter the Filter syntax with no spaces

Answ -> 
sudo tcpdump -n "tcp[0:2]=53 || udp[0:2]=53 || tcp[2:2]=53 || udp[2:2]=53" -r /home/activity_resources/pcaps/BPFCheck.pcap | wc -l

## Basic Analysis - CLIENT CONNECTIONS 5 ##

What is the Berkeley Packet Filter, using tcpdump, to capture the initial packets from a client trying to initiate a TCP connection? There should be 3447 packets

Enter the Filter syntax with no spaces

SYN tcp[13] & 0x02 !=0
ACK tcp[13] & 0x10 !=0
FIN tcp[13] & 0x01 !=0
RST tcp[13] & 0x04 !=0
URG tcp[13] & 0x20 !=0
PSH tcp[13] & 0x08 !=0

Answ -> 
sudo tcpdump -n "tcp[13]=2" -r /home/activity_resources/pcaps/BPFCheck.pcap | wc -l

## Basic Analysis - OPEN PORTS 5 ##

What is the Berkeley Packet Filter, using tcpdump, to capture the response packets from a server listening on an open TCP ports? There should be 277 packets

Enter the Filter syntax with no spaces

Continuing from CLIENT CONNECTIONS. What flags do the server use to respond to the connection request if the port is open?

Answ -> 
sudo tcpdump -n "tcp[13]=18" -r /home/activity_resources/pcaps/BPFCheck.pcap | wc -l

## Basic Analysis - CLOSED PORTS 5 ##

What is the Berkeley Packet Filter, using tcpdump, to capture the response packets from a server with closed TCP ports There should be 17 packets

Answ -> 
sudo tcpdump -n "tcp[13]=4" -r /home/activity_resources/pcaps/BPFCheck.pcap | wc -l


## Basic Analysis - WELL KNOWN PORTS 5 ##

What is the Berkeley Packet Filter, using tcpdump, to capture all TCP and UDP packets sent to the well known ports? There should be 3678 packets

Enter the Filter syntax with no spaces

Answ -> 
sudo tcpdump -n "tcp[2:2]<=1023 || udp[2:2]<=1023" -r /home/activity_resources/pcaps/BPFCheck.pcap | wc -l


## Basic Analysis - HTTP 5 ##

What is the Berkeley Packet Filter, using tcpdump, to capture all HTTP traffic? There should be 1404 packets

Enter the Filter syntax with no spaces

Answ -> 
sudo tcpdump -n "tcp[0:2]=80 || tcp[2:2]=80" -r /home/activity_resources/pcaps/BPFCheck.pcap | wc -l


## Basic Analysis - TELNET 5 ##

What is the Berkeley Packet Filter, using tcpdump, to capture all telnet traffic? There should be 62 packets

Enter the Filter syntax with no spaces

Answ -> 
sudo tcpdump -n "tcp[0:2]=23 || tcp[2:2]=23" -r /home/activity_resources/pcaps/BPFCheck.pcap | wc -l

## Basic Analysis - ARP 5 ##

What is the Berkeley Packet Filter, using tcpdump, to capture all ARP traffic? There should be 40 packets

Enter the Filter syntax with no spaces

Answ -> 
sudo tcpdump -n "ether[12:2]=0x0806" -r /home/activity_resources/pcaps/BPFCheck.pcap | wc -l

## Basic Analysis - EVIL BIT 5 ##

What is the Berkeley Packet Filter, using tcpdump, to capture if the "Evil bit" is set? There should be 197 packets

Enter the Filter syntax with no spaces

Research Evil bit in networking to determine what it means so you can create a filter for it.

Answ -> 
sudo tcpdump -n "ip[6]&0x80=0x80" -r /home/activity_resources/pcaps/BPFCheck.pcap | wc -l

## Basic Analysis - TOTAL CHAOS 5 ##

What is the Berkeley Packet Filter, using tcpdump, to capture any packets containing the CHAOS protocol within an IPv4 header? There should be 139 packets

Research how to identify the CHAOS protocol to determine how to filter for it.

Answ -> 
sudo tcpdump -n "ip[9]=16" -r /home/activity_resources/pcaps/BPFCheck.pcap | wc -l

## Basic Analysis - dscp 10 ##

What is the Berkeley Packet Filter, using tcpdump, to capture all IPv4 packets with the DSCP field of 37? There should be 42 packets.

Enter the Filter syntax with no spaces

sudo tcpdump -n "ip[1]>>2=37" -r /home/activity_resources/pcaps/BPFCheck.pcap | wc -l

## Basic Analysis - traceroute 10 ##

What is the Berkeley Packet Filter, using tcpdump, to capture all IPv4 packets targeting just the beginning of potential traceroutes as it's entering your network. This can be from a Windows or Linux machine using their default settings? There should be 83 packets.

Research how traceroute operates.

How can you identify an initial traceroute that enters your network?

What is the default carrier protocols used by Windows?

By Linux?

Find anything whose TTL value is 1 and anything and filter for udp 


Enter the Filter syntax with no spaces
Answ -> 
sudo tcpdump -n "ip[8]=1 && (ip[9] =1 || ip[9]=17)" -r /home/activity_resources/pcaps/BPFCheck.pcap | wc -l


## Basic Analysis - URGent EXFIL 10 ##

What is the Berkeley Packet Filter, using tcpdump, to capture all packets where the URG flag is not set and URG pointer has a value? There should be 43 packets

Enter the Filter syntax with no spaces

Answ -> 
sudo tcpdump -n "tcp[13]&32=0 && tcp[18:2]!=0" -r /home/activity_resources/pcaps/BPFCheck.pcap | wc -l


## Basic Analysis - NULL SCAN 10 ##

What is the Berkeley Packet Filter, using tcpdump, to capture a TCP null scan to the host 10.10.10.10? There should be 19 packets

Enter the Filter syntax with no spaces

Research NMAP Null scan to determine how to filter for it.

Answ -> 
sudo tcpdump -n "tcp[13]=0&&ip[16:4]=0x0a0a0a0a" -r /home/activity_resources/pcaps/BPFCheck.pcap | wc -l

## Basic Analysis - VLAN HOPPING 15 ##

What is the Berkeley Packet Filter, using tcpdump, to capture an attacker using vlan hopping to move from vlan 1 to vlan 10? There should be 15 packets

Enter the Filter syntax with no spaces

Answ -> 
sudo tcpdump -n "ether[12:4]&0xffff0fff=0x81000001 && ether[16:4]&0xffff0fff=0x8100000a" -r /home/activity_resources/pcaps/BPFCheck.pcap | wc -l

# Networking - 2 - Socket Creation and Packet Manipulation # 

## AddressFamilies 5 ##

What are the 3 Address Families associated with the python3 socket module?

example:

socket.ADDFAM, socket.ADDFAM, socket.ADDFAM

### Answer ###
socket.AF_Unix, socket.AF_INET, socket.AF_INET6

## Connections 5 ##

What are the two socket functions called to open a connection and to disconnect from that connection?

example:

socket.fun(), socket.func()

### Answer ###
socket.connect(), socket.close()

## Header Preparation 5 ##


What python3 library function is utilized to combine the various pieces of your raw socket packet into network order?

example:

module.function


### Answer ###
struct.pack

## Missing Data 5 ##

What must be manually created with raw sockets that stream and datagram sockets creates for you?

### Answer ###
headers

## Sending UDP 5 ##

What function within the socket module allows you to Send data to a socket, while not already being connected to a remote socket?

example:

socket.func()

### Answer ###
Socket.sendto() specifies that the system is to send the data into the socket (addr) and that it is not
currently connected.

## Transport Layer Sockets 5 ##

Provide an example of the two required items needed to be set in order to send a Datagram or Stream socket? (excluding any of the socket.socket functions)

example:

item1 item2

These are the 2 parts to a socket

socket? (excluding any of the socket.socket functions)

### Answer ###
Ipaddr port

## Objects ##

When sending data across a connection, what must a string be converted to before being sent due to encoding?

### Answer ###
Bytes

## Stream Socket Message Sender 10 ##

Gorgan Forces have requested you get a message to one of their remote teams that are utilizing the BLUE_DMZ_HOST-1. Utilizing the criteria they provided, generate a stream socket with python3:

Coded information was placed into the video below. Look at the note the woman passes to the man.

https://youtu.be/6WTdTwcmxyo?t=35

From your INTERNET-HOST to the BLUE_DMZ_HOST-1
Port number = #Last four digits on the note

Message = #Name on the note (First letter capitalized)


### Answer ###
sudo nano STREAM.py # to open the file
Change the IP and port
Change the message on message = b
“....”
Ctrl+O == save
Exit a
Open python3 STREAM.py — flag is there

## Datagram Socket Message Sender 10 ##

Gorgan Forces have requested you get a message to one of their remote teams that are utilizing the INTERNET_HOST. Utilizing the criteria they provided, generate a datagram socket with python3:

Coded information was placed into the video below. Listen to the words in the video.

https://youtu.be/OuK4OcMUGcg?t=67

Send to your INTERNET-HOST localhost.

Port number = #The number of fists

Message = #The name of the band (First letter capitalized)


### Answer ###
Open DGRAM.py
And complete the similar process

## Raw IPv4 Socket 10 ##
Gorgan forces, tool development cell have provided RAWSOCK.py for your teams use, it defines the basic structure of the desired result.

Create a raw socket and code your message into the socket
Send your last name as the data.
The sent data is required to be encoded, with a final result of the data being in hex. You can use the python module of your choice; a good module to start with is binascii.
When viewing in Wireshark, the packet should not be malformed

Target IP: 172.16.1.15

TOS: 96

IP ID: 1984

Protocol: CHAOS

The flag will be provided by the Mission Command once you complete the activity.

Provide the Wireshark Packet Capture.
Provide proof of the decoded message.

10. RAWSOCK.py for your teams use, it defines the basic structure of the desired result.
● Create a raw socket and code your message into the socket
● Send your last name as the data.
● The sent data is required to be encoded, with a final result of the data being in hex. You can use
● the python module of your choice; a good module to start with is binascii.
● When viewing in Wireshark, the packet should not be malformed

### Answer ###
1. Copy the RAWSOCK.py script
2. Create the file: touch RAWSOCK.py
3. Nano file and paste the script
4. Change the required fields — compare the file with RAW.py file
5. Run the file and use wireshark to capture the file

## Networking - 2 - VLAN HOPPING 15 ##

11. Gorgan forces, tool development cell have provided RAWSOCK2.py for your teams use, it defines the
basic structure of the desired result.

### Answer ###
● Create a raw socket and code your message into the socket
● When viewing in Wireshark, the packet should not be malformed















## 4. Tunnels Training - Remote Practice 5 ##

T3 is the authorized initial pivot

Conduct passive recon on the Target T4, it appears to have access to the 10.2.0.0/25 subnet.

Create a Remote Port Forward from T4 to T3 binding the source as one of Your authorized ports, from the Mission Prompt, targeting:
ip: 10.2.0.2 port: HTTP

Create a Local Port Forward from Internet_Host to T3 targeting the port you just established.
When creating tunnels your authorized port ranges to utilize are NssXX (N = Net number, ss = Student Number and XX = is student assigned port number)

Use curl or wget to pull the flag.
Identify the flag on Mohammed Web Server

Hint: 
internet_host$ telnet {T4_float_ip}
pineland$ ssh netX_studentX@{T3_inside_ip} -R NssXX:localhost:22 -NT
internet_host$ ssh netX_studentX@{T3_float_ip} -L NssXX:localhost:NssXX -NT
internet_host$ ssh netX_studentX@localhost -p NssXX -L NssXX:10.2.0.2:80 -NT
curl http://localhost:NssXX
wget -r http://localhost:NssXX

(UNKNOWN) [10.50.42.216] 22 (ssh) open



# Networking - 5 - Network Analysis #

#### 1. Attack Analysis - Total 5 ####
How many total packets were captured in the pcap?

Enter number with no comma's

#### Answer ####

statistics -> captured file properties 
1908895

# Networking - 5 - Network Analysis #

#### 1. Attack Analysis - Total 5 ####

Determine all IP addresses that were captured in the pcap, and list them in order. You should find 10.

Example:

1.1.1.1,2.2.2.2,3.3.3.3

#### Answer ####

91.189.89.199,192.168.10.101,192.168.10.111,192.168.10.112,192.168.41.1,192.168.41.2,192.168.41.130,192.168.41.254,224.0.0.251,239.255.255.250


#### 3. Attack Analysis - Hosts5 ####

How many hosts are in the capture?

hint: 
What types of IP address can be assigned to a host?

#### Answer ####

statistics -> end points 
There are two broadcast addresses ffffffffff and 000000000 subtract those from the total 10-2=8 hosts

#### 4. Attack Analysis - OSI Layer 5 ####


What Transport Layer Protocol is the most prominent in the capture?

#### Answer ####

statistics -> ipv4

check which is the more prominent

UDP 

#### 6. Attack Analysis - Cellular 5 ####

There is traffic related to 2G & 3G Cellular Communications, which uses a packet oriented mobile data standard.

What standard/protocol is performing this communication?
be sure to name the protocol and not the standard being used!

Hint: 
Conduct Internet Research on 2G & 3G Cellular Communications
Find the protocol in the PCAP

#### Answer ####

statistics -> protocol hierarchy -> GPRS Network Service

#### 7. Attack Analysis - Address 1 - Types 5 ####

Within the packet capture, the following IP Address was identified:

239.x.x.x

What type of address is this?

Hint
×
Research this address class

#### Answer ######## 

Multicast

#### 8. Attack Analysis - Address 2 - Protocol 5 ####

The protocol being used to generate the traffic associated with 239.x.x.x is a UDP based protocol which is commonly used with UPnP for finding devices and services on the network.

What is this protocol?

Hint
×
Google search the protocol
Filter on the address

#### Answer ######## 

Google to find the port for UPnP then run this on wireshark

`udp.port==1900`

#### 9. Attack Analysis - Address 3 - Source 5 ####

What is the mac address of the device that is sending the multicast SSDP traffic?

Example:
00:00:00:00:00:00

#### Answer ####

Check -> Ethernet information from wireshark from the port that filtered upd.port==1900

00:50:56:c0:00:08

#### 10. Attack Analysis - Address 4 - User Agent 5 ####

What user agent is making use of the protocol you discovered in Attack Analysis - Address 2 - Protocol?

Hint
Filter on the protocol from Question 8.
Look for the USER-AGENT

#### Answer ####

Filter based on ssdp then look at the user-agent under SSDP in the results column 

#### 11. Attack Analysis - DNS 1 - IP 5 ####

What is the IP Address for the DNS Server in the packet capture?

#### Answer ####

Filter DNS 
192.168.41.2

### 12. Attack Analysis - DNS 2 - Port 5 ####

What IP Address and Port is the query responding to?

Example:
XXX.XXX.XXX.XXX:PORT

#### Answer #####

From 11 above, check the source ip -> 192.168.10.111 and the source port -> 54966

#### 13. Attack Analysis - Service 1 5 ####

What is the Service indicated by the use of the following IP Address?

224.0.0.251

#### Answer ####

Hint
Google search the Multicast IP

#### Answer ######## ####

Google -> mDNS

#### 14. Attack Analysis - Service 2 5 ####

What is the FQDN and IP Address of the device indicated in the response to the query identified in `Attack Analysis - Service 1``? Look for the DNS A record.

Example (No Spaces):
keurig.domain,1.1.1.1

Hint
Look further into the responses from that address specified in Q13.
Look at the DNS A record

#### Answer ####

ip.addr==224.0.0.251 # Run this in the search bar 
Multicast Domain Name System -> Additional Records -> HP705A0FF92F8D.local: type A, class IN, addr 192.168.1.7

Answer -> HP705A0FF92F8D.local,192.168.1.7

#### 15. Attack Analysis - Vulnerability 10 ####

Attackers will seek unique ways to avoid being caught. This Traffic has been reported to contain a vulnerability that crashes wireshark due to an out-of-bounds write, detailed in CVE-2017-13766

What Protocol did the attackers use to achieve this and which server IP Address and Port was targeted?

Example:
PROTOCOL 1.1.1.1:PORT

Hint
Google search the CVE details

Find the protocol mentioned in your internet research in the pcap.

#### Answer ####

run `pn_ptcp` on the filter 
ans-> PN-PTCP 192.168.10.1111:55

#### 16. Attack Analysis - IOT 10 ####

It was identified that an exploit targeting a prominent IOT Systems was captured targeting 192.168.10.111 over UDP port 55.

This protocol was identified as an open global standard for wireless technology that uses low-power digital radio signals for indoor Personal Area Networks, uses the IEEE 802.15.4 specification as it's basis, which is often deployed in a mesh topology.

What is the name of this Protocol and what is the Packet Type being flooded?

Example: (No Spaces) PROTOCOL,PACKET_TYPE

Hint
Google search details from the question

Find the protocol mentioned in your internet research in the pcap.

#### Answer ####

scop and udp.port==55

Check the packets
Ans-> SCoP,Hello

#### 17. Attack Analysis - RCE 5 ####

Remote arbitrary Code Execution was captured targeting 192.168.10.111 via a gaming protocol.

What is the name of the game?

Example:
fortnite

Hint
Look for a "game" protocol being run

#### Answer ####

ip.addr==192.168.10.111 and udp
look for protocols that aren't common 

statistics -> hierarchy 

Look through the protocols 

Look under UDP -> Quake

#### 19. Attack Analysis - Conversation 5 ####

Determine the IP addresses for the top two talkers in the capture (the two hosts that generated the most traffic). (list in order e.g. 1.1.1.1,2.2.2.2)

Hint
Filter using 'Conversations'

#### Answer ####

statistics -> conversations

Look at the most packets -> 192.168.10.101,192.168.10.111

#### 21. Attack Analysis - Attacked Port 5 ####

Filter traffic communication between the IP addresses of the hosts determined in challenge 19, a UDP flood is occurring. What port is being attacked?

#### Answer ####

ip.addr==192.168.10.101  and ip.addr==192.168.10.111 # On wireshark
look at UDP on the results section look at the destination port 
Ans -> 55

#### 23. Attack Analysis - Type of Attack 5 ####

What type of attack is the UDP flood discovered in challenge 22?

#### Answer ####

DOS

#### 24. Attack Analysis - Type of Attack 2 5 ####

Is this an automated attack? (yes/no)

Once you have completed challenge questions 1 - 24 you can shorten the pcap to make Wireshark run faster.

First run this filter to select everything but the flooding of UDP port 55.

!(udp.port==55)

Next export the selected packets as a new pcap using File > Export Specified Packets.

Save as a new pcap and load it in Wireshark. You should now only have 86345 packets instead of the 1.9 million you had before.

#### Answer ####

It is DOS attack so it's an automated attack
Ans -> Yes

### 24. Attack Analysis - Type of Attack 2 5 ####

What version of Apache is running on the web server at the 192.168.10.111 address according to raw signatures in p0f?

#### Answer ####

sudo p0f -r  attack_analysis1.pcap | grep Apache # See the version at the end

#### 26. Attack Analysis - Website Tool 5 ####

What is the name of the website creation tool/software used on the 192.168.10.111 server indicated in the HTTP POST/GET messages and plugin scanning done by the attackers? (Supply the main software, not the plugin names)

Hint
Can use: http.request.method==" "

#### Answer ####

ip.addr==192.168.10.111 and http.request.method=="POST"

word-press in the post messages

#### 29. Attack Analysis - Plugin 5 ####

Consider the user agent strings identified in challenge 27.

Analyze the related traffic, and identify what Plugin the vulnerability scan triggered on?

Hint
Vulnerability scanners using the POST method.
http.request.method ==

Follow streams until you find one that gives a successful response

The 'plugin' will be annotated in a folder structure such as:
/~/~/plugins/ {plugin name} /~/~
http contains " "

#### Answer #####

ip.addr==192.168.10.111 and http contains User-Agent

#### 27. Attack Analysis - Scanning Tools 10 ####

Wordpress provides a plethora of plugins, however these are notorious for vulnerabilities, and there are several ways to scan these types of servers. Perform OSR on some of the top tools that could be used.

Determine which 2 tools were used for scanning against 192.168.10.111. These tools can be identified through examining the user-agent strings.

(The answer has no spaces)

scanner1,scanner2

Hint:
Search for User-Agent in the http header:
http contains User-Agent

#### Answer ####

ip.addr==192.168.10.111 and http contains User-Agent
Look at the data -> bruteforce
Ans -> WPScan, Nikto

#### 28. Attack Analysis - Credentials 10 ####

What is the username and password that was attempted against the axis2 plugin? (submit answer in the following format: jeff:mynamisjeff)

Hint
Websites uses the POST method to submit data.

Can use: http contains " "

#### Answer ####

http.request.method=="GET" && http contains "axis2" Follow tcp stream Search for axis2

#### 29. Attack Analysis - Plugin 5 ####

Consider the user agent strings identified in challenge 27.

Analyze the related traffic, and identify what Plugin the vulnerability scan triggered on?

Hint
Vulnerability scanners using the POST method.
http.request.method ==

Follow streams until you find one that gives a successful response

The 'plugin' will be annotated in a folder structure such as:
/~/~/plugins/ {plugin name} /~/~
http contains " "

#### Answer ####

`ip.dst == 192.168.10.111 &&( http.request.method == "POST")` - look for info with "plugins" - only 2 have it. - reflex-gallery

#### 30. Attack Analysis - Plugin CVE 10 ####

Refer to challenge 29. What CVE is related to the plugin the web vulnerability scanner found? (you need to include the version in your research) Submit your answer as the cve listing (e.g. CVE-2019-9999)

Hint
Google search the 'plugin' from question 29

#### Answer ####

Google answer -> CVE for reflex-gallery

https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-4133#:~:text=Unrestricted%20file%20upload%20vulnerability%20in,the%20file%20in%20uploads%2F%20directory.

#### 31. Attack Analysis - Exploit 5 ####

Reading the CVE details will provide you with the knowledge to know what the attacker is able to exploit.

What was the Filename that was successfully uploaded by the attacker to 192.168.10.111?

Hint
What file type is referred to from research into the CVE from question 30?

File that was uploaded from question 29.

will be listed under 'filename'

#### Answer ####

ip.dst == 192.168.10.111 &&( http.request.method == "GET") || http contains "php" && http contains "reflex-gallery" 
look through the encapsulated multipart part
msf.php

or follow tcp stream

#### 32. Attack Analysis - Exploit 2 5 ####

The malicious upload referred to in challenge 31 is used to start communication for a specific tool, what is the name of this tool/framework (not the attack payload)?

Hint
Research the CVE from the file in question 30 on exploit-db.com

#### Answer ####

Go to exploit.com and search for msf
metasploit

#### 33. Attack Analysis - Payload 10 ####

Refer to challenge 32. Perform open-source research:

This popular attack payload provides an interactive shell to the attacker, this payload uses in-memory DLL injection. Identify the payload name (this is a single word, not the payload in hex).

Hint
Google search the question

#### Answer ####

Meterpreter -> From Google 


#### 34. Attack Analysis - Language 10 ####

What programming language is this payload discovered in question 33 written in?

Hint
Google search the answer to question 33 to find the programming language its written in.

#### Answer ####

Answ -> Ruby

#### 35. Attack Analysis - Payload UUID 10 ####

Refering to the payload identified in Challenge 33, what is the Payload UUID identified in the session of the host that was first compromised?

Enter answer in this format: \x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff

Hint
Can use the filter: data contains " "
Follow the streams and search for UUID

#### Answer ####

data contains "UUID" -> Wireshark
follow TCP stream
control F - UUID
\x81\xc2\xe4\x1d\xc3\x06\xf6\xf6\xeb\xd8\xf8\xd7\xb2\xe2\xea\x5b

#### 36. Attack Analysis - Attacked IP 5 ####

The 192.168.10.111 web server is now under control of the attacker through a reverse TCP connection via the meterpreter session. The 192.168.10.111 server is used to pivot to another target and perform the same actions the attacker took against 192.168.10.111, what is its ip address?

Hint
Check conversations to see who else 192.168.10.111 is talking to.

#### Answer ####

statistics -> conversations # check the traffic 192.168.10.112

#### 37. Attack Analysis - Malware Type 10 ####

What type of malware is uploaded to the 192.168.10.112 server (not the malicious php upload to kick off the meterpreter session)? Look for a connection back to a malware repository in the TCP stream.

Hint
Recall back to the session from question 29.
Search through the communication from the .112. Look for the .php POST request.

From the stream:
Find the IP:PORT address that it is supposed to connect to to download the malware from the stream.

Filter for that IP:PORT and the .112.

Find the malware in the stream next to github

#### Answer ####

ip.dst == 192.168.10.112  Exclude all the web traffic------look for fubky port number: 444 Follow the stream----search for github 
ransomware

#### 38. Attack Analysis - New Payload UUID 10 ####

What is the payload UUID for the new meterpreter session on the host at 192.168.10.112?

Enter andwer in this format: \x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff\

Hint
Can use the filter: data contains " "

Follow the streams and search for UUID

#### Answer ####

Filter =  `data contains "UUID"` Follow stream \xc5\x0f\xbc\x3a\x9f\x31\x91\x0b\x42\x66\x51\x69\x1b\x5c\x43\xa3

#### 39. Attack Analysis - Malware Location 10 ####

Refer back to challenge 37, the malware referenced in this question was identified as ransomware. What is the github repo from which the malware is downloaded? (submit your answer in the following format: https://github.com/horst_simco/malwarez)

Hint
Follow the streams and search for the github repo URL

#### Answer ####

Seach from 38
https://github.com/mauri870/ransomware 

#### 40. Attack Analysis - Malware Language 10 ####

According to the github site, the malware was determined to be ransomware. What programming language was used to write this?
Hint
Language is described in the Readme on the github site.

#### Answer ####

go

#### 41. Attack Analysis - OS Target 10 ####


Refer back to challenge 38, the malware referenced in this question was identified as ransomware. What OS is targeted by the malware?

Hint
OS mentioned in Readme on the github site

#### Answer ####

windows

#### 42. Attack Analysis - Architecture 10 ####

The ransomware indicated in challenge 37 targets what type of system architecture?
Hint
Check the ransomware.manifest file on the github site.

#### Answer ####

x86

#### 43. Attack Analysis - Assembly Description ####

10 What is the assembly description attribute in the assembly manifest for the ransomware? 

Hint
Check the ransomware.manifest file on the github site.

#### Answer ####

Nothing to see here

#### 44. Attack Analysis - Date 10 ####

In the pcap, there is a protocol that provides clock synchronization between systems over packet-switched networks in this pcap. Use the information within this protocol's header to determine the date of this packet capture. (format your answer as follows: Oct 20, 2019)

Hint
search for a protocol that synchronizes network time

#### Answer ####

apply NTP as a filter

#### 5. Attack Analysis - OS Type 10 ####

p0f has extensive finger printing capabilities (as indicated by the name).

Use p0f to read the pcap and determine the OS type of the host: 192.168.10.101

#### Answer ####

sudo p0f -r /home/activity_resources/pcaps/attack_analysis1.pcap 'src host 1 92.168.10.101'
Linux 3.11

#### 15. Attack Analysis - Vulnerability 10 ####

Attackers will seek unique ways to avoid being caught. This Traffic has been reported to contain a vulnerability that crashes wireshark due to an out-of-bounds write, detailed in CVE-2017-13766

What Protocol did the attackers use to achieve this and which server IP Address and Port was targeted?

Example:
PROTOCOL 1.1.1.1:PORT

Hint
Google search the CVE details
Find the protocol mentioned in your internet research in the pcap.


#### Answer ####

Google 
bittorrent

#### 18. Attack Analysis - Vuze 10 ####

The Vuze DHT protocol was used as an exploit against 192.168.10.111, indicated in the protocol hierarchy page of Wireshark.

After analysis and some Open Source Research, what type of Application is Vuze?

Hint
Google search Vuze DHT

#### Answer ####



#### 20. Attack Analysis - OS Fingerprint 10 ####

Initial TTL can be used to determine host operating systems. Use a tool that will perform fingerprinting based on other criteria to determine the OS of the host with the IP address 192.168.10.111.

#### Answer ####

sudo p0f -r /home/activity_resources/pcaps/attack_analysis1.pcap 'src host 1 92.168.10.101'
Linux 3.11


#### 22. Attack Analysis - Attacked Port 2 10 ####

In the last challenge you discovered port 55 being targeted for attacks, this is within the well known range, what typical service is associated with it?

Hint
Google search the port

#### Answer ####

ISI Graphics Language

#### 25. Attack Analysis - Server Version 10 ####

What version of Apache is running on the web server at the 192.168.10.111 address according to raw signatures in p0f?

#### Answer ####

#### ####


#### Answer ####

### Networking - 6 - Filtering - Task 1 - Host Filtering ###


IPTable Rule Definitions

    Allow New and Established traffic to/from via SSH, TELNET, and RDP
    Change the Default Policy in the Filter Table for the INPUT, OUTPUT, and FORWARD chains to DROP
    Allow ping (ICMP) requests (and reply) to and from the Pivot.
    Allow ports 6579 and 4444 for both udp and tcp traffic
    Allow New and Established traffic to/from via HTTP

Once these steps have been completed and tested, go to Pivot and open up a netcat listener on port 9001 and wait up to 2 minutes for your flag. If you did not successfully accomplish the tasks above, then you will not receive the flag.

T1
Hostname: BLUE_Host-1
IP: 172.16.82.106
Creds: student : password
Action: Implement Host Filtering to Allow and Restrict Communications and Traffic

#### Answer ####

##### Allow New and Established traffic to via SSH, TELNET, and RDP #####
iptables -A INPUT -p tcp -m multiport --sports 22,23,3389 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT -p tcp -m multiport --dports 22,23,3389 -m state --state NEW,ESTABLISHED -j ACCEPT

##### Allow New and Established traffic from via SSH, TELNET, and RDP #####
iptables -A OUTPUT -p tcp -m multiport --sports 22,23,3389 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp -m multiport --dports 22,23,3389 -m state --state NEW,ESTABLISHED -j ACCEPT

##### Change the Default Policy in the Filter Table for the INPUT, OUTPUT, and FORWARD chains to DROP #####
iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP

##### Allow ICMP (ping) requests and replies # input #####
iptables -A INPUT -p icmp --src 10.10.0.40 --icmp-type echo-request -j ACCEPT
iptables -A INPUT -p icmp --src 10.10.0.40 --icmp-type echo-reply -j ACCEPT

##### Allow ICMP (ping) requests and replies # output #####
iptables -A OUTPUT -p icmp --dst 10.10.0.40 --icmp-type echo-request -j ACCEPT
iptables -A OUTPUT -p icmp --dst 10.10.0.40 --icmp-type echo-reply -j ACCEPT

##### Allow ports 6579 and 4444 for both tcp traffic # input #####
iptables -A INPUT -p tcp -m multiport --sports 6579,4444 -j ACCEPT
iptables -A INPUT -p tcp -m multiport --dports 6579,4444 -j ACCEPT

##### Allow ports 6579 and 4444 for both tcp traffic # output #####
iptables -A OUTPUT -p tcp -m multiport --sports 6579,4444 -j ACCEPT
iptables -A OUTPUT -p tcp -m multiport --dports 6579,4444 -j ACCEPT

##### Allow ports 6579 and 4444 for both udp traffic # input #####
iptables -A INPUT -p udp -m multiport --sports 6579,4444 -j ACCEPT
iptables -A INPUT -p udp -m multiport --dports 6579,4444 -j ACCEPT

##### Allow ports 6579 and 4444 for both udp traffic # output #####
iptables -A OUTPUT -p udp -m multiport --sports 6579,4444 -j ACCEPT
iptables -A OUTPUT -p udp -m multiport --dports 6579,4444 -j ACCEPT

##### Allow New and Established traffic to via HTTP # input #####
iptables -A INPUT -p tcp --sport 80 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -m state --state NEW,ESTABLISHED -j ACCEPT

##### Allow New and Established traffic from via HTTP # output #####
iptables -A OUTPUT -p tcp --sport 80 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp --dport 80 -m state --state NEW,ESTABLISHED -j ACCEPT

task 1 -> 467accfb25050296431008a1357eacb1
task 2 -> 
task 3 -> 05e5fb96e2a117e01fc1227f1c4d664c

truncate -s 0 iptablerules.sh 

######################################################################################################

### IP/NFTables - Filtering T3 5 ###

IPTable Rule Definitions

Allow New and Established traffic to/from via SSH, TELNET, and RDP

Change the Default Policy in the Filter Table for the INPUT, OUTPUT, and FORWARD chains to DROP

Allow New and Established traffic to/from via HTTP

Once these steps have been completed and tested, go to Pivot and open up a netcat listener on port 9003 and wait up to 2 minutes for your flag. If you did not successfully accomplish the tasks above, then you will not receive the flag.


T1
Hostname: BLUE_Host-1
IP: 172.16.82.106
Creds: student : password
Action: Implement Host Filtering to Allow and Restrict Communications and Traffic

#### Answer ####

##### Allow New and Established traffic to via SSH, TELNET, and RDP #####
iptables -A INPUT -p tcp -m multiport --sports 22,23,3389 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT -p tcp -m multiport --dports 22,23,3389 -m state --state NEW,ESTABLISHED -j ACCEPT

##### Allow New and Established traffic from via SSH, TELNET, and RDP #####
iptables -A OUTPUT -p tcp -m multiport --sports 22,23,3389 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp -m multiport --dports 22,23,3389 -m state --state NEW,ESTABLISHED -j ACCEPT

##### Set the default policy to DROP for INPUT, OUTPUT, and FORWARD chains #####
iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP

##### Allow New and Established traffic to via HTTP # input #####
iptables -A INPUT -p tcp --sport 80 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -m state --state NEW,ESTABLISHED -j ACCEPT

##### Allow New and Established traffic from via HTTP # output #####
iptables -A OUTPUT -p tcp --sport 80 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp --dport 80 -m state --state NEW,ESTABLISHED -j ACCEPT

Ans -> 
05e5fb96e2a117e01fc1227f1c4d664c



iptables -t filter -P INPUT ACCEPT
iptables -t filter -P OUTPUT ACCEPT
iptables -t filter -F
iptables -t filter -vL





### IP/NFTables - Filtering T2 5 ###

NFTable Rule Definitions

NFTable: CCTC
Family: ip

Create input and output base chains with:
Hooks
Priority of 0
Policy as Accept

Allow New and Established traffic to/from via SSH, TELNET, and RDP

Change your chains to now have a policy of Drop

Allow ping (ICMP) requests (and reply) to and from the Pivot.

Allow ports 5050 and 5150 for both udp and tcp traffic to/from

Allow New and Established traffic to/from via HTTP

Once these steps have been completed and tested, go to Pivot and open up a netcat listener on port 9002 and wait up to 2 minutes for your flag. If you did not successfully accomplish the tasks above, then you will not receive the flag.

#### Answer ####


##### Create input and output base chains with a policy of Accept #####
nft add chain ip CCTC input { type filter hook input priority 0; }
nft add chain ip CCTC output { type filter hook output priority 0; }

##### Rule 1: Allow New and Established traffic to/from SSH (port 22), TELNET (port 23), and RDP (port 3389) using the multiport module #####
nft add rule ip CCTC input ip protocol tcp ct state new,established tcp sport { 22, 23, 3389 } accept
nft add rule ip CCTC input ip protocol tcp ct state new,established tcp dport { 22, 23, 3389 } accept

nft add rule ip CCTC output ip protocol tcp ct state new,established tcp sport { 22, 23, 3389 } accept
nft add rule ip CCTC output ip protocol tcp ct state new,established tcp dport { 22, 23, 3389 } accept

##### Rule 2: Change the chains to have a policy of Drop #####
nft add rule ip CCTC input drop
nft add rule ip CCTC output drop

##### Rule 3: Allow ping (ICMP) requests (and replies) to and from the Pivot #####
nft add rule ip CCTC input ip protocol icmp accept
nft add rule ip CCTC output ip protocol icmp accept

##### Rule 4: Allow ports 5050 and 5150 for both UDP and TCP traffic using the multiport module #####
nft add rule ip CCTC input ip protocol { tcp, udp } ct state new,established multiport { 5050, 5150 } accept
nft add rule ip CCTC output ip protocol { tcp, udp } ct state new,established multiport { 5050, 5150 } accept

##### Rule 5: Allow New and Established traffic to/from HTTP (port 80) using the multiport module #####
nft add rule ip CCTC input ip protocol tcp ct state new,established tcp dport 80 accept
nft add rule ip CCTC output ip protocol tcp ct state new,established tcp sport 80 accept


### IP/NFTables - Filtering Validation 10 ###

For verification (only) of your IPTables and NFTables rules. This is NOT required for the flag:

    Pivot can SSH into all three targets
    Pivot can ping T1 and T2 but not T3
    T1, T2 andT3 should not be able to PING each other
    Pivot can access all three targets via HTTP
    Monitor via TCPDump on T3 for web traffic from outside the network
    Monitor via TCPDump on T1 for traffic on the allowed high ports
    Monitor via TCPDump on T2 for traffic on the allowed high ports

To get the Validation FLAG:

Once you have received the flag for T1, T2, and T3, go to Pivot and perform an md5sum on the combination of T1 flag, T2 flag, and T3 flag combined and separated by underscores.

For example:
echo "T1flag_T2flag_T3flag" | md5sum
Update the Stream Socket Message Sender script created in Networking - 2 - Socket Creation and Packet Manipulation.
Send the result of the md5sum of all three flags separated by underscores to the same IP address and port (IP 172.16.1.15 Port 5309) to receive your flag.

#### Answer ####

# Create the filter table if it doesn't exist
nft add table ip CCTC

# Create input and output base chains with a policy of Accept
nft add chain ip CCTC input { type filter hook input priority 0\; policy accept \;}
nft add chain ip CCTC output { type filter hook output priority 0\; policy accept \;}

# Rule 1: Allow New and Established traffic to/from SSH (port 22), TELNET (port 23), and RDP (port 3389)
nft add rule ip CCTC input ip protocol tcp ct state { new, established } tcp dport { 22, 23, 3389 } accept
nft add rule ip CCTC output ip protocol tcp ct state { new, established } tcp sport { 22, 23, 3389 } accept

# Rule 2: Change the chains to have a policy of Drop
nft add rule ip CCTC input drop
nft add rule ip CCTC output drop

# Rule 3: Allow ping (ICMP) requests (and replies) to and from the Pivot
nft add rule ip CCTC input ip protocol icmp accept
nft add rule ip CCTC output ip protocol icmp accept

# Rule 4: Allow ports 5050 and 5150 for both UDP and TCP traffic
nft add rule ip CCTC input ip protocol tcp ct state { new, established } tcp dport { 5050, 5150 } accept
nft add rule ip CCTC input ip protocol udp ct state { new, established } udp dport { 5050, 5150 } accept
nft add rule ip CCTC output ip protocol tcp ct state { new, established } tcp sport { 5050, 5150 } accept
nft add rule ip CCTC output ip protocol udp ct state { new, established } udp sport { 5050, 5150 } accept

# Rule 5: Allow New and Established traffic to/from HTTP (port 80)
nft add rule ip CCTC input ip protocol tcp ct state { new, established } tcp dport 80 accept
nft add rule ip CCTC output ip protocol tcp ct state { new, established } tcp sport 80 accept




nft add table ip CCTC
# Create input and output base chains with:Hooks, Priority of 0, Policy as Accep
nft add chain ip CCTC input { type filter hook input priority 0 \; policy accept \; }
nft add chain ip CCTC output { type filter hook output priority 0 \; policy accept \; }

# Allow New and Established traffic to/from via SSH, TELNET, and RDP
nft insert rule ip CCTC output tcp dport { 22,23,3389} ct state { new, established} accept 
nft insert rule ip CCTC output tcp sport { 22,23,3389} ct state { new, established} accept
nft insert rule ip CCTC input tcp dport { 22,23,3389} ct state { new, established} accept
nft insert rule ip CCTC input tcp sport { 22,23,3389} ct state { new, established} accept

# Change your chains to now have a policy of Drop
sudo nft add chain ip CCTC input { type filter hook input priority 0 \; policy drop \; }
sudo nft add chain ip CCTC output { type filter hook output priority 0 \; policy drop \; }

# Allow ping (ICMP) requests (and reply) to and from the Pivot.
nft insert rule ip CCTC output icmp type 8 ip daddr 10.10.0.40 accept
nft insert rule ip CCTC output icmp type 0 ip daddr 10.10.0.40 accept
nft insert rule ip CCTC output icmp type 8 ip saddr 10.10.0.40 accept
nft insert rule ip CCTC output icmp type 0 ip saddr 10.10.0.40 accept
nft insert rule ip CCTC input icmp type 8 ip saddr 10.10.0.40 accept
nft insert rule ip CCTC input icmp type 0 ip saddr 10.10.0.40 accept
nft insert rule ip CCTC input icmp type 8 ip daddr 10.10.0.40 accept
nft insert rule ip CCTC input icmp type 0 ip daddr 10.10.0.40 accept

