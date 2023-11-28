# Day 1 FUNDAMENTALS #

Alt F -> gets rid of unclass banner. 

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

https://net.cybbh.io/public/networking/latest/index.html

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