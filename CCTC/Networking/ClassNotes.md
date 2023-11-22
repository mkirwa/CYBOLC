# Day 1 FUNDAMENTALS #

BBB Link
We will use this link to share our screen: https://bbb.cybbh.space/b/net-nfp-jln-zok

2023-11-20T17:46:20ZClass Notification
INTERNET HOST Login Info
Hostname: BLUE-INTERNET_HOST-student_11 IP: 10.50.39.135 Username: student Password: password

2023-11-20T11:51:01Z

ssh -X student@10.50.47.43

-X enables use of graphics can open things like wireshack. 

Advantages of Assymetric 

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


Task 1: Frame and Packet Headers
START FLAG: P@cket_C@rv1ng


Utilize the /home/activity_resources/pcaps/packet-headers.pcapng for this activity.

CISCO switches - CDP 
Router Information - RIP