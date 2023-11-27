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



