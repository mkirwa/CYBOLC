# control i 


Floating IP -> 10.50.27.32
cred -> net4_student11: password11
known ports: unknown
Port ranges # 41100-41199
directory to check once you logon - /usr/share/cctc/
echo "CHEESE" | base64
Q0hFRVNFCg==

### DO THE RECONNAISANCE ###

### STEPS WHEN BUILDING A TUNNEL ###
1. Make a map 
2. Scan pivot ip 
3. Passive -
		ip addr
		ip neighbor
		ss -anltp

		from ip address, you have subnets. 
		if the ip address or the point is a pivot, run ip a vertical scans with the subnet range as the starting host range and ending host range

		if the ip address or the point is not a pivot, ran to find what other ports are open on that address


4. For port 80/21
		wget -r http://ip-address
		wget -r ftp://ip-address
		
		if you see hint-02a.png (means that it corresponds to box number 2)
5. cd /user/share/cctc
6. if you need a tool, you can run `where is [tool]` to see if the tool is installed. `which`
7. If you see a multiple choice question, 
8. echo "C" | base64 -> Converts an answer to base64....

#### ip address from running ip neigbor 
10.1.1.126
10.1.1.125
10.1.1.33
10.1.1.11
10.1.1.25

### Running Scans ###
Create a dynamic tunnel to the floating ip address
ssh net4_student11@10.50.27.32 -D 9050
Ran proxy scans and discovered:
10.1.1.33 ports -> 21, 23,80
10.1.1.11 ports -> 21, 23
10.1.1.25 ports -> 21
10.1.1.30 ports -> 80

Ran proxychains wget -r [ipaddresses]


hint 1. file:///home/student/10.1.1.11/hint-02a.png
pushed me through to questions 1-5

From the hint, ran 

`proxychains wget -r http://10.1.1.11:1918`

### Running Scans ###

#### Question 1 ####
APIPA uses the IP network range of 169.254.0.0/16. What RFC number governs this? Enter only the BASE64 conversion of the number.
3927

##### Ans #####
echo "3927" | base64 -> 

Ans -> MzkyNwo=

#### Question 2 ####

Question 2

IPv6 Uses SLAAC to resolve its Global address from the Router. What multicast destination address does it use to Solicit the router?
Enter the address in uppercase and convert to BASE64.

##### Ans #####
FF02::2
echo "FF02::2" | base64 -> 
Ans -> RkYwMjo6Mgo=

#### Question 3 ####

Which type of ARP is sent in order to perform a MitM attack?
Specify the answer in ALL CAPS and convert to BASE6

##### Ans #####
echo "REPLY" | base64


#### Question 4 ####

An attacker built a FRAME that looks like this:
| Destination MAC | Source MAC | 0x8100 | 1 | 0x8100 | 100 | 0x0800 | IPv4 Header | TCP Header | Data | FCS |
What form of attack is being performed? Supply your answer in ALL CAPS and convert to BASE64.

##### Ans #####
VLAN Hopping attack, specifically a Double Tagging attack. This is indicated by the presence of two 802.1Q tags (0x8100) in the frame. In this attack, the attacker exploits the behavior of network hardware in handling VLAN tags to make packets reach VLANs that they normally should not reach.

VLAN HOPPING

echo "VLAN HOPPING" | base64

#### Question 5 ####

A router receives a 5000 byte packet on eth0. The MTU for the outbound interface (eth1) is 1500. What would the fragmentation offset increment be with the conditions below?

Origional packet Size = 5000 bytes

MTU for outboud interface = 1500

Packet IHL = 7

Supply only the BASE64 conversion of the number.

##### Ans #####

The fragmentation offset is specified in units of 8 bytes. When a packet is fragmented, the first fragment will have a fragmentation offset of 0. Subsequent fragments will have an offset that is the number of data bytes in all previous fragments divided by 8.

Given the conditions:

- Original packet size = 5000 bytes
- MTU for outbound interface = 1500 bytes
- Packet IHL (Internet Header Length) = 7 (this means the header is 7 * 4 = 28 bytes)

The maximum data that can be included in each fragment is the MTU minus the IP header size. So, for the first fragment, it's 1500 - 28 = 1472 bytes.

The fragmentation offset for the second fragment would be 1472 / 8 = 184.

For subsequent fragments, the offset would increase by the same amount (184) for each fragment.

echo "184" | base64

Ans -> MTg0Cg==

####  Capstone - 02 PCAP Question 2 10 ####

Refer to the diagram

Using the PCAP stored on Capstone-02.

What is the Answer to Question 2 referenced in “Flag-02f.txt”

tcpdump -n -r {pcap} "BPF Filter" | wc -l

student@blue-internet-host-student-11:~$ proxychains telnet 10.1.1.11

To answer these 4 questions, you will need to use tcpdump and BPF's against the capstone-bpf.pcap file.



Question 2:

What is the total number of fragmented packets?

Provide the number of packets converted to BASE64.

-------------------------------------------------------------------------------

##### Ans #####

tcpdump -n -r capstone-bpf.pcap 'ip[6] & 0x20 != 0 or ip[6:2] & 0x1fff != 0' | wc -l | base64

MjcyOQo=

##### Interpretting the answer #####

-n: This option prevents tcpdump from converting addresses (like host addresses and port numbers) to names.
-r capstone-bpf.pcap: This option specifies that tcpdump should read from the pcap file capstone-bpf.pcap.
The filter expression is the most complex part:

ip[6] & 0x20 != 0: This part of the filter expression checks the IP header's flags and fragmentation offset field. Specifically, ip[6] refers to the byte in the IP header that contains the flags and the high-order bits of the fragmentation offset. The & 0x20 part checks if the "More Fragments" flag is set. This flag is used in IP fragmentation and is set for all fragments except the last one.

or ip[6:2] & 0x1fff != 0: This part continues the check for fragmentation. ip[6:2] accesses 2 bytes starting from the sixth byte of the IP header (including the flags and the entire fragmentation offset), and & 0x1fff applies a mask to isolate the 13 bits of the fragmentation offset field. The check != 0 determines if this is not the first fragment (i.e., if the packet is a middle or last fragment in a series).

A "mask" is a binary pattern used to extract, modify, or manipulate specific bits from another binary pattern.
In the context of your tcpdump filter (ip[6:2] & 0x1fff), 0x1fff is the mask being applied. In binary, 0x1fff is 0001 1111 1111 1111, which has 13 bits set to 1.

In summary, this tcpdump command is used to filter and display packets from the capstone-bpf.pcap file that are either not the first fragment in a fragmented set of IP packets (ip[6] & 0x20 != 0) or are middle or last fragments (ip[6:2] & 0x1fff != 0). This command is particularly useful for analyzing fragmented IP traffic.


#### Capstone - 02 PCAP Question 3 10 ####

Using the PCAP stored on Capstone-02.

What is the Answer to Question 3 referenced in “Flag-02f.txt”

tcpdump -n -r {pcap} "BPF Filter" | wc -l

Question 3:

How many packets have the DF flag set and has ONLY the RST and FIN TCP Flags set?

Provide the number of packets converted to BASE64.

-------------------------------------------------------------------------------

##### Ans #####

tcpdump -n -r capstone-bpf.pcap 'ip[6] & 0x40 != 0 and tcp[13] = 0x05' | wc -l | base64

-> MTA5Cg==

##### Interpretting the answer #####

ip[6] & 0x40 != 0: This part of the filter expression examines the IP header, specifically the byte that contains the flags and a portion of the fragmentation offset. The expression & 0x40 isolates the "Don't Fragment" (DF) flag bit. If the DF bit is set (!= 0), the expression evaluates to true. This filter selects IP packets where the "Don't Fragment" flag is set.

tcp[13] = 0x05: This part of the filter expression examines the TCP header, specifically the 13th byte, which contains flags indicating the state of the TCP connection. In TCP flag encoding, 0x05 represents the ACK and RST flags being set. An ACK is used to acknowledge the receipt of a packet, and RST is used to reset the connection. This filter selects TCP packets where both the ACK and RST flags are set.

Putting it all together, this tcpdump command filters for and displays packets from the specified pcap file that are TCP packets with both ACK and RST flags set and are IP packets with the "Don't Fragment" flag set. This command is useful for analyzing specific network issues or behaviors, such as connections being reset in scenarios where fragmentation is not allowed.


#### Capstone - 02 PCAP Question 1 15 ####

Using the PCAP stored on Capstone-02.

What is the Answer to Question 1 referenced in “Flag-02f.txt”

tcpdump -n -r {pcap} "BPF Filter" | wc -l

Question 1:

Using BPF’s, determine how many packets with a DSCP of 26 being sent to the host 10.0.0.103.

Provide the number of packets converted to BASE64.

-------------------------------------------------------------------------------

##### Ans #####

tcpdump -n -r capstone-bpf.pcap 'ip[1] & 0xfc == 104 and dst host 10.0.0.103' | wc -l | base64

##### Interpretting the answer #####

ip[1] & 0xfc == 104: This part of the expression is filtering based on the IP header:
ip[1]: Refers to the second byte of the IP header, which contains the Differentiated Services Code Point (DSCP) and Explicit Congestion Notification (ECN).
& 0xfc: This applies a bitmask to the DSCP/ECN byte, isolating the DSCP portion (first 6 bits of the byte). 0xfc in binary is 11111100.

== 104: This compares the masked value to 104 (in binary 01101000). This checks whether the DSCP value is 26 (011010 shifted left by two bits, as DSCP occupies the most significant 6 bits of the byte).
and dst host 10.0.0.103: This filters packets where the destination IP address is 10.0.0.103.

In summary, this command will display packets from the pcap file that have a DSCP value of 26 and are destined for the host 10.0.0.103. This type of filtering is useful for analyzing network traffic with specific QoS settings (as indicated by DSCP values) going to a particular destination.

#### Capstone - 02 PCAP Question 4 15 ####

Using the PCAP stored on Capstone-02.
What is the Answer to Question 4 referenced in “Flag-02f.txt”
tcpdump -n -r {pcap} "BPF Filter" | wc -l

Question 4:

An attacker is targeting the host 10.0.0.104 with either a TCP full or half open scan. Based off the pcap, how many ports are open?

Provide the number of ports converted to BASE64.

##### Ans #####

Write a tcpdump script for this scenario: An attacker is targeting the host 10.0.0.104 with either a TCP full or half open scan. Based off the pcap, how many ports are open?

tcpdump -n -r capstone-bpf.pcap 'tcp[tcpflags] == tcp-syn+tcp-ack and src host 10.0.0.104' | awk '{print $3}' | cut -d. -f1-5 | sort | uniq | wc -l | base64

The filter:
tcp[tcpflags] == tcp-syn+tcp-ack: Filters TCP packets where the TCP flags set are SYN and ACK. This typically indicates a response to a SYN packet, part of the TCP three-way handshake.

src host 10.0.0.104: Further filters these packets to those originating from the source IP address 10.0.0.104.

awk '{print $3}'
This extracts and prints the third field from each line of the tcpdump output. In tcpdump output, this usually corresponds to the source IP address and port (e.g., 10.0.0.104.443).

cut -d. -f1-5
Splits the line by the delimiter . and selects the first 5 fields. This effectively retains the entire IP address and port (since an IP address has 4 fields, and the port is the 5th field).

sort | uniq
Sorts the lines and then passes them to uniq, which removes any duplicate lines

### Networking - 7 - Capstone v2 03 ###

#### Capstone - 03 Web Question 1 5 ####

Using the questions found on Capstone-03 web-page.
What is the Answer to Packet Crafting and Socket Programming Question 1?

##### Ans #####
 
USED HINT -> file:///home/student/10.1.1.25/hint-03a.png

###### Question 1 ######

RAW Sockets are created in ________ space. Specify the one word BASE64 conversion of your answer in ALL CAPS.

Raw sockets are created in user space. The Base64 conversion of "USER" in all caps is "VVNFUg==".

echo "KERNEL" | base64

Ans -> S0VSTkVMCg==

#### Capstone - 03 Web Question 2 5 ####

Using the questions found on Capstone-03 web-page.

What is the Answer to Packet Crafting and Socket Programming Question 2?

##### Ans #####
###### Question 2 ######

Which module would you need to import to convert data into a corresponding 2-digit hex representation?
Specify the module in lowercase and converted to BASE64.

echo "binascii" | base64

binascii

#### Capstone - 03 Web Question 3 5 ####

Using the questions found on Capstone-03 web-page.
What is the Answer to Packet Crafting and Socket Programming Question 3?

##### Ans #####
###### Question 3 ######

What is the proper format to pro-grammatically pack the IPv4 RAW header?
Specify the answer in the proper case. Include only what is between the single or double quotes and not the quotes themselves or the "!".
Provide the answer converted to BASE64.

echo "BBHHHBBH4s4s" | base64

QkJISEhCQkg0czRzCg==

#### Capstone - 03 Web Question 4 5 ####

Using the questions found on Capstone-03 web-page.
What is the Answer to Packet Crafting and Socket Programming Question 4?

##### Ans #####
###### Question 4 ######

What is the default (and most common) encoding used when converting data to be sent over the network.
Provide your answer in ALL CAPS and converted to BASE64. 

UTF-8
echo "UTF-8" | base64

#### Capstone - 03 Web Question 5 5 ####

Using the questions found on Capstone-03 web-page.
What is the Answer to Packet Crafting and Socket Programming Question 5?

##### Ans #####
###### Question 4 ######

What type of header does TCP build to perform the checksum function?
i.e. [ANSWER] Header
Provide your answer in ALL CAPS and converted to BASE64. 

TCP creates a 96-bit pseudo header to calculate the checksum function.
echo "PSEUDO" | base64
PSEUDO

UFNFVURPCg==

#### Capstone - 03 Socket 10 ####

What was the response that was referenced from “Hint-03b”? Provide the answer (exactly as you received it) converted to BASE64
##### Ans #####

import socket

# Create a socket object
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Define the server address and port
server_address = ('localhost', 12345)  # replace with your server address and port

# Connect to the server
s.connect(server_address)

# Encode the message to bytes
message = "hi"
message_bytes = message.encode('utf-8')

# Send the message
s.sendall(message_bytes)

# Receive the response
data = s.recv(1024)

# Decode the response from bytes to UTF-8 string
response = data.decode('utf-8')

# Print the response
print("Response: ", response)

# Close the connection
s.close()

NDIgNjEgN2EgNjkgNmUgNjcgNjE=

Converted to hex using this tool https://www.base64decode.org/

42 61 7a 69 6e 67 61

Hex to ASCII -> https://www.rapidtables.com/convert/number/hex-to-ascii.html

Bazinga

echo "Bazinga" | base64

Ans -> QmF6aW5nYQo=

#### Capstone - 04 Malware Discovery 15 ####

What is the message referenced by “Hint-04a.png”. Provide the message (exactly as you received it) converted to BASE64

hint-04a.png: There is another box (Capstone-05) on a different network (that only this system can see) trying to attack this box, on one of the port(s) associated with the W32/Blaster Worm. Use a sniffing tool to try to find the message it is trying to send. 

ssh net4_student11@10.50.27.32 -p 22 41101:10.1.1.33:23


There is a computer on a different network trying to attack my computer, on one of the port(s) associated with the W32/Blaster Worm. 
write a tcpdump script to try and find the message it is trying to send.

##### Ans #####

telnet to the machine and run 

tcpdump -i any -X 'port 69'

echo "I just want to say LOVE YOU SAN" | base64

SSBqdXN0IHdhbnQgdG8gc2F5IExPVkUgWU9VIFNBTgo=

#### Capstone - 04 IP Discovery 15 ####

What is the IP referenced in “Hint-04b”. Provide the exact dotted decimal IP address discovered for next pivot.

hint-05b -> RIPv2 seems to be running on the 10.1.1.0/25 network. Try to sniff out the traffic to find out what networks its advertising in its updates. What you find will bte the IP address of the next environment pivot to access from your INTERNET_HOST 


tcpdump --interface eth0 -vvv dst 224.0.0.9

Look at the tcpdump

10.50.41.66/32


#### Capstone - 06 Port Discovery 5 ####

What is the answer to the question referenced in “Hint-06a”? Provide the answer converted to BASE64.

Hint
Conduct your scan in the range of 7000-8000 to minimize the scan time.

##### Ans #####

Change TTL as per the hint:
iptables -t mangle -A POSTROUTING -j TTL --ttl-set 255

ran your scans 

Ans -> Nzc3Nwo=


#### Capstone - 07 Credential Farming 10 ####

What is the answer to the question referenced in “Hint-07a”? Provide the answer (exactly as you found it) converted to BASE64
You will use the phrase as your password for this system only.

Hint-07a: SSH is running on a higher port but it is not accessible from the outside. It also seems to use different username and password than what the other systems use. How can we intercept these credentials? Maybe another system has a tool that can help us. The Flag for this system is the password you find converted to BASE64. Credentials for this system will be exactly what you did. 

##### Ans #####

Build a dynamic channel 

ssh net4_student11@10.50.41.66 -p 7777 -D 9050

Run 

tcpdump -A port 23

wait for the passwords

username: net3_comrade15@capstone-07
password: Netflix and Chill

echo "Netflix and Chill" | base64

#### Capstone - 07 Credential Farming 10 ####

What is the Answer referenced in “Hint-08a.png”? Provide the answer converted to BASE64.

##### Ans #####

    # Create a local tunnel to be used for telnet. Local tunnel to host A 
	ssh net4_student11@10.50.41.66 -p 7777 -L 41103:10.2.2.7:23
	telnet localhost 41103
        username: net3_comrade15
        password: Netflix and Chill

	# Let's create a remote tunnel back to A from B
	ssh net4_student11@10.2.2.6 -p 7777 -R 41104:10.2.2.7:2222   

	# A local tunnel from the internet host to host A
	ssh net4_student11@10.50.41.66 -p 7777 -L 41105:localhost:41104  

	# A dynamic channel to B 
	ssh net3_comrade15@localhost -p 41105 -D 9050

	# Run ip neighbor to find any near by addresses 
	10.10.10.167
	10.2.2.14
	10.2.2.6
	10.10.10.140

	ss -anltp
		doesn't generate anything really 

	from running ip addr I found the following addresses:
		10.2.2.7 -> eth0
		10.10.10.129 -> eth1
	
	Scanning for eth1, I found these open addresses:
		10.10.10.129 (23, 80)
		10.10.10.140 (21)
		10.10.10.167 (80)
		10.10.10.182 (21 -> ftp)

#### Capstone - 08 Port Discovery 5 ####

What is the Answer referenced in “Hint-08a.png”? Provide the answer converted to BASE64.

##### Ans #####

Hint-08a: SSH is running on the port that corresponds with the HTTP status code for Moved Permanently. The flag for this system is the port number converted to BASE64

HTTP Status Code for moved Permanently - 301
MzAxCg==

#### Capstone - 10 Port Discovery 5 ####

What is the Answer referenced in “Hint-10a.png”? Provide the answer converted to BASE64.

##### Ans #####

Hint-10a: SSH is running  on the port that corresponds with the HTTP status code for not Found. The flag for this system is the port number converted to BASE64.

Status-code: 404
NDA0Cg==

#### Capstone - 12 Port Discovery 5 ####

What is the Answer referenced in “Hint-12a.png”? Provide the answer converted to BASE64.

##### Ans #####

Hint-12a: SSH is running on the port that corresponds with the HTTP status code for Gateway Timeout. The flag for this system is the port number converted to BASE64. 

Status Code: 504
NTA0Cg==

#### Capstone - 09 Web Question 1 5 ####

Using the questions found on Capstone-09 web-page.
What is the Answer to Network Reconnaissance Question 1?

##### Ans #####

###### ESTABLISHING A LOCAL TUNNEL TO 10.10.10.140 ######
ssh net3_comrade15@localhost -p 41105 -L 41106:10.10.10.140:301

###### Dynamic tunnel ######
ssh net4_student11@localhost -p 41106 -D 9050

from running ip addr I found the following addresses:
        10.10.10.140/25 -> eth0
        192.168.10.44/27 -> eth1

ip neighbor listed 
	192.168.10.62

Run vertical scans based on the subnet /27 which should be 32 hosts from .44
	Ip addresses found
		192.168.10.39
		192.168.10.44

Run horizontal scans from ports - 0- 65000, found 21, 3790, 4444, 5687 

Question 1
What type of recon is being performed if you are performing ARP scans and sending Gratuitous ARPs to perform a MitM attack?

Provide the 2 word process in ALL CAPS and converted to Base64.

i.e. [word1] [word2]

echo "ACTIVE INTERNAL" | base64

????????????

#### Capstone - 09 Web Question 2 5 ####

Using the questions found on Capstone-09 web-page.
What is the Answer to Network Reconnaissance Question 2?

Question 2
What is the typical flag response (if any) would a Linux host perform when receiving a Stealth scan on an CLOSED port?

Provide the 3 letter abbreviated name of the FLAG(s) in ALL CAPS, separated by / (use “NONE” if no response) and converted to Base64.

##### Ans #####

echo "RST" | base64
UlNUCg==

#### Capstone - 09 Web Question 3 5 ####

Using the questions found on Capstone-09 web-page.
What is the Answer to Network Reconnaissance Question 3?

Question 3
What command line tool can be used to pull DNS information from the server using TCP port 43?
Provide the command in ALL CAPS and converted to Base64.

##### Ans #####

echo "WHOIS" | base64

#### Capstone - 09 Web Question 4 5 ####

Using the questions found on Capstone-09 web-page.
What is the Answer to Network Reconnaissance Question 4?

Question 4
Which NMAP scan is able to determine open ports on a target by spoofing packets to make them looks as if they came from a zombie machine?

Provide the scan name in ALL CAPS and converted to Base64.
##### Ans #####

echo "IDLE" | base64

#### Capstone - 09 Web Question 5 5 ####

Using the questions found on Capstone-09 web-page.
What is the Answer to Network Reconnaissance Question 5?

Question 5
A cyber analyst wants to us Netcat to perform a banner grab on a target IP of 10.1.0.1 port 1111.
Provide the exact command (without switches and including spaces) you would perform on the command line and converted to Base64.

##### Ans #####

echo "nc 10.1.0.1 1111" | base64
bmMgMTAuMS4wLjEgMTExMQo=

#### Capstone - 09 Web Question 5 5 ####

Using the questions found on Capstone-11 web-page.
What is the Answer to Movement & Redirection Question 3?

##### Ans #####

To get to the answer I ran through the steps below

###### ESTABLISHING A LOCAL TUNNEL TO 10.10.10.167 ######

ssh net3_comrade15@localhost -p 41105 -L 41108:10.10.10.167:404

###### Dynamic tunnel to .167 ######
ssh net4_student11@localhost -p 41108 -D 9050

running ip addr on the dynamic tunnel, I found these addresses:

127.0.0.1/8
10.10.10.167/25
192.168.10.70/27

From running scans on subnet 192.168.10.70/27 I found the following ip addresses
	192.168.10.70 -> port 80
	192.168.10.80 ->port 21

Connetcting to 192.168.10.80 using proxychains and wget, I got the hint below 

Hint-11a -> There is a webservice running on the port that corresponds with the default port for Proxy-chains 

port for hint-11a -> 9050

Connected to proychains -wget http:192.168.10.80:9050 for questions on capstonev2 10

Ans -> asymmetric

QVNZTU1FVFJJQwo=

#### Capstone Capstone - 11 Web Question 5 5 ####

Using the questions found on Capstone-11 web-page.
What is the Answer to Movement & Redirection Question 5?

Which tool adds “FTP Like” services to SSH?
Provide the exact tool acronym in ALL CAPS and converted to Base64.

##### Ans #####

Ans -> SFTP

#### Capstone - 11 Web Question 1 10 ####

Using the questions found on Capstone-11 web-page.
What is the Answer to Movement & Redirection Question 1?


      -----------     ------       ----------    -------
      | Outside |     | FW |       | Inside |    | Web |
      -----------     ------       ----------    -------
      147.25.99.1                 192.168.1.27  188.8.8.8
  


A.) ssh outside@192.168.1.27 -L 1234:188.8.8.8:80 -NT

B.) ssh inside@147.25.99.1 -L 9876:188.8.8.8:1234 -NT

C.) ssh outside@147.25.99.1 -L 1234:188.8.8.8:80 -NT

D.) ssh inside@192.168.1.27 -L 1234:188.8.8.8:80 -NT

##### Ans #####

Ans -> D
echo "D" | base64
RAo=

#### Capstone - 11 Web Question 2 10 ####

Using the questions found on Capstone-11 web-page.
What is the Answer to Movement & Redirection Question 2?

Which SSH syntax will properly setup a Remote port forward from the “Inside Host” to give “Outside Host” access to the Internal Website?

      -----------     ------       ----------    -------
      | Outside |     | FW |       | Inside |    | Web |
      -----------     ------       ----------    -------
      147.25.99.1                 192.168.1.27  192.168.1.10
  


A.) ssh Outside@147.25.99.1 -R 9876:192.168.1.10:80 -NT

B.) ssh Inside@147.25.99.1 -R 9876:192.168.1.10:80 -NT

C.) ssh Outside@192.168.1.10 -R 9876:147.25.99.1:80 -NT

D.) ssh Inside@192.168.1.27 -R 9876:192.168.1.10:80 -NT


echo "ssh Inside@192.168.1.27 -R 9876:192.168.1.10:80 -NT" | base64

##### Ans #####

Ans -> D
echo "D" | base64
RAo=

#### Capstone - 11 Web Question 4 15 ####

Using the questions found on Capstone-11 web-page.
What is the Answer to Movement & Redirection Question 4?

Question 4
What exact SCP command would you use to copy a file called “secret.txt” from the 'tgt' home directory, to your current working directory, using the Dynamic tunnel you have established.

      -----------     ------       ----------    -------
      | outside |     | FW |       | inside |    | tgt |
      -----------     ------       ----------    -------
      147.25.99.1                 192.168.1.27  192.168.1.10
  

outside$: ssh inside@192.168.1.27 -D 9050 -NT
Provide the command exactly as you would run in from the command line (including any appropriate spaces and all lower case) using proxychains and converted to Base64.
proxychains scp {username}@{ip}:{path}/{filename} {target location}

##### Ans #####

echo "proxychains scp tgt@192.168.1.10:/home/tgt/secret.txt ." | base64

#### Capstone - 13 Web Question 1 5 ####

Using the questions found on Capstone-13 web-page.
What is the Answer to Network Analysis Question 1?


Question 
Which option in Wireshark could you use if you wanted to identify which IP address are communicating with each other?
Specify your answer in ALL CAPS and converted to Base64.


##### Ans #####

Conversations

CONVERSATIONS

echo "CONVERSATIONS" | base64

#### Capstone - 13 Web Question 2 5 ####

Using the questions found on Capstone-13 web-page.
What is the Answer to Network Analysis Question 2?

Question 2
What is the name of the data type that is a Cisco proprietary protocol used for collecting IP traffic information and monitoring network flow?
Specify your answer in ALL CAPS and converted to Base64.

##### Ans #####

NETFLOW

echo "NETFLOW" | base64

#### Capstone - 13 Web Question 3 5 ####

Using the questions found on Capstone-13 web-page.
What is the Answer to Network Analysis Question 3?

Question 3
A method of data collection where this device can be placed in line on the wire to capture traffic?
What is this device called?
Specify your one word answer in ALL CAPS and converted to Base64.

##### Ans #####

echo "TAP" | base64

#### Capstone - 13 Web Question 4 5 ####

Using the questions found on Capstone-13 web-page.
What is the Answer to Network Analysis Question 4?

Question 4
A network admin starts to notice an increase in requests for certain files, changes to the registry and unusual tasks being run.

This anomaly is an Indicator of ________?

Specify your 1 word answer in ALL CAPS and converted to Base64.

##### Ans #####

ndicator of Compromise (IoC).

echo "IOC" | base64

#### Capstone - 13 Web Question 5 5 ####

Using the questions found on Capstone-13 web-page.
What is the Answer to Network Analysis Question 5?

Question 5
What type of malware doesn't use an encryption key but is capable of rewriting its code and signature patterns with each iteration?

Specify your 1 word answer in ALL CAPS and converted to Base64.

##### Ans #####

Metamorphic

METAMORPHIC

echo "METAMORPHIC" | base64

#### Capstone - 13 PCAP Question 1 5 ####

Using the PCAP stored on Capstone-13.
What is the Answer to Question 1 referenced in “Flag-13f.txt”

copy the cctc directory to the local machine for analysis 

##### Ans #####

scp -r student@192.168.10.101:/usr/share/cctc/ Temp_101_Folder/

proxychains scp -r net4_student11@192.168.10.101:/usr/share/cctc/ Temp_101_Folder/

scp -r student@10.50.39.135:/home/student/Temp_101_Folder/cctc . 

To answer these 8 questions, you will need extract the capstone-analysis-HEX-Encoded.pcap file that you will need extract, decode with XXD, and open with Wireshark.

cd to the location of the file download
xxd -r capstone-analysis_HEX-ENCODED.pcap capstone-analysis-decoded_home1.pcap
-------------------------------------------------------------------------------

Question 1:

Which ip address initiated the attack against the FTP server?

Provide the ip address in the x.x.x.x format and converted to Base64.

echo "10.1.0.108" | base64

????? ASK THE INSTRUCTOR HOW TO GO ABOUT THIS !!!!

#### Capstone - 13 PCAP Question 2 5 ####

Using the PCAP stored on Capstone-13.

What is the Answer to Question 2 referenced in “Flag-13f.txt”

##### Ans #####


-------------------------------------------------------------------------------

Question 2:

How many failed attempts to guess the FTP password?

Provide number and converted to Base64.

-------------------------------------------------------------------------------

frame contains "Login incorrect" -> 4 times 

echo "4" | base64

#### Capstone - 13 PCAP Question 3 5 ####

Using the PCAP stored on Capstone-13.

What is the Answer to Question 3 referenced in “Flag-13f.txt”

##### Ans #####

Question 3:

What is the correct FTP password?

Provide the exact password and converted to Base64.
-------------------------------------------------------------------------------

frame contains "Login" -> found PASS, w and the echo for that is dwo=

#### Capstone - 13 PCAP Question 4 5 ####

Using the PCAP stored on Capstone-13.

What is the Answer to Question 4 referenced in “Flag-13f.txt”

##### Ans #####


Question 4:

What is the system IP that was compromised?

Provide the ip address in the x.x.x.x format and converted to Base64.

-------------------------------------------------------------------------------

10.2.0.2

echo "10.2.0.2" | base64

?????????  ASK INSTRUCTOR ABOUT THIS !!!!!!!!!

#### Capstone - 13 PCAP Question 5 5 ####

Using the PCAP stored on Capstone-13.

What is the Answer to Question 5 referenced in “Flag-13f.txt”

##### Ans #####

Question 5:

What is the FTP version?

Provide the version number only and converted to Base64.

-------------------------------------------------------------------------------

Search ftp 

Scroll through the packet list, and you may see packets with "Response: 220" in the "Info" column. This is the FTP server's welcome message, and it typically includes information about the server and its version.

Ans -> 3.0.2

echo "3.0.2" | base64

#### Capstone - 13 PCAP Question 6 10 ####

Using the PCAP stored on Capstone-13.

What is the Answer to Question 6 referenced in “Flag-13f.txt”

##### Ans #####

Question 6:

What is the name of the file taken by the attacker?

Provide the filename exactly as shown and converted to Base64.

-------------------------------------------------------------------------------

echo "test.txt" | base64

?????????  ASK INSTRUCTOR ABOUT THIS !!!!!!!!!

#### Capstone - 13 PCAP Question 7 10 ####

Using the PCAP stored on Capstone-13.

What is the Answer to Question 7 referenced in “Flag-13f.txt”

##### Ans #####

Question 7:

What was the message contained within the extracted file?

Provide the message exactly as shown and converted to Base64.

-------------------------------------------------------------------------------

company_payroll_2019

hi

echo "Here comes the directory listing." | base64

?????

#### Capstone - 13 PCAP Question 8 10 ####

Using the PCAP stored on Capstone-13.

What is the Answer to Question 8 referenced in “Flag-13f.txt”

##### Ans #####
Question 8:

What is the name of the file uploaded by the attacker?

Provide the filename exactly as shown and converted to Base64.

-------------------------------------------------------------------------------
echo "company_payroll_2019" | base64

#### Capstone - 14 Web Question 1 5 ####

Using the questions found on Capstone-14 web-page.
What is the Answer to Network Filtering Question 1?

Question 1
In NAT, which Hook would I place a rule to change the source IP for all traffic thru this host?
Specify your 1 word answer in ALL CAPS and converted to Base64.

###### Ans ######

There is a webservice running on the port that falls in the Expanded Extended Cisco Numbered ACL Range
Ran proxy scans for all the ports and connected to 2223

POSTROUTING

echo "POSTROUTING" | base64

#### Capstone - 14 Web Question 2 5 ####

Using the questions found on Capstone-14 web-page.
What is the Answer to Network Filtering Question 2?

Question 2
Which Hook would I apply rules that are destined for the ‘localhost’?
Specify your 1 word answer in ALL CAPS and converted to Base64.

###### Ans ######

INPUT

echo "INPUT" | base64

#### Capstone - 14 Web Question 3 5 ####

Using the questions found on Capstone-14 web-page.
What is the Answer to Network Filtering Question 2?

Question 3
What recognition method do IDS/IPS primarily use to detect malicious traffic?
Specify your 1 word answer in ALL CAPS and converted to Base64.

###### Ans ######

Signature-based

SIGNATURE-BASED 

echo "SIGNATURE" | base64

#### Capstone - 14 Web Question 4 5 ####

Using the questions found on Capstone-14 web-page.
What is the Answer to Network Filtering Question 4?

Question 4

In iptables, which Table would I use if I wanted to preform packet alterations?
Specify your 1 word answer in ALL CAPS and converted to Base64.

###### Ans ######

mangle

MANGLE

echo "MANGLE" | base64

#### Capstone - 14 Web Question 5 5 ####

Using the questions found on Capstone-14 web-page.
What is the Answer to Network Filtering Question 5?

Question 5

What is the default family for NFTables?
Specify your 1 word answer in ALL CAPS and converted to Base64.

###### Ans ######

IP 

echo "IP" | base64

#### Capstone - 14 Snort Question 1 5 ####

What is the Answer to Question 1 referenced in “Flag-14f.txt”

To answer these s questions, you will need to examine the Snort services running on this system.

-------------------------------------------------------------------------------

Question 1:

How many rule files are on the system?

Provide the number converted to Base64 as your answer.

find /etc/snort/rules/ -name "*.rules" 2>/dev/null | wc -l

Gives the answer as 24

echo "24" | base64

###### Ans ######


#### Capstone - 14 Snort Question 2 5 ####

What is the Answer to Question 2 referenced in “Flag-14f.txt”

-------------------------------------------------------------------------------

Question 2:

How many of the rules are currently in use to match on traffic?

Provide the number converted to Base64 as your answer.

###### Ans ######

grep -c '^include' /etc/snort/snort.conf

echo "7" | base64

#### Capstone - 14 Snort Question 3 10 ####

What is the Answer to Question 3 referenced in “Flag-14f.txt”

-------------------------------------------------------------------------------

Question 3:

Which rule will look for someone doing a null scan ?

Provide only the filename as your answer (i.e. ‘file.rules’) and converted to Base64.

###### Ans ######

grep -v '^#' /etc/snort/rules/*.rules | grep 'flags: 0'

Will give, alien-abductions.rules 

echo "alien-abductions.rules" | base64

YWxpZW4tYWJkdWN0aW9ucy5ydWxlcwo=

#### Capstone - 14 Snort Question 4 10 ####

What is the Answer to Question 4 referenced in “Flag-14f.txt”

-------------------------------------------------------------------------------

Question 4:

What is the exact Alert Message that is being triggered on the system?

Convert the exact message as you see it and convert it to Base64 for your answer.

---------------------------------------------------------------

message that says to print whenever a rule triggers.....

/var/log/snort/ -> logs are stored here. 
cat /var/log/snort/README.txt -> See where the messages are stored 
ps -ef | grep snort -> See where else snort is running

Looks like the file is being stored here -> /etc/snort/snort.conf 
root      9922     1  0 Dec10 ?        00:00:05 /usr/bin/snort -D -c /etc/snort/snort.conf -l /var/log/capstone

ls /var/log/capstone/ -> Check what's in that folder 
cat /var/log/capstone/alert -> See what the alert says. 

The message below is listed on the alert. 

Answ -> Who got that kinda monies to pay that!

echo "Who got that kinda monies to pay that!" | base64

###### Ans ######


#### Capstone - 14 Snort Question 5 15 ####

What is the Answer to Question 5 referenced in “Flag-14f.txt”

Question 5:

From what IP is the attack coming from?

Provide your answer in the x.x.x.x format and converted to Base64.

-------------------------------------------------------------------------------

###### Ans ######

From the alert in question 4, 

12/11-14:44:31.574629 192.168.10.99:34682 -> 192.168.10.111:139

looks like the message is coming from 192.168.10.99

echo "192.168.10.99" | base64


###### STUDY ACTIVE INTERNAL / PASSIVE ######