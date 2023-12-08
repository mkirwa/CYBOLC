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


-------------------------------------------------------------------------------

Question 1:

Using BPF’s, determine how many packets with a DSCP of 26 being sent to the host 10.0.0.103.

Provide the number of packets converted to BASE64.

-------------------------------------------------------------------------------

Question 2:

What is the total number of fragmented packets?

Provide the number of packets converted to BASE64.

-------------------------------------------------------------------------------

Question 3:

How many packets have the DF flag set and has ONLY the RST and FIN TCP Flags set?

Provide the number of packets converted to BASE64.

-------------------------------------------------------------------------------

Question 4:

An attacker is targeting the host 10.0.0.104 with either a TCP full or half open scan. Based off the pcap, how many ports are open?

Provide the number of ports converted to BASE64.

##### Ans #####

tcpdump -n -r capstone-bpf.pcap 'ip[6] & 0x20 != 0 or ip[6:2] & 0x1fff != 0' | wc -l | base64

MjcyOQo=

#### Capstone - 02 PCAP Question 3 10 ####

Using the PCAP stored on Capstone-02.

What is the Answer to Question 3 referenced in “Flag-02f.txt”

tcpdump -n -r {pcap} "BPF Filter" | wc -l

##### Ans #####

tcpdump -n -r capstone-bpf.pcap 'ip[6] & 0x40 != 0 and tcp[13] = 0x05' | wc -l | base64

-> MTA5Cg==

#### Capstone - 02 PCAP Question 1 15 ####

Using the PCAP stored on Capstone-02.

What is the Answer to Question 1 referenced in “Flag-02f.txt”

tcpdump -n -r {pcap} "BPF Filter" | wc -l

##### Ans #####

tcpdump -n -r capstone-bpf.pcap 'ip[1] & 0xfc == 104 and dst host 10.0.0.103' | wc -l | base64

#### Capstone - 02 PCAP Question 4 15 ####

Using the PCAP stored on Capstone-02.
What is the Answer to Question 4 referenced in “Flag-02f.txt”
tcpdump -n -r {pcap} "BPF Filter" | wc -l

##### Ans #####

Write a tcpdump script for this scenario: An attacker is targeting the host 10.0.0.104 with either a TCP full or half open scan. Based off the pcap, how many ports are open?

tcpdump -n -r capstone-bpf.pcap 'tcp[tcpflags] == tcp-syn+tcp-ack and src host 10.0.0.104' | awk '{print $3}' | cut -d. -f1-5 | sort | uniq | wc -l | base64


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

	# Let's create a remote tunnel back to A from B
	ssh net4_student11@10.2.2.6 -p 7777 -R 41104:10.2.2.7:41106   

	# A local tunnel from the internet host to host A
	ssh net4_student11@10.50.41.66 -p 7777 -L 41105:localhost:41104  

	# A dynamic channel to B 
	ssh net4_student11@localhost -p 41105 -D 9050





    # Create a local tunnel to be used for telnet to D
	ssh hostC@localhost -p 4444 -L 5555:10.3.9.39:23 
	telnet localhost 5555 

	# Let's create a remote tunnel back to C from D
	ssh hostC@10.3.9.33 -p 22 -R 6666:localhost(this_is_at_host_D):3597

	# A local tunnel from internet host 
	ssh hostC@localhost -p 4444 -L 7777:localhost(this_is_host_c_localhost):6666

	# Let's create a dynamic tunnel to D 
	ssh hostD@localhost -p 7777 -D 9050


