# HOW TO PERFORM CHANNELING FROM A FLOATING ADDRESS # 

Task 3
1. T3 is the authorized initial pivot
Conduct passive recon on the Target T3, it appears to have access to the 10.3.0.0/24 subnet.
Create a Local Port Forward from your Internet_Host to T3 targeting:
ip: 10.3.0.27
port: `HTTP``
Initial ssh request was denied
To create a tunnel, need to use the float IP as ssh to T3 is denied so,
Ssh
Need to create a local port to T3

internet_host$ ssh netX_studentX@{T3_float_ip} -L NssXX:10.3.0.27:80 -NT

ssh net25_student25@10.3.0.27 -L NssXX:10.3.0.27:80 -NT

### Floating Address Provided 10.50.44.68 ###

1. Step 1: find the range of addresses floating using 10.50.44 as the network address, starting and ending range as 68

`./scan.sh`

List of open ports open. 
 
Following the ports open you can tell what protocol they belong to. Follow the instructions for the following protocols

### Protocol 80 - https ####
run 
`wget -r http://10.50.44.68` # downloads files that are downloadable 
Check the files that have been downloaded. Cat and see the contents of those files 
cat 10.50.44.68/index.html

2. Step 2: Look for hints here... if hints is found just scan that specific port e.g. John is... telling us who John is so..

3. Step 3: `ssh john@10.50.44.68 -D 9050` # Guess the password i.e. password 

4. Step 4: `ip a` # This will list the ip addresses present, from running this you get etho 

5. Step 5: `proxychains nmap -Pn -sT 104.16.181.1/27 -p 21` # Will try to establish a connection if there's none

The command instructs nmap to scan the 32 IP addresses in the range 104.16.181.1 to 104.16.181.31, through a series of proxies, targeting only port 21, without first checking if the hosts are online. This could be used to find FTP services running on these IPs while masking the source of the scan by routing it through proxy servers.

`-Pn`: This option tells nmap to skip the discovery phase where it determines if the host is online before scanning it. It assumes the host is online and proceeds with the scan. This is useful when scanning through a proxy because ICMP packets (used for host discovery) might be blocked or filtered through the proxy.

`-sT`: This option specifies a TCP connect scan, which is the default TCP scan type when SYN scan is not an option. This is a more “polite” form of scanning compared to the SYN scan (-sS), as it completes the TCP three-way handshake process.

6. Step 6: If nothing is established, check the `ls /usr/share/cctc/` directory for any files. 


### Protocol 21 - file transfer protocol ###
 
7. step 7: `wget -r ftp://10.50.44.68` # Contacts the ftp server


### 