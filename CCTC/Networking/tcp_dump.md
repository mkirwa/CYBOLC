### TCPDUMP SYNTAX ###

Can sniff packets from layer 1 to layer 6 
Helps when ssh'ing into a box. 

### Getting the help menu ###

`tcpdump --help`

1. `tcpdump -i etho0 -v host 192.168.1.1`
2. `tcpdump -i etho0 -v dst 192.168.1.1`
3. `tcpdump -i etho0 -v src 192.168.1.1`

-i eth0 # Specifies the interface you are trying to use 
-v # prints out all the traffic that is captured

#### Filters ####
host 192.168.1.1 # Specificies the host, monitors traffic with regards to this host. In place of the host you could say google.com or bbc.com
for 2 and 3, dst and src means destination and source 

#### Combining filters ####

1. `tcpdump -i etho0 -v src 192.168.1.1 and src 192.168.2.1`

#### Scanning the entire network ####

1. `tcpdump -i etho0 -v net 192.168.1.0/24` # specifies the subnet 

