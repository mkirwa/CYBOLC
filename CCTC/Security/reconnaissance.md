### Host Discovery ####

Determine if hosts exists on the network using quick port agnostic scans.

Ping Sweep
Sends one icmp echo request packet to each host on the 192.168.1.0/24

Linux: `for i in {1..254} ;do (ping -c 1 192.168.1.$i | grep "bytes from" &) ;done`

Windows: `for /L %i in (1,1,255) do @ping -n 1 -w 200 192.168.1.%i > nul && echo 192.168.1.%i is up.`

### Port Enumeration ###

Determine what ports on a target machine are available to be communicated with. *These ports indicate which services are potentially listening on a target machine and are not blocked by a network or host security appliance.

Use nmap to scan a range and specific ports on a discovered machine:

`nmap -sS -Pn 8.8.8.8 -p 135-139,22,80,443,21,8080`

    NOTE: Nmap requires the -Pn switch to be run over Proxychains. It requires this switch because proxychains does not support ICMP traffic. Nmap pings each target first before attempting to enumerate selected ports.

Use nc to scan a range and specific ports on a discovered machine:

`nc -z -v -w 1 8.8.8.8 440-443`

    NOTE: nc does not ping an IP Address before enumerating the ports; therefore, it works great over proxychains.

### Port Interrogation ###

Interact with discovered hosts and ports to determine the best way to leverage each available service.

Use nc to interrogate a web server:

`nc -Cv 127.0.0.1 80`

Type: `GET / HTTP/1.0` to get a HTTP Response header from the server.

Use nmap to perform service detection on port 22 of your opstation:

`nmap -sV 127.0.0.1 -p 22`

Using nikto to perform a vulnerability scan on your opstation:

`nikto -h 127.0.0.1 -p 80`

Also shows other information like what HTTP methods are allowed and various CVE vulnerabilities.