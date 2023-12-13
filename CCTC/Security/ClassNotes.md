### LOGIN INFO ###
Please log into Lins-ops
find IPs on vta.cybbh.space

class info: 10.50.46.45/classinfo.html
Keep this output in your notes, password for pivot/-jump box and CTFd, 10.50 is your Jump box for challenges

CTFd: 10.50.20.250:8000

ssh into my workstation -> ssh -X student@10.50.39.223

JUMP_BOX!!!
username: MAKI-502-B
password: d07PevVUniUxBNR
Stack Number: 16
lin.internet: 10.50.49.22

VTA_creds: https://vta.cybbh.space/horizon/project/
Username: mahlon.k.kirwa80
password: regular linux password
Domain: ipa

Jump box:
cctc.cybb

Link slides and what not - https://sec.cybbh.io/public/security/latest/index.html

Instances - https://vta.cybbh.space/horizon/project/instances/

## SECURITY MODULES ##

LESSONS:
1. Penetration testing
2. Reconnaissance
3. Exploit Research
4. Web Exploitation - Day 1
5. Web Exploitation - Day 2
6. Reverse Engineering
7. Exploit Development Testing
8. Post Exploitation
9. Windows Exploitation
10. Linux Exploitation

### PENETRATION TESTING ###

Phases:
1. Phase 1 - Mission definition
2. Phase 2 - Recon
3. Phase 3 - Footprinting
4. Phase 4 - Exploitation and Initial Access
5. Phase 5 - Post Exploitation
6. Phase 6 - Document Mission

for i in {1..254} ;do (ping -c 1 192.168.1.$i | grep "bytes from" &) ;done # Does the first 1000 scans. For the ping sweep... 

Always run the regular scans like above before you try banner grabbing (a technique used to gain information about a computer on a network and the services running on its open ports.)

storage nmap scripts -> ls /usr/share/nmap/scripts/
Popular scripts: ftp-anon.nse, http-enum.nse, smb-os-discovery.nse

How to get information about a certain script -> proxychains nmap [target_ip_address]-Pn -p [target_port] --script-help [target_script]
                                                             nmap ip 192.168.28.97-100, 100,105,111,120 -pm
