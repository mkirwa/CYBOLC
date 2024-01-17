
## OPERATION: DRY RUN ##

SITREP: This is a dry run operation to prepare you for tomorrow's real operation. You will be provided with a mission task sheet, RoE, and scope.

Maintain 'low visibility' on the wire, as security products may be in place, and document your actions and results as you will be expected to provide OpNotes at the end of the operation.

Take notes on this document.

Dry Run Operation
XX June 2024
Start Time: 0830
Duration: 3 hours

Type of Operation: Information Systems Penetration Test

Objective:Actively exploit and attack networked information systems for the purposes of identifying and reporting vulnerabilities.

Tasking:Perform all tasks outlined in this document.

Mission Scope:

All public facing systems of target entitiy excluding devices responsible for networking (routers, switches, etc). Known web address will be supplied out of band.

Internal network of target entity excluding devices responsible for networking (routers, switches, etc)


RoE:

Google docs, and all other shareable document platforms, are forbidden during this operation.

All communication platforms and applications, such as Slack or Gmail, are forbidden during this operation.

You are authorized to modify passwords to user accounts.

Writing to disk is authorized on all machines.

You will not destroy data/systems, perform DoS, or otherwise disrupt business operations of any entity during this penetration test.

You will not use Metasploit tools for any affect with the exception of shellcode generation.

You will not target routers, switches or other networking devices.

You will not target entities or systems outside of the scope previously defined.

You will not interfere with other entities' operations in any way.

Prior Approvals: OSINT through publicly available resources. Scrape appropriate web content that will provide operational data. Testing of found credentials. NOT approved to change routing or destroy data.

Data is only encoded into base64

10.50 assigned. -> 10.50.29.144 (public facing) 

Step 1. student@lin-ops:~$ `nmap 10.50.29.144`

    Starting Nmap 7.60 ( https://nmap.org ) at 2024-01-17 13:51 UTC
    Nmap scan report for 10.50.29.144
    Host is up (0.0043s latency).
    Not shown: 998 filtered ports
    PORT   STATE SERVICE
    22/tcp open  ssh
    80/tcp open  http

    Nmap done: 1 IP address (1 host up) scanned in 4.84 seconds

Step 2: student@lin-ops:~$ `nmap -Pn -sT 10.50.29.144 -p 80 --script http-enum.nse`

    Starting Nmap 7.60 ( https://nmap.org ) at 2024-01-17 13:54 UTC
    Nmap scan report for 10.50.29.144
    Host is up (0.013s latency).

    PORT   STATE SERVICE
    80/tcp open  http
    | http-enum: 
    |   /login.php: Possible admin folder
    |   /login.html: Possible admin folder
    |   /img/: Potentially interesting directory w/ listing on 'apache/2.4.29 (ubuntu)'
    |_  /scripts/: Potentially interesting directory w/ listing on 'apache/2.4.29 (ubuntu)'

    Nmap done: 1 IP address (1 host up) scanned in 0.52 seconds


Step 3. Open reminna and login to your linops and open firefox on there. Enter the ip address 10.50.29.144 and see what's on there.... 


Step 4. Che




