## TUNNELING ACTIVITY 1 ##

![Alt Text](tunnel1.png)

##### Going from Internet Host to Host A and creating a dynamic tunnel on the fly #####

`ssh hostA@10.50.30.99 -p 22 -D 9050`

run proxychain scans and identified Host B with ip 192.168.1.39 sshd 22

##### Create a local tunnel to host B from A #####

`ssh hostA@10.50.30.99 -p 22 (or remove it and as it defaults to 22) -L 1111:192.168.1.39:22`

kill dynamic tunnel, `kill -9 #PID_NO`

##### Create a dynamic tunnel to host B from the Internet Host #####

`ssh hostB@localhost -p 1111 -D 9050`

run proxychain scans and identified host C 10.0.0.50 with port 22

##### Create a local tunnel to host C from B #####

`ssh hostB@localhost -p 1111 (or remove it and as it defaults to 22) -L 2222:10.0.0.50:22`

kill dynamic tunnel, `kill -9 #PID_NO`

##### Create a dynamic tunnel to host C from the Internet Host #####

`ssh hostC@localhost -p 2222 -D 9050`

run proxychain scans and identified host D 172.16.1.8 with port 22

##### Create a local tunnel to host D from C #####

`ssh hostC@localhost -p 2222 (or remove it and as it defaults to 22) -L 3333:172.16.1.8:22`

##### Create a dynamic tunnel to host D from the Internet Host #####

`ssh hostD@localhost -p 3333 -D 9050`

## TUNNELING ACTIVITY 2 ##

![Alt Text](tunnel2.png)

##### Telnet to Host A #####

`telnet hostA@10.50.23.19`

##### Create a Reverse tunnel to host the internet host from A #####

`ssh internet_host@10.50.23.21 -p 22 -R 1111:localhost:22`

##### Create a dynamic tunnel to host A from the Internet Host #####

`ssh hostA@localhost -p 1111 -D 9050`

run proxychain scans and identified Host B with ip 10.1.2.18 sshd 2222

##### Create A local tunnel to B from A #####

`ssh hostA@localhost -p 1111 -L 4444:10.1.2.18:2222`

kill dynamic tunnel, `kill -9 #PID_NO`

##### Create a dynamic tunnel to host B from the Internet Host #####

`ssh hostB@localhost -p 4444 -D 9050`

run proxychain scans and identified Host C with ip 172.16.10.121 sshd 2323

##### Create A local tunnel to C from B #####

`ssh hostB@localhost -p 4444 -L 5555:172.16.10.121:2323`

kill dynamic tunnel, `kill -9 #PID_NO`

`ssh hostC@localhost -p 5555 -D 9050`

run proxychain scans and identified Host D with ip 192.168.10.69 sshd 22

##### Create A local tunnel to D from C #####

`ssh hostC@localhost -p 5555 -L 6666:192.168.10.69:22`

`ssh hostD@localhost -p 6666 -D 9050`

kill dynamic tunnel, `kill -9 #PID_NO`
