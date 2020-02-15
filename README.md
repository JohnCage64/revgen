# revgen
oneline reverse shell generator

very simple use and validation of IP, PORT and TYPE of reverse shell. 
---------------------------------------------------------------------
Added -i switch for setup ip of local interface  
Added -p switch for setting port number  
Added -b switch for output in base64 (works only with -w,-i,-p together sequence doesent matter)
Added -l switch for aut change IP to LongIP format  


Now You can just type $./revgen.py -i tun0 -p 1337 -w bash !
---
 ./revgen.py -i tun0 -p 1337 -w bash -b  / for base64 instant output
---
 ./revgen.py -i tun0 -p 1337 -w bash [-b] -l  / auto change ip to longIP format
---

example usage:  
./revgen.py -i tun0 -w bash -p 1337  (without questions)  
./revgen.py -i tun0 -w bash -p 1337 -b (Without question and output in base64)
./revgen.py -i tun0 (You will be ask for PORT and TYPE)  
.revgen.py -i tun0 -w bash (You will be ask for PORT)  
./revgen.py -w bash (You will be ask for IP and PORT)  
./revgen.py -ip 10.10.10.10:123 (You will be ask for TYPE)  
./revgen.py -ip 10.10.10.12: (You will be ask for PORT and TYPE)  
./revgen.py -ip 10.10.10.12  (You will be ask for PORT and TYPE)  
./revgen.py (You will be ask for IP, PORT and TYPE)  
and so on..

TYPE:
'all','bash','python','mk','java','perl','echo','php','ruby','nc','mknod','lua','xterm','socat','awk','nodejs','psh','tclsh','telnet'
---
