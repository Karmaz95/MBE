# coding: utf-8
# 1. Setting up variables
import z3
solver = z3.Solver()
wanted_length = 8
assert wanted_length > 5 # checked at 0x08048a4f
sym_username = [z3.BitVec('x{i}'.format(i=i), 8) for i in range(wanted_length)]
sym_serial = z3.BitVec('serial', 32)

# 2. Translating preloop
'''
0x08048ab6 8b4508 mov eax, dword [arg_8h]
0x08048ab9 83c003 add eax, 3
0x08048abc 0fb600 movzx eax, byte [eax]
0x08048abf 0fbec0 movsx eax, al
0x08048ac2 3537130000 xor eax, 0x1337
0x08048ac7 05eded5e00 add eax, 0x5eeded
0x08048acc 8945f0 mov dword [local_10h], eax
'''
eax = z3.SignExt(24, sym_username[3]) # (int32_t)*((uint8_t*)arg_8h + 3)
eax ^= z3.BitVecVal(0x1337, 32)
eax += z3.BitVecVal(0x5eeded, 32)
local_10h = eax

# 3. Translating loop header / footer
'''
0x08048acf c745ec000000. mov dword [local_14h], 0
0x08048ad6 eb4e jmp 0x8048b26
...
0x08048b22 8345ec01 add dword [local_14h], 1
0x08048b26 8b45ec mov eax, dword [local_14h]
0x08048b29 3b45f4 cmp eax, dword [local_ch]
0x08048b2c 7caa jl 0x8048ad8
'''
local_ch = len(sym_username) # this is set by the strnlen at 0x08048a3e
for local_14h in range(local_ch):
    pass # we'll translate the loop body here

# 4. Translating the loop body
'''
0x08048ad8 mov edx, dword [local_14h]
0x08048adb mov eax, dword [arg_8h]
0x08048ade add eax, edx
0x08048ae0 movzx eax, byte [eax]
0x08048ae3 cmp al, 0x1f
0x08048ae5 jg 0x8048aee
'''
solver.add(sym_username[local_14h] > 0x1f)
'''
0x08048aee mov edx, dword [local_14h]
0x08048af1 mov eax, dword [arg_8h]
0x08048af4 add eax, edx
0x08048af6 movzx eax, byte [eax]
0x08048af9 movsx eax, al
0x08048afc xor eax, dword [local_10h]
'''
eax = z3.SignExt(24, sym_username[local_14h])
eax ^= local_10h
'''
0x08048aff mov ecx, eax
0x08048b01 mov edx, 0x88233b2b
0x08048b06 mov eax, ecx
'''
ecx = eax
edx = z3.BitVecVal(0x88233b2b, 32)
eax = ecx
'''
0x08048b08 mul edx
'''
mul_result = z3.ZeroExt(32, eax) * z3.ZeroExt(32, edx)
edx = z3.Extract(63, 32, mul_result)
eax = z3.Extract(31, 0, mul_result)
'''
0x08048b0a mov eax, ecx
0x08048b0c sub eax, edx
0x08048b0e shr eax, 1
0x08048b10 add eax, edx
0x08048b12 shr eax, 0xa
'''
eax = ecx
eax -= edx
eax = eax >> 1
eax += edx
eax = eax >> 0xa
'''
0x08048b15 imul eax, eax, 0x539
'''
eax = z3.Extract(31, 0, z3.SignExt(32, eax) * 0x539)
'''
0x08048b1b sub ecx, eax
0x08048b1d mov eax, ecx
0x08048b1f add dword [local_10h], eax
'''
ecx -= eax
eax = ecx
local_10h += eax

# 5. Solving for a valid serial
solver.add(sym_serial == local_10h) # outside the loop
solver.push() # backtracking point for next demo
username = 'karol'
for (x, y) in zip(username, sym_username):
    solver.add(ord(x) == y)
assert solver.check().r == 1
model = solver.model()
serial = model.evaluate(sym_serial)
print('serial for name %r is %r' % (username, serial))
