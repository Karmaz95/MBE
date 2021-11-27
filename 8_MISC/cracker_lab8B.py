# -*- coding: utf-8 -*-

# Security
'''
CANARY    : ENABLED
FORTIFY   : disabled
NX        : ENABLED
PIE       : ENABLED
RELRO     : FULL
'''

# Vulnerable code 1:
'''
memcpy(v, faves[i], sizeof(v));
''' # So loadFave() will overwrite first 4B of the vector strucure which is pointer to printFunc() - EIP control if dword can be controlled

# Vulnerable code 2:
'''
faves[i] = malloc(sizeof(struct vector));
memcpy(faves[i], (int*)(&v3)+i, sizeof(struct vector));
''' # To control above overwrite save (v3) sum - 4 times and set v3->d => to EIP.

