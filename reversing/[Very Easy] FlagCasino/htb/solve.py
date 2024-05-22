#!/usr/bin/env python3

import ctypes

libc = ctypes.CDLL('libc.so.6')

mapping = {}
for i in range(255):
    libc.srand(i)
    mapping[libc.rand()] = chr(i)

flag = ""
from pwn import *
e = ELF("./casino", checksec=False)
for j in range(29):
    val = e.u32(e.sym["check"] + j * 4)
    flag += mapping[val]

print(flag)