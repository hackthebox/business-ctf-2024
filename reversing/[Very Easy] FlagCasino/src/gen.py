#!/usr/bin/env python3

import ctypes

libc = ctypes.CDLL('libc.so.6')
flag = "HTB{r4nd_1s_v3ry_pr3d1ct4bl3}"
check = []

for c in flag:
    libc.srand(ord(c))
    check.append(libc.rand())

with open('flag.inc', 'w') as f:
    f.write("int check[] = {");
    f.write(', '.join(str(i) for i in check))
    f.write('};\n')
