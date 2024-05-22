from pwn import *

with open("solver.js") as f:
    exploit = f.read()

p = remote('127.0.0.1', 1337)

p.sendlineafter(b'30001 bytes): ', str(len(exploit)).encode())
p.sendlineafter(b'Script:\n', exploit.encode())

p.recvuntil(b'Stdout:\n')
print(p.clean(4))
