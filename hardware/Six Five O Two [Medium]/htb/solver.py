from pwn import *
import os

assembly = """
        code
        org $8000

        ldx #$00
LOOP    lda $4000,x
        sta $6000,x
        inx
        cmp #$20
        bne LOOP


        org $fffc
        dw $8000
        dw $ffff
"""


def assembler():
    with open("solver.a65", "w") as f:
        f.write(assembly)

    os.system("./as65  -l -m -w -h0 solver.a65 -osolver.rom")

    with open("solver.rom", "rb") as f:
        bytecode = f.read().hex()
    return bytecode


def toAscii(data):
    return data.decode().strip()


def flash_rom(bytecode):
    r.sendlineafter(b"READY.", b"FLASH " + bytecode.encode())


def run_cpu(steps):
    r.sendlineafter(b"READY.", b"RUN " + str(steps).encode())


def print_console():
    r.sendlineafter(b"READY.", b"CONSOLE")


def parse_flag():
    r.recvuntil(b"\x1b[94m")
    first = toAscii(r.recvline())
    second = toAscii(r.recvuntil(b"\x1b[0m")[1:-4])
    flag = first + " " + second
    flag = "".join([bytes.fromhex(byte).decode() for byte in flag.split(" ")])
    return flag


def pwn():
    r.recvuntil(b"READY.")
    bytecode = assembler()
    flash_rom(bytecode)
    run_cpu(160)
    print_console()
    flag = parse_flag()
    print(flag)


if __name__ == "__main__":
    if args.REMOTE:
        ip, port = args.HOST.split(":")
        r = remote(ip, int(port))
    else:
        r = process("python3 ../challenge/server.py", shell=True)

    pwn()
