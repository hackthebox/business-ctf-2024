from pwn import *


def toAscii(data):
    return data.decode().strip()


def trigger_backdoor():
    r.sendlineafter(b"Input : ", b"1111111111101001")


def pwn():
    trigger_backdoor()
    r.recvuntil(b"flag: ")
    flag = toAscii(r.recvline())
    print(flag)


if __name__ == "__main__":
    if args.REMOTE:
        ip, port = args.HOST.split(":")
        r = remote(ip, int(port))
    else:
        r = process("python3 server.py", cwd="../challenge", shell=True)

    pwn()
