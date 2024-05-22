from pwn import *
from hashlib import sha256

def my_keyed_SHA(key, input):
    out = sha256(key + input).digest()
    return out

def my_hash(key, input):
    return my_keyed_SHA(my_keyed_SHA(key, b"Improving on the security of SHA is easy"), input) + my_keyed_SHA(key, input)

def get_fixed_key():
    global conn
    msg = b"Improving on the security of SHA is easy"
    conn.recvline()
    my_balance = 100
    appeared = []
    for i in range(10):
        my_balance -= 10
        conn.recvuntil(b"Option: ")
        conn.sendline(b"2")
        conn.recvuntil(b"hex :: ")
        conn.sendline(msg.hex().encode())
        potential_hash = conn.recvline().decode().split()[-1]
        appeared.append(potential_hash)
        if appeared.count(appeared[-1]) > 1:
            H_k_msg = bytes.fromhex(appeared[-1][64:])
            return H_k_msg, my_balance

def check_output(out, inp, H_k_msg):
    if out[:64] == my_keyed_SHA(H_k_msg, bytes.fromhex(inp)).hex():
        return True
    return False

def win_game(H_k_msg, my_balance):
    global conn

    while my_balance < 500:
        conn.recvuntil(b"Option: ")
        conn.sendline(b"3")
        curr_input = conn.recvline().decode().split()[-1]
        curr_output = conn.recvline().decode().split()[-1]
        conn.recvuntil(b" :: ")
        if check_output(curr_output, curr_input, H_k_msg):
            conn.sendline(b"0")
        else:
            conn.sendline(b"1")
        my_balance += 5
    return

def get_flag():
    global conn
    conn.recvuntil(b"Option: ")
    conn.sendline(b"1")
    flag = conn.recvline()
    conn.close()
    return flag.decode()
    
def pwn():
    H_k_msg, my_balance = get_fixed_key()
    win_game(H_k_msg, my_balance)
    flag = get_flag()
    print(flag)

if __name__ == '__main__':
    global conn
    if args.REMOTE:
        host_port = sys.argv[1].split(':')
        HOST = host_port[0]
        PORT = host_port[1]
        conn = remote(HOST, PORT, level='error')
    else:
        conn = process(['python3', '../challenge/server.py'], level='error')

    pwn()