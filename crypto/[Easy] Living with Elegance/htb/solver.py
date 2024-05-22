from pwn import process, remote, args
from Crypto.Util.number import long_to_bytes
import sys

n = 256

def receive_ciphertext(bit):
    global io
    io.sendlineafter(b' : ', str(bit).encode())
    io.recvline()
    A = int(io.recvline().decode().split(' = ')[1])
    b = int(io.recvline().decode().split(' = ')[1])
    return A, b

def get_flag():
    flag_bits = ''
    flag = ''
    current_idx = 0

    io.sendlineafter(b' : ', str(100000).encode())
    flag_bit_len = int(io.recvline().decode().strip().split(', ')[1][:-1])

    while True:
        for _ in range(25):
            A, b = receive_ciphertext(current_idx)
            if b < 0 or b >= n:
                flag_bits += '1'
                break
        else:
            flag_bits += '0'

        current_idx += 1
        
        if current_idx % 8 == 0:
            flag += chr(int(flag_bits[-8:-1], 2))
            print(flag)

        if current_idx > flag_bit_len:
            flag += '}'
            break

    return flag

if __name__ == '__main__':
    global io
    if args.REMOTE:
        host_port = sys.argv[1].split(':')
        HOST = host_port[0]
        PORT = host_port[1]
        io = remote(HOST, PORT, level='error')
    else:
        io = process(['python3', '../challenge/server.py'], level='error')
    
    flag = get_flag()
    print(flag)