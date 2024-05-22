from pwn import *
import re

def get_candidates():
    candidates = []
    with open('../challenge/data.txt', 'r') as f:
        lines = f.readlines()
        for line in lines:
            match = re.search(pattern, line)
            if match:
                candidates.append(match.groups())
    return candidates

def calculate_values(candidates):
    data = []
    for candidate in candidates:
        first_name, last_name, h_skill, a_skill, c_skill, k_skill, e_skill, r_skill = candidate
        name = first_name + ' ' + last_name
        health          = round(6 * (int(h_skill) * 0.2))  + 10
        agility         = round(6 * (int(a_skill) * 0.3))  + 10
        charisma        = round(6 * (int(c_skill) * 0.1))  + 10
        knowledge       = round(6 * (int(k_skill) * 0.05)) + 10
        energy          = round(6 * (int(e_skill) * 0.05)) + 10
        resourcefulness = round(6 * (int(r_skill) * 0.3))  + 10
        value = round(5 * ((health * 0.18) + (agility * 0.20) + (charisma * 0.21) + (knowledge * 0.08) + (energy * 0.17) + (resourcefulness * 0.16)))
        data.append([name, value])
    return data

def sort_players(data):
    data = sorted(data, key=lambda l:l[1], reverse=True)
    out = ''
    for recruit in data[:13]:
        out += f'{recruit[0]} - {recruit[1]}, '
    out += f'{data[13][0]} - {data[13][1]}'
    return out

def get_flag(sol_str):
    io.recvuntil(b'> ')
    io.sendline(sol_str.encode())
    io.recvuntil(b'HTB{')
    return b'HTB{' + io.recvline().rstrip()

def pwn():
    flag = get_flag(sort_players(calculate_values(get_candidates())))
    print(flag)

if __name__ == '__main__':
    pattern = r"^\s*([A-Za-z]+)\s+([A-Za-z]+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$"
    ip = '127.0.0.1'
    port = 1337
    io = remote(ip, port)
    #io = process(['python', 'server.py'])
    pwn()
