#!/usr/bin/env python3

from pwn import *

MAZE_SIZE = 20
CELL_SIZE = 0x10

e = ELF("./tunnel", checksec=False)
def read_cell(addr):
    data = e.read(addr, CELL_SIZE)
    return struct.unpack("IIII", data)

def read_coord(coord):
    x, y, z = coord
    addr = e.sym["maze"] + (x * MAZE_SIZE * MAZE_SIZE * CELL_SIZE) + (y * MAZE_SIZE * CELL_SIZE) + (z * CELL_SIZE)
    return read_cell(addr)

START = 0
OPEN = 1
CLOSED = 2
FINISH = 3

def get_adj(pos):
    x, y, z = pos
    options = []
    if not x - 1 < 0: options.append((x-1, y, z))
    if not x + 1 >= MAZE_SIZE: options.append((x+1, y, z))
    if not y - 1 < 0: options.append((x, y-1, z))
    if not y + 1 >= MAZE_SIZE: options.append((x, y+1, z))
    if not z - 1 < 0: options.append((x, y, z-1))
    if not z + 1 >= MAZE_SIZE: options.append((x, y, z+1))
    return options

def solve():
    pos = (0, 0, 0)
    visited = []
    while True:
        for adj in get_adj(pos):
            if adj in visited: continue
            _, _, _, typ = read_coord(adj)
            if typ == OPEN:
                visited.append(pos)
                pos = adj
                break
            elif typ == FINISH:
                return visited + [pos, adj]
        else:
            print(f"failed at {pos}")

path = solve()
solution = ""
for i in range(1, len(path)):
    prev = path[i-1]
    cur = path[i]
    if cur[0] > prev[0]:
        solution += "R"
    elif cur[0] < prev[0]:
        solution += "L"
    elif cur[1] > prev[1]:
        solution += "F"
    elif cur[1] < prev[1]:
        solution += "B"
    elif cur[2] > prev[2]:
        solution += "U"
    elif cur[2] < prev[2]:
        solution += "D"
print(solution)
r = remote(args.HOST or "localhost", args.PORT or 1337)
for c in solution:
    r.sendlineafter(b"? ", c.encode())
print(r.recvlines(2)[1].decode())
