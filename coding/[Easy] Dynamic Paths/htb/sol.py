from pwn import *

def get_values(test_n):
    io.recvuntil(f'Test {test_n + 1}/100\n'.encode())
    dimension = io.recvline().rstrip().decode()
    grid = io.recvline().rstrip().decode()
    return dimension, grid

def format_grid(dimensions, grid):
    i, j = [int(d) for d in dimensions.split(' ')]
    grid = [int(g) for g in grid.split(' ')]
    ngrid = []
    for _i in range(i):
        row = []
        for _j in range(j):
            row.append(grid[_i * j + _j])
        ngrid.append(row)
    return ngrid

def find_min_path_sum(grid):
    if not grid:
        return 0, []
    
    rows, cols = len(grid), len(grid[0])
    
    dp = [[0] * cols for _ in range(rows)]
    dp[0][0] = grid[0][0]
    
    path = [[''] * cols for _ in range(rows)]
    path[0][0] = str(grid[0][0])

    for j in range(1, cols):
        dp[0][j] = dp[0][j-1] + grid[0][j]
        path[0][j] = path[0][j-1] + ' ' + str(grid[0][j])
    
    for i in range(1, rows):
        dp[i][0] = dp[i-1][0] + grid[i][0]
        path[i][0] = path[i-1][0] + ' ' + str(grid[i][0])

    for i in range(1, rows):
        for j in range(1, cols):
            if dp[i-1][j] < dp[i][j-1]:
                dp[i][j] = dp[i-1][j] + grid[i][j]
                path[i][j] = path[i-1][j] + ' ' + str(grid[i][j])
            else:
                dp[i][j] = dp[i][j-1] + grid[i][j]
                path[i][j] = path[i][j-1] + ' ' + str(grid[i][j])
    
    min_path_sum = dp[rows-1][cols-1]
    min_path = path[rows-1][cols-1]

    return min_path_sum, min_path

def send_solution(min_sum, min_path):
    io.sendlineafter(b'> ', f'{min_sum}'.encode())

def get_flag():
    io.recvuntil(b'HTB{')
    return b'HTB{' + io.recvline().rstrip()

def pwn():
    for t in range(100):
        print('Test', t + 1)
        dimensions, grid = get_values(t)
        grid = format_grid(dimensions, grid)
        min_path_sum, min_sum = find_min_path_sum(grid)
        send_solution(min_path_sum, min_sum)
    flag = get_flag()
    print(flag)

if __name__ == '__main__':
    ip = '127.0.0.1'
    port = 1337
    io = remote(ip, port)
    #io = process(['python', 'server.py'])
    pwn()