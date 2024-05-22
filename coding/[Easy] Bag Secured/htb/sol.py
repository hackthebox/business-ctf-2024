from pwn import *

def get_values(test_n):
    io.recvuntil(f'Test {test_n + 1}/100\n'.encode())
    N = int(io.recvuntil(b' ').decode())
    C = int(io.recvline().rstrip().decode())
    weights = []
    values = []
    for _ in range(N):
        product = io.recvline().rstrip().decode().split(' ')
        weights.append(int(product[0]))
        values.append(int(product[1]))
    return N, C, weights, values

def solve_knapsack(n, c, weights, values):
    dp = [[0 for _ in range(c + 1)] for _ in range(n + 1)]
    
    for i in range(1, n + 1):
        for w in range(1, c + 1):
            if weights[i-1] <= w:
                dp[i][w] = max(dp[i-1][w], dp[i-1][w-weights[i-1]] + values[i-1])
            else:
                dp[i][w] = dp[i-1][w]
    
    return dp[n][c]

def send_solution(max_sum):
    io.sendline(f'{max_sum}'.encode())

def get_flag():
    io.recvuntil(b'HTB{')
    return b'HTB{' + io.recvline().rstrip()

def pwn():
    for t in range(100):
        print('Test', t + 1)
        N, C, weights, values = get_values(t)
        max_sum = solve_knapsack(N, C, weights, values)
        send_solution(max_sum)
    flag = get_flag()
    print(flag)

if __name__ == '__main__':
    ip = '127.0.0.1'
    port = 1337
    io = remote(ip, port)
    #io = process(['python', 'server.py'])
    pwn()