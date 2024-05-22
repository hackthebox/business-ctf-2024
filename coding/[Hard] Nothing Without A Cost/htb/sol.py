from pwn import *

def get_values(test_n):
    global a
    io.recvuntil(f'Test {test_n + 1}/100\n'.encode())
    n, k = list(map(int, io.recvline().rstrip().decode().split(' ')))
    a = [0] + list(map(int, io.recvline().rstrip().decode().split(' ')))
    return n, k

def divide_and_conquer(l, r, L, R, val):
    global now, a, sum_, dp
    if l > r:
        return
    
    m = (l + r) // 2
    i = l
    while i <= m:
        val += sum_[a[i]]
        sum_[a[i]] += 1
        i += 1
    
    x = 0
    i = L
    while i <= R and i <= m:
        sum_[a[i]] -= 1
        val -= sum_[a[i]]
        if val + dp[now-1][i] < dp[now][m]:
            x = i
            dp[now][m] = val + dp[now-1][i]
        i += 1
    
    i = L
    while i <= R and i <= m:
        val += sum_[a[i]]
        sum_[a[i]] += 1
        i += 1
    
    i = l
    while i <= m:
        sum_[a[i]] -= 1
        val -= sum_[a[i]]
        i += 1
    
    divide_and_conquer(l, m-1, L, x, val)
    
    i = l
    while i <= m:
        val += sum_[a[i]]
        sum_[a[i]] += 1
        i += 1
    
    i = L
    while i < x:
        sum_[a[i]] -= 1
        val -= sum_[a[i]]
        i += 1
    
    divide_and_conquer(m+1, r, x, R, val)
    
    i = L
    while i < x:
        sum_[a[i]] += 1
        i += 1
    
    i = l
    while i <= m:
        sum_[a[i]] -= 1
        i += 1

def find_minimum_gold(n, k):
    global now, a, sum_, dp

    large_value = float('inf')
    dp = [[large_value] * (n + 1) for _ in range(k + 1)]
    dp[1][0] = 0
    sum_ = [0] * (100005)
    
    for i in range(1, n + 1):
        dp[1][i] = dp[1][i-1] + sum_[a[i]]
        sum_[a[i]] += 1
    
    for i in range(2, k + 1):
        now = i
        sum_ = [0] * (100005)
        divide_and_conquer(i-1, n, i-1, n, 0)
    
    return dp[k][n]

def send_solution(min_gold):
    io.sendline(f'{min_gold}'.encode())

def get_flag():
    io.recvuntil(b'HTB{')
    return b'HTB{' + io.recvline().rstrip()

def pwn():
    for t in range(100):
        print('Test', t + 1)
        n, k = get_values(t)
        min_gold = find_minimum_gold(n, k)
        print(min_gold)
        send_solution(min_gold)
    flag = get_flag()
    print(flag)

if __name__ == '__main__':
    now = 0
    a = []
    sum_ = []
    dp = []
    ip = '127.0.0.1'
    port = 1337
    io = remote(ip, port)
    #io = process(['python', 'server.py'])
    pwn()