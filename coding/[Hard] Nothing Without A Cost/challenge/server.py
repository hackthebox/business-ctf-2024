import random

def banner():
    print("You will be given a number of t = 100 rounds of tests you need to pass. For every test you will be given an array of integers a_1, ..., a_n.")
    print("The cost of a subsegment of the array a is defined as the number of distinct pair of indexes in that subsegment whose elements are equal.")
    print("Divide the array into k non-overlapping subsegments with at least one element, such that each element of the array a belongs to exactly one subsegment.")
    print("For every test you will have the below values:")
    print("\t1. The number of the array elements n, and the number of subsegments k, where 2 <= n <= 10 ** 5 and 2 <= k <= min(n, 20)")
    print("\t2. The elements of the array a_1, a_2, ..., a_n, where 1 <= a_i <= n")
    print("Find the minimum possible cost of these k subsegments.")
    print()
    print("Example Input 1:")
    print("\t2 2")
    print("\t1 2")
    print()
    print("Example Output 1:")
    print("\t0")
    print()
    print("Example Input 2:")
    print("\t8 3")
    print("\t1 2 1 2 1 2 1 2")
    print()
    print("Example Output 2:")
    print("\t2")
    print()
    print("Example Input 3:")
    print("\t15 2")
    print("\t1 2 3 1 2 3 1 2 3 1 2 3 1 2 3")
    print()
    print("Example Output 3:")
    print("\t12")

def generate_test(n_bound, k_bound):
    global a
    n = random.randint(2, n_bound)
    k = random.randint(2, min(n, k_bound))
    a = [random.randint(1, n) for _ in range(n)]
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
    a = [0] + a

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

def main():
    global a
    banner()
    f = 1
    for t in range(100):
        print()
        print(f'Test {t+1}/100')
        if 0 <= t <= 5:
            n_limit = 5
            k_limit = 2
        elif 5 < t <= 20:
            n_limit = 10 ** 1
            k_limit = 5
        elif 20 < t <= 40:
            n_limit = 10 ** 2
            k_limit = 8
        elif 40 < t <= 60:
            n_limit = 10 ** 3
            k_limit = 12
        elif 60 < t <= 80:
            n_limit = 10 ** 4
            k_limit = 15
        else:
            n_limit = 10 ** 5
            k_limit = 20
        n, k = generate_test(n_limit, k_limit)
        print(n, k)
        out = ''
        for i in a[:-1]:
            out += f'{i} '
        out += str(a[-1])
        print(out)
        minimum_gold_server = find_minimum_gold(n, k)
        minimum_gold_client = int(input())
        if minimum_gold_server != minimum_gold_client:
            f = 0
            break
    if f:
        flag = open('/flag.txt', 'r').read()
        print(f'You managed to open the gate, and have left with the maxium possible gold. Now go to the outside and help humanity prosper. Here is your reward: {flag}')
    else:
        print('You have failed the test. You will remain forever locked in the vault...')

if __name__ == '__main__':
    now = 0
    a = []
    sum_ = []
    dp = []
    main()