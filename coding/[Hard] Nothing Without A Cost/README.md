![img](../../../../../assets/banner.png)

<img src='../../../../../assets/htb.png' style='margin-left: 20px; zoom: 80%;' align=left /> <font size='10'>Nothing Without A Cost</font>

8<sup>th</sup> May 2024

Prepared By: ckrielle

Challenge Author(s): ckrielle

Difficulty: <font color=red>Hard</font>

Classification: Official

# Synopsis

- DP with an optimized divide and conquer approach

## Description

- After many perils and challenges, you have finally entered vault 79. Going through the remnants of a place people once dwelled by people, deep inside the vault you lay your eyes upon an unsealed bunker. You move it's entrance, and inside you lay your eyes on the long-sought gold. As you celebrate and rejoice, the door behind you closes, trapping you inside. A screen appears, telling you that you need to give big amounts of gold based on numbers in the screen, or you will be stuck inside forever. After solving so many problems however, and so close to success, you aren't prepared to give away the gold just to escape. You start studying what the screen says, and start to devise a way to keep as much gold as you can. Can you give away the least possible gold, and outsmart the vault?

## Skills Required

- Competent research skills.
- Intermediate programming skills.
- Intermediate to Advanced algorithmic skills.

## Skills Learned

- Understanding how to optimize DP problems.
- Understanding devide and conquer approaches.

# Enumeration

## Connecting to the instance

Since no files are provided for this challenge, let's connect to the instance and see what we get

```
You will be given a number of t = 100 rounds of tests you need to pass. For every test you will be given an array of integers a_1, ..., a_n.
The cost of a subsegment of the array a is defined as the number of distinct pair of indexes in that subsegment whose elements are equal.
Divide the array into k non-overlapping subsegments with at least one element, such that each element of the array a belongs to exactly one subsegment.
For every test you will have the below values:
        1. The number of the array elements n, and the number of subsegments k, where 2 <= n <= 10 ** 5 and 2 <= k <= min(n, 20)
        2. The elements of the array a_1, a_2, ..., a_n, where 1 <= a_i <= n
Find the minimum possible cost of these k subsegments.
```

We get a big description of the problem we need to solve. This one is more abstract than the others, with different terms which need further understanding, like subsegment. However the main thing the problem asks is to find a minimum cost. So we can rely on a dynamic programming approach

# Solution

## First attempt: naive dynamic programming approach

A simple first approach is to implement a dynamic programming approach. We will define a `dp[i][j]` array to be the smallest cost of a partition of first j elements into i parts. To find at every step the minimum cost, we calculate `dp[i][j] = min(dp[i-1][k] + cost(k+1,j)) k<j`. However this will be extremely costly. To be more specific, it has a complexity of O(k * n ** 2). So there is definitely room for improvement.

## Optimal solution: optimized divide and conquer approach

First off, the previous idea can be further optimized with a frequency array as we go from k to j. This is because introducing an element into a subsegment increases it's cost by it's frquency. The next level of optimization comes from observing that the optimal split points `p(j)` for dividing the segment ending at `j` are monotonic in `j`. Monotonic is a concept from mathematics, meaning the for every `j1 < j2` it's true that `p(j1) <= p(j2)`. This allows us to perform an optimized divide and conquer approach, similar to the [Chinese DivideConquer (CDP)](https://robert1003.github.io/2020/01/31/cdq-divide-and-conquer.html). From there for each section we will define 4 values, l, r, L, R, the left and right bounds of the subsequence we will be checking. The algorithm will also be recursive, due to the dive and conquer nature of the algorithm. We will define the middle of every layer m = (L + R) / 2, and once we go through them we will define the new layers [l, m - 1] and [m + 1, r]. We will have a global `sum_` array to count the aforementioned frequencies, and `dp[i][j]` will represents the minimum cost of splitting the first j elements into i parts.

For a more detailed approach, view the solution of the original problem statement which inspired this problem [here](https://codeforces.com/blog/entry/55046).

## Exploitation

### Remote connection and initializations

Some simple pwntools lines to connect to the instace, and initialization of global values

```py
if __name__ == '__main__':
        now = 
    a = []
    sum_ = []
    dp = []
    ip = '127.0.0.1'
    port = 1337
    io = remote(ip, port)
    pwn()
```

### Getting the values

We will initially get the values, before we proceed to pass them onto our solver function

```py
def get_values(test_n):
    global a
    io.recvuntil(f'Test {test_n + 1}/100\n'.encode())
    n, k = list(map(int, io.recvline().rstrip().decode().split(' ')))
    a = [0] + list(map(int, io.recvline().rstrip().decode().split(' ')))
    return n, k
```

### Solving the divide and conquer dp problem

We impleement our solution to the problem, and get the solution from the last element of dp

```py
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
```

### Sending the solution to the server

We write a simple small function to send the solution to the server

```py
def send_solution(min_gold):
    io.sendline(f'{min_gold}'.encode())
```

### Getting the flag

A function that recieves the flag when we pass all the tests

```py
def get_flag():
    io.recvuntil(b'HTB{')
    return b'HTB{' + io.recvline().rstrip()
```

In summary:
1. Open a connection to the remote instance
2. Get the values
3. Find the minimum gold we need to give
4. Send the solutions
5. Get the flag

```py
def pwn():
    for t in range(100):
        print('Test', t + 1)
        n, nodes, m, queries = get_values(t)
        final_nodes = find_final_nodes(n, nodes, queries)
        send_solution(final_nodes)
    flag = get_flag()
    print(flag)
```