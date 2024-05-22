![img](../../../../../assets/banner.png)

<img src='../../../../../assets/htb.png' style='margin-left: 20px; zoom: 80%;' align=left /> <font size='10'>Bag Secured</font>

8<sup>th</sup> May 2024

Prepared By: ckrielle

Challenge Author(s): ckrielle

Difficulty: <font color=green>Easy</font>

Classification: Official

# Synopsis

- Implement an algorithm to solve the knapsack problem.

## Description

- Now that you've gathered the finest in the land, you need to equip your team. Big men, trouble makers, shotguns, riffles, roasted ants, nuclear soda, some scrapped hacky-boys, a power armor and more are all essential for the job. As you go to the different merchants, you soon start to realize that you're gonna start gathering a lot of stuff. Your team may be strong, but there's a limit to what they can lift. But that musn't sacrifice the quality of products you get. Can you devise a way to get the best products without going over your physical limits?

## Skills Required

- Basic research skills.
- Basic programming skills.
- Basic algorithmic skills.

## Skills Learned

- Capable to implement a solution to the knapsack problem.
- Understanding of combinatorial optimization problems.

# Enumeration

## Connecting to the instance

Since no files are provided for this challenge, let's connect to the instance and see what we get

```
You will be given a number of s = 100 salesmen offering their products. You have a bag with a capacity C, where 1 <= C <= 10 ** 5
For every product bench you will have the below values:
	1. The number of products N, using 1-based indexing (1, 2, ..., N), where 1 <= N <= 100
	2. The capacity C
	3. Every product i will have 2 values, a weight w_i, and a value v_i, where 1 <= w_i <= C, and 1 <= v_i <= 10 ** 10 
Find the maximum value of products you can fit in your bag.

You will receive N and C, then after that the product values w_i and v_i.
Example Input:
	4 14
	6 3
	7 9
	5 4
	2 1

Example Output:
	14
```

We get a big description of the problem we need to solve. It seems to be an optimization problem, asking us to find the best products we can get based on the weight we can carry for every test. If we search a bit online based on the core principles of this problem, we quickly find out it's the knapsack problem.

# Solution

## Solving the knapsack problem

There are some ways to tackle the knapsack problem, a dynamic programming approach and a greedy approach. All we have to do is make sure we get the data from the server correctl, pass them into our knapsack solver function, and then pass that into the server to have our solution

## Exploitation

### Remote connection

Some simple pwntools lines to connect to the instace

```py
if __name__ == '__main__':
    ip = '127.0.0.1'
    port = 1337
    io = remote(ip, port)
    pwn()
```

### Getting the values

We will parse the values based on the specification laid out on the problem statement

```py
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
```

### Knapsack problem solver implementation

Below is a solver for the knapsack problem following the dynamic programming path. One can either find a program online to do this, or write a solver himself

```py
def solve_knapsack(n, c, weights, values):
    dp = [[0 for _ in range(c + 1)] for _ in range(n + 1)]
    for i in range(1, n + 1):
        for w in range(1, c + 1):
            if weights[i-1] <= w:
                dp[i][w] = max(dp[i-1][w], dp[i-1][w-weights[i-1]] + values[i-1])
            else:
                dp[i][w] = dp[i-1][w] 
    return dp[n][c]
```

### Sending the solution to the server

We write a simple small function to send the solution to the server

```py
def send_solution(max_sum):
    io.sendline(f'{max_sum}'.encode())
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
3. Solve the knapsack problem
4. Send the solution
5. Get the flag

```py
def pwn():
    for t in range(100):
        print('Test', t + 1)
        N, C, weights, values = get_values(t)
        max_sum = solve_knapsack(N, C, weights, values)
        send_solution(max_sum)
    flag = get_flag()
    print(flag)
```