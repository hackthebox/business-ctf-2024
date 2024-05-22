![img](../../../../../assets/banner.png)

<img src='../../../../../assets/htb.png' style='margin-left: 20px; zoom: 80%;' align=left /> <font size='10'>Dynamic Paths</font>

8<sup>th</sup> May 2024

Prepared By: ckrielle

Challenge Author(s): ckrielle

Difficulty: <font color=green>Easy</font>

Classification: Official

# Synopsis

- Implement a dynamic programming algorithm to solve the minimum path sum problem.

## Description

- On your way to the vault, you decide to follow the underground tunnels, a vast and complicated network of paths used by early humans before the great war. From your previous hack, you already have a map of the tunnels, along with information like distances between sections of the tunnels. While you were studying it to figure your path, a wild super mutant behemoth came behind you and started attacking. Without a second thought, you run into the tunnel, but the behemoth came running inside as well. Can you use your extensive knowledge of the underground tunnels to reach your destination fast and outrun the behemoth?

## Skills Required

- Basic research skills.
- Basic programming skills.
- Basic algorithmic skills.

## Skills Learned

- Understanding of dynamic programming.

# Enumeration

## Connecting to the instance

Since no files are provided for this challenge, let's connect to the instance and see what we get

```
You will be given a number of t = 100 grids for the different regions you need to pass. For every map you will have the below values:
	1. The dimensions i x j of the map grid where 2 <= i, j <= 100
	2. The numbers n_i,j symbolizing the distances between the blocks where 1 <= n_i,j <= 50
You will start at the top left element, and your goal is to reach the bottom right, while only being allowed to move down or right, minimizing the sum of the numbers you pass. Provide the minimum sum.

Example Question:
	4 3
	2 5 1 9 2 3 9 1 3 11 7 4

This generates the following grid:
	 2 5 1
	 9 2 3
	 9 1 3
	11 7 4

Example Response:
	17
(Optimal route is 2 -> 5 -> 2 -> 1 -> 3 -> 4)
```

We get a big description of the problem we need to solve. It seems to be an optimization problem, asking us to find the best path to take for every test.

## Considering our approaches

A first thought would be to consider a greedy approach, everytime following the minimum value. However that could lead to a problem if we face two big values which could ahve been avoided if we had previously taken a bigger value that led down a smaller sum path. Another approach that exists in competitive programming problems is dynamic programming, or dp for short. DP is often used for problems that:
1. Count something (e.g. the number of ways to d something)
2. Minimize or maximize certain values
3. Answer a Yes/No question
We are clearly in the second case, so we can use dp as an approach

## A quick overview of dynamic programming

DP is used to solve complex puzzles by breaking them down into smaller subproblems, a divide and conquer approach. DP helps us calculate the values of a problem, store them, and provides a way to easily access them when they are needed again. This way, we don't lose computational time recalculating different values. A good example of this is the fibonacci sequence. For example fib(5) = fib(4) + fib(3) = (fib(3) + fib(2)) + fib(3). As we can see, fib(3) will be calculated two times, and the same with all the other values that emerge. So dp helps us avoid all these extra computations, making the problem solving process more optimal. A great overview of dp and some of it's standard problems is provided by errichto in [this](https://www.youtube.com/watch?v=YBSt1jYwVfU&list=PLl0KD3g-oDOEbtmoKT5UWZ-0_JbyLnHPZ&ab_channel=ErrichtoAlgorithms) video

# Solution

## Solving the minimum sum path problem

The problem described is the minimum path sum problem. To solve it using dp, we will model each cell of the grid as a subproblem whose solution is the minimum path sum to reach that cell from the starting cell. This way we can slowly start going through every cell, and thus build a structure that can help us find the optimal path when it's time to compute the sums of the entire grid. 

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

We will initially get the values, before we proceed to format the grid to a proper state

```py
def get_values(test_n):
    io.recvuntil(f'Test {test_n + 1}/100\n'.encode())
    dimension = io.recvline().rstrip().decode()
    grid = io.recvline().rstrip().decode()
    return dimension, grid
```

### Format the grid

We will create a 2D matrix from the dimensions and the 1D grid for much more intuitive computation of the solution later on

```py
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
```

### Solve the minimum path sum problem

Below is a solver for the minimum path sum problem following the dynamic programming approach. It finds both the minimum sum and the path as requests

```py
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
```

### Sending the solution to the server

We write a simple small function to send the solution to the server

```py
def send_solution(min_sum, min_path):
    io.sendline(f'{min_sum}'.encode())
    io.sendline(min_path.encode())
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
2. Format them
3. Solve the minimum sum path problem
4. Send the solution
5. Get the flag

```py
def pwn():
    for t in range(100):
        print('Test', t + 1)
        dimensions, grid = get_values(t)
        grid = format_grid(dimensions, grid)
        min_path_sum, min_sum = find_min_path_sum(grid)
        send_solution(min_path_sum, min_sum)
    flag = get_flag()
    print(flag)
```