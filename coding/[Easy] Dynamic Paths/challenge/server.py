import random

def banner():
    print("You will be given a number of t = 100 grids for the different regions you need to pass. For every map you will have the below values:")
    print("\t1. The dimensions i x j of the map grid where 2 <= i, j <= 100")
    print("\t2. The numbers n_i,j symbolizing the distances between the blocks where 1 <= n_i,j <= 50")
    print("You will start at the top left element, and your goal is to reach the bottom right, while only being allowed to move down or right, minimizing the sum of the numbers you pass. Provide the minimum sum.")
    print()
    print("Example Question:")
    print("\t4 3")
    print("\t2 5 1 9 2 3 9 1 3 11 7 4")
    print()
    print("This generates the following grid:")
    print("\t 2 5 1")
    print("\t 9 2 3")
    print("\t 9 1 3")
    print("\t11 7 4")
    print()
    print("Example Response:")
    print("\t17")
    print("(Optimal route is 2 -> 5 -> 2 -> 1 -> 3 -> 4)")

def generate_test(dimension_bound, num_bound):
    i, j = [random.randint(2, dimension_bound) for _ in range(2)]
    grid = []
    for _ in range(i * j):
        grid.append(str(random.randint(1, num_bound)))
    return f'{i} {j}', ' '.join(grid)

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

def min_path_sum(grid):
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

def main():
    banner()
    f = 1
    for t in range(100):
        print()
        print(f'Test {t+1}/100')
        if 0 <= t <= 20:
            dim_limit = 5
            num_limit = 9
        elif 20 < t <= 40:
            dim_limit = 15
            num_limit = 20
        elif 40 < t <= 60:
            dim_limit = 30
            num_limit = 30
        elif 60 < t <= 80:
            dim_limit = 50
            num_limit = 40
        else:
            dim_limit = 100
            num_limit = 50
        dimensions, grid = generate_test(dim_limit, num_limit)
        print(dimensions)
        print(grid)
        min_path_sum_res, min_path_res = min_path_sum(format_grid(dimensions, grid))
        min_path_sum_inp = int(input('> '))
        if min_path_sum_inp != min_path_sum_res:
            f = 0
            break

    if f:
        flag = open('/flag.txt', 'r').read()
        print(f'You managed to traverse the maze of the underground and escape the behemoth. Here is your reward: {flag}')
    else:
        print('You made the wrong choice, the behemoth caught you...')


if __name__ == '__main__':
    main()
