import random

def banner():
    print("You will be given a number of s = 100 salesmen offering their products. You have a bag with a capacity C, where 1 <= C <= 10 ** 5")
    print("For every product bench you will have the below values:")
    print("\t1. The number of products N, using 1-based indexing (1, 2, ..., N), where 1 <= N <= 100")
    print("\t2. The capacity C")
    print("\t3. Every product i will have 2 values, a weight w_i, and a value v_i, where 1 <= w_i <= C, and 1 <= v_i <= 10 ** 10 ")
    print("Find the maximum value of products you can fit in your bag.")
    print()

    print("You will receive N and C, then after that the product values w_i and v_i.")

    print("Example Input:")
    print("\t4 14")
    print("\t6 3")
    print("\t7 9")
    print("\t5 4")
    print("\t2 1")
    print()
    print("Example Output:")
    print("\t14")

def generate_test(count_bound, weight_bound, value_limit):
    N = random.randint(1, count_bound)
    C = random.randint(1, weight_bound)
    products = []
    for _ in range(N):
        products.append((random.randint(1, C), random.randint(1, value_limit)))
    return N, C, products

def solve_knapsack(n, c, weights, values):
    dp = [[0 for _ in range(c + 1)] for _ in range(n + 1)]
    
    for i in range(1, n + 1):
        for w in range(1, c + 1):
            if weights[i-1] <= w:
                dp[i][w] = max(dp[i-1][w], dp[i-1][w-weights[i-1]] + values[i-1])
            else:
                dp[i][w] = dp[i-1][w]
    
    return dp[n][c]

def main():
    banner()
    f = 1
    for s in range(100):
        print()
        print(f'Test {s+1}/100')
        if 0 <= s <= 5:
            c_limit = 5
            w_limit = 10 ** 1
            v_limit = 10 ** 1
        elif 5 < s <= 20:
            c_limit = 20
            w_limit = 10 ** 1
            v_limit = 10 ** 2
        elif 20 < s <= 40:
            c_limit = 40
            w_limit = 10 ** 2
            v_limit = 10 ** 4
        elif 40 < s <= 60:
            c_limit = 60
            w_limit = 10 ** 3
            v_limit = 10 ** 6
        elif 60 < s <= 80:
            c_limit = 80
            w_limit = 10 ** 4
            v_limit = 10 ** 8
        else:
            c_limit = 100
            w_limit = 10 ** 5
            v_limit = 10 ** 10
        N, C, products = generate_test(c_limit, w_limit, v_limit)
        print(N, C)
        weights = []
        values = []
        for p in products:
            print(p[0], p[1])
            weights.append(p[0])
            values.append(p[1])
        server_solution = solve_knapsack(N, C, weights, values)
        client_solution = int(input())
        if server_solution != client_solution:
            f = 0
            break
    if f:
        flag = open('/flag.txt', 'r').read()
        print(f'You filled your bag with amazing weapons, your adventure will be a piece of cake now. Here is your reward: {flag}')
    else:
        print('Chief you got scammed')


if __name__ == '__main__':
    main()