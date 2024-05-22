![img](../../../../../assets/banner.png)

<img src='../../../../../assets/htb.png' style='margin-left: 20px; zoom: 80%;' align=left /> <font size='10'>Branching Tactics</font>

8<sup>th</sup> May 2024

Prepared By: ckrielle

Challenge Author(s): ckrielle

Difficulty: <font color=orange>Medium</font>

Classification: Official

# Synopsis

- Traverse a tree efficiently using binary lifting

## Description

- You have finally reached the vault, however upon reaching it you lay your eyes on a super mutant camp outisde of the vault's entrance. Seeing that you are vastly outnumbered, you decide to not engage in combat and risk losing them. Instead, you decide to use the tnt you brought along, and place them strategically in the underground tunnel network to blow up the mutant camp so all of them are eliminated. However your group is tired, and may not deliver them at the desired location, so you also need to account as to where the explosives will end up. Like the branches of a tree, can you find study the underground tunnel and find where to put your bombs to defeat the mutants and enter the vault of hope?

## Skills Required

- Basic research skills.
- Intermediate programming skills.
- Basic algorithmic skills.

## Skills Learned

- Understanding of tree data structures.
- Understanding of common tree operations.

# Enumeration

## Connecting to the instance

Since no files are provided for this challenge, let's connect to the instance and see what we get

```
You have a set of troops tasked with placing tnt in the underground tunnel. For every scenario, you will have the below values:
	1. The n number of nodes in the terrain, where 2 <= n <= 3 * 10 ** 5.
	2. The following n-1 lines will have 2 numbers e1, e2. These will both be nodes of the tunnels, where 1 <= e1, e2 <= n. The pair of nodes e1, e2 are connected.
	3. The next number is m, the number of troops carrying tnt, where 1 <= m <= n.
	4. m lines will follow, each with 3 values: s (the starting node of the troop), d (the destination node of the troop), and e (the energy of the troop), where 1 <= s, d, e <= n.

Each troop does their best job to move from nodes s to d, but can only make a maximum of e movements between nodes. The troop tries to get as far as possible with what energy it has.
Each movement from one node to another costs 1 energy, decreasing e by 1 - once e is at 0, the troop can not make another move.
Find the node each troop ends up in and place the tnt. Send the node e, in the same order as you received the s-d-e triplets.

Example Scenario:
	3
	3 2
	2 1
	2
	1 1 1
	1 3 1

Example Response:
	1
	2
```

We get a big description of the problem we need to solve. It seems to hint at a tree data structure, asking us to find the node each troop will land on for every test. So it's a node traversal problem. To tackle this, we need to cover a bit about trees

## Quick overview of trees and algorithms

Before going into trees, we will discuss a very popular search algorithm, DFS, or Depth First Search. It takes a LIFO algorithmic approach, going deep into every path of our defined dataset, one path at a time. If for example in a tree there is a subtree that splits into two branches, then DFS will first go into the left path, go back into the common ancestor from which it branched, and it will traverse the second path. So it's a good algorithm to traverse every node of a tree. A good explanation of DFS (and BFS) can be found [here](https://www.youtube.com/watch?v=TIbUeeksXcI&ab_channel=BackToBackSWE).

Trees are a data structure, providing a specific and powerful way to store data. Instead of storing data into an array/list and making up their structure in our mind, trees provided a structured way of storing data, and provides relations between them. Since trees, unlike graphs, are not a cyclic data structure, they provide a unique path from one node to another. Through this, traversing them is relatively easy and something that can be done quite efficiently, especially if for every node a path is precomputed (i.e. we know the parent of every node). This process can be performed with DFS.

After precomputing the paths, we can use the idea of binary lifting to minimze the times it takes to traverse a tree even further. Binary lifting relies on the idea that since the paths are known, instead of moving one node at a time, we can speed up our traversal by doubling the nodes we can pass through in every iteration by a power of 2. For example if we have a path `1 2 3 4 5`, instead of going through each node, we can rearrange our paths array to hold the path `1 3 5`, essentially lifting the path by 2. And since this is a logarithmic behaviour, we decreade our time complexity from a linear O(n) to O(n * logn), which is vastly improved. This is very important if we deal with cases where our tree is thousands of nodes. A very good explanation of trees and of binary lifting is provided [here](https://www.youtube.com/watch?v=MOy4UDjN8DM&ab_channel=SecondThread).


# Solution

## Traversing a tree

To solve the problem, we essentially have to perform binary lifting to find the LCA of the two target nodes. Afterwards, we find the depth of the two nodes minus 2 times the depth of the lca. If the result is less than the energy of the troops, then the troops have enough energy to go there, so we return that. If however it isn't, then we need to find out the node we will end up at, we need to find based on the path between the 2 nodes where we will end up. The trivial case is if the node we end up in is on the same part of the tree as our starting node (i.e. we're going up on the tree), whereas if it's on the other side of the lca, we will perform a meet in the middle approach, going up from the end node. To improve all this, we will perform binary lifting 

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

We will initially get the values, before we proceed to pass them onto our tree data structure

```py
def get_values(test_n):
    io.recvuntil(f'Test {test_n + 1}/100\n'.encode())
    n = int(io.recvline().rstrip())
    nodes = []
    for _ in range(n - 1):
        nodes.append(list(map(int, io.recvline().rstrip().decode().split(' '))))
    m = int(io.recvline().rstrip())
    queries = []
    for _ in range(m):
        queries.append(list(map(int, io.recvline().rstrip().decode().split(' '))))
    return n, nodes, m, queries
```

### Creating our data structure

The data structure will hold all the necessary internal values, structures, and methods to solve our problem. Specifically
- `dfs0`: It precomputes the binary lifting table
- `goUp`: Ascends the tree to find ancestors of our node using the lift table
- `lca`: find the least common ancestor of two nodes

```py
class Node:
    def __init__(self, id):
        self.id = id
        self.adj = []
        self.depth = 0
        self.lift = [None] * 20
    
    def dfs0(self, par, depth):
        self.depth = depth
        self.lift[0] = par
        for neighbor in self.adj:
            if neighbor == par:
                continue
            neighbor.dfs0(self, depth + 1)
    
    def goUp(self, nSteps):
        if nSteps == 0:
            return self
        step = 1 << (nSteps.bit_length() - 1)
        return self.lift[nSteps.bit_length() - 1].goUp(nSteps - step)
	
    # least common ancestor
    def lca(self, other, maxJumps=19):
        if self == other:
            return self
        if self.depth != other.depth:
            if self.depth > other.depth:
                return self.goUp(self.depth - other.depth).lca(other, maxJumps)
            return self.lca(other.goUp(other.depth-self.depth), 19)
        if self.lift[0] == other.lift[0]:
            return self.lift[0]
        while (self.lift[maxJumps] == other.lift[maxJumps]):
            maxJumps -= 1;
        return self.lift[maxJumps].lca(other.lift[maxJumps], maxJumps)
```

### Find the final node

Below is a solver to traverse the tree and find the node the troop will end up at. The function computes the solution for every given query all at once, and returns an array with the results

```py
def find_final_nodes(n, edges, queries):
    nodes = [Node(i + 1) for i in range(n)]
    for a, b in edges:
        nodes[a - 1].adj.append(nodes[b - 1])
        nodes[b - 1].adj.append(nodes[a - 1])
    nodes[0].dfs0(None, 0)
    for e in range(1, 20):
        for node in nodes:
            if node.lift[e - 1] is not None:
                node.lift[e] = node.lift[e - 1].lift[e - 1]
    results = []
    for a, b, c in queries:
        a_node = nodes[a - 1]
        b_node = nodes[b - 1]
        lca = a_node.lca(b_node)
        totalDist = a_node.depth + b_node.depth - 2 * lca.depth
        if totalDist <= c:
            results.append(b_node.id)
        else:
            aDist = a_node.depth - lca.depth
            if c <= aDist:
                results.append(a_node.goUp(c).id)
            else:
                bUp = totalDist - c
                results.append(b_node.goUp(bUp).id) 
    return results
```

### Sending the solution to the server

We write a simple small function with a for loop to send the solution of every query to the server

```py
def send_solution(final_nodes):
    for node in final_nodes:
        io.sendline(f'{node}'.encode())
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
3. Populate the node data structure and solve the tree traversal problem
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