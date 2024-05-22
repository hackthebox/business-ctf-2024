from pwn import *

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

def send_solution(final_nodes):
    for node in final_nodes:
        io.sendline(f'{node}'.encode())

def get_flag():
    io.recvuntil(b'HTB{')
    return b'HTB{' + io.recvline().rstrip()

def pwn():
    for t in range(100):
        print('Test', t + 1)
        n, nodes, m, queries = get_values(t)
        final_nodes = find_final_nodes(n, nodes, queries)
        send_solution(final_nodes)
    flag = get_flag()
    print(flag)

if __name__ == '__main__':
    ip = '127.0.0.1'
    port = 1337
    io = remote(ip, port)
    #io = process(['python', 'server.py'])
    pwn()