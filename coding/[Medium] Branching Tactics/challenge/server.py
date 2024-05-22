import random

def banner():
    print("You have a set of troops tasked with placing tnt in the underground tunnel. For every scenario, you will have the below values:")
    print("\t1. The n number of nodes in the terrain, where 2 <= n <= 3 * 10 ** 5.")
    print("\t2. The following n-1 lines will have 2 numbers e1, e2. These will both be nodes of the tunnels, where 1 <= e1, e2 <= n. The pair of nodes e1, e2 are connected.")
    print("\t3. The next number is m, the number of troops carrying tnt, where 1 <= m <= n.")
    print("\t4. m lines will follow, each with 3 values: s (the starting node of the troop), d (the destination node of the troop), and e (the energy of the troop), where 1 <= s, d, e <= n.")
    print()
    print("Each troop does their best job to move from nodes s to d, but can only make a maximum of e movements between nodes. The troop tries to get as far as possible with what energy it has.")
    print("Each movement from one node to another costs 1 energy, decreasing e by 1 - once e is at 0, the troop can not make another move.")
    print("Find the node each troop ends up in and place the tnt. Send the node e, in the same order as you received the s-d-e triplets.")
    print()
    print("Example Scenario:")
    print("\t3")
    print("\t3 2")
    print("\t2 1")
    print("\t2")
    print("\t1 1 1")
    print("\t1 3 1")
    print()
    print("Example Response:")
    print("\t1")
    print("\t2")

class TreeNode:
    def __init__(self, val):
        self.val = val
        self.children = []

def generate_valid_tree(n):
    nodes = [TreeNode(i) for i in range(n)]
    edges = []
    available_nodes = [0]
    for i in range(1, n):
        parent = random.choice(available_nodes)
        child = i
        available_nodes.append(child)
        nodes[parent].children.append(nodes[child])
        edges.append((parent+1, child+1))
    return edges

def generate_queries(n, q):
    queries = []
    for _ in range(q):
        a = random.randint(1, n)
        b = random.randint(1, n)
        c = random.randint(1, n)
        queries.append((a, b, c))
    return queries

def generate_test(n_bound):
    n = random.randint(2, n_bound)
    while True:
        try:
            nodes = generate_valid_tree(n)
            if nodes:
                break
        except IndexError:
            pass
    m = random.randint(1, n-1)
    queries = generate_queries(n, m)
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

def main():
    banner()
    f = 1
    for t in range(100):
        print()
        print(f'Test {t+1}/100')
        if 0 <= t <= 5:
            n_limit = 5
        elif 5 < t <= 20:
            n_limit = 3 * 10 ** 1
        elif 20 < t <= 40:
            n_limit = 3 * 10 ** 2
        elif 40 < t <= 60:
            n_limit = 3 * 10 ** 3
        elif 60 < t <= 80:
            n_limit = 3 * 10 ** 4 // 2
        else:
            n_limit = 3 * 10 ** 4
        n, nodes, m, queries = generate_test(n_limit)
        print(n)
        for e1, e2 in nodes:
            print(e1, e2)
        print(m)
        for s, d, e in queries:
            print(s, d, e)
        final_nodes_server = find_final_nodes(n, nodes, queries)
        final_nodes_client = []
        for _ in range(m):
            final_nodes_client.append(int(input()))
        if final_nodes_server != final_nodes_client:
            f = 0
            break
    if f:
        flag = open('/flag.txt', 'r').read()
        print(f'You won over your enemies. Better hide the bodies however before ghouls show up... Here is your reward: {flag}')
    else:
        print('Aaaaaaaaand you got destroyed. Should have structured the field more...')

if __name__ == '__main__':
    main()
