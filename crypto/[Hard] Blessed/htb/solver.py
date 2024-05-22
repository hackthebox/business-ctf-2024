import json

from functools import reduce
from pwn import process, sys, remote

from py_ecc.bls.ciphersuites import G2ProofOfPossession as bls
from py_ecc.bls.g2_primitives import G1_to_pubkey, pubkey_to_G1
from py_ecc.bls.point_compression import decompress_G1
from py_ecc.bls.typing import G1Compressed

from py_ecc.optimized_bls12_381.optimized_curve import add, G1, multiply, neg, normalize, Z1

from sage.all import EllipticCurve, GF, identity_matrix, PolynomialRing, Sequence, zero_matrix, ZZ


def get_process():
    if len(sys.argv) == 1:
        return process(['python3', '../challenge/server.py'])

    host, port = sys.argv[1].split(':')
    return remote(host, port)


def sr(data):
    io.sendlineafter(b'> ', json.dumps(data).encode())
    return json.loads(io.recvline().decode())


p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
K = GF(p)
a = K(0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc)
b = K(0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b)
E = EllipticCurve(K, (a, b))
G = E(0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296, 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)
E.set_order(0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551 * 0x1)


def crack_ec_lcg(values):
    assert len(values) == 6
    u1, v1, u2, v2, u3, v3 = values
    a1, b1, a2, b2, a3, b3 = PolynomialRing(K, 'a1, b1, a2, b2, a3, b3').gens()

    ec1 = (v1 + b1) ** 2 - (u1 + a1) ** 3 - a * (u1 + a1) - b
    ec2 = (v2 + b2) ** 2 - (u2 + a2) ** 3 - a * (u2 + a2) - b
    ec3 = (v3 + b3) ** 2 - (u3 + a3) ** 3 - a * (u3 + a3) - b

    ec4 = ((u1 + a1) + (u2 + a2) + G.x()) * ((u2 + a2) - (u1 + a1)) ** 2 - ((v2 + b2) + (v1 + b1)) ** 2
    ec5 = ((u2 + a2) + (u3 + a3) + G.x()) * ((u3 + a3) - (u2 + a2)) ** 2 - ((v3 + b3) + (v2 + b2)) ** 2
    ec6 = (G.y() - (v1 + b1)) * ((u2 + a2) - (u1 + a1)) - ((v2 + b2) + (v1 + b1)) * ((u1 + a1) - G.x())
    ec7 = (G.y() - (v2 + b2)) * ((u3 + a3) - (u2 + a2)) - ((v3 + b3) + (v2 + b2)) * ((u2 + a2) - G.x())

    A, v = Sequence([ec1, ec2, ec3, ec4, ec5, ec6, ec7]).coefficients_monomials(sparse=False)
    A = A.change_ring(ZZ)

    A = (identity_matrix(7) * p).augment(A)
    A = A.stack(zero_matrix(len(v), 7).augment(identity_matrix(len(v))))
    A[-1, -1] = 2 ** 256

    L = A.T.LLL()
    assert L[-1][-1] == 2 ** 256
    a1, b1, a2, b2, a3, b3 = L[-1][-7:-1]

    W1 = E(u1 + a1, v1 + b1)
    W2 = E(u2 + a2, v2 + b2)
    W3 = E(u3 + a3, v3 + b3)
    return W3


io = get_process()

res = sr({'cmd': 'create'})
sk = int(res.get('sk'), 16)
robot_id = int(res.get('robot_id'), 16)

cmd = 'list'
sig = bls.Sign(sk, cmd.encode())
res = sr({'cmd': cmd, 'robot_id': hex(robot_id), 'sig': sig.hex()})

ids, Pks = [], []

for r in res:
    ids.append(int(r.get('robot_id'), 16))
    Pks.append(decompress_G1(G1Compressed(int(r.get('pk'), 16))))

sk = 1337
cmd = 'unveil_secrets'
pk = bls.SkToPk(sk)
sig = bls.Sign(sk, cmd.encode())
Pk = pubkey_to_G1(pk)

Pk_prime = add(Pk, neg(reduce(add, Pks, Z1)))
pk_prime = G1_to_pubkey(Pk_prime)
assert normalize(add(reduce(add, Pks), Pk_prime)) == normalize(Pk)
io.success('Forged signature!')

res = sr({'cmd': 'join', 'pk': pk_prime.hex()})
robot_id = int(res.get('robot_id'), 16)
ids.append(robot_id)
assert len(ids) == 6

Wn = crack_ec_lcg([i << 32 for i in ids])
io.success('Cracked EC-LCG!')

prog = io.progress('Cheating ZKP')
sr({'cmd': 'verify', 'robot_id': hex(robot_id)})

for _ in range(64 // 2):
    Wn += G

    for c in Wn.xy():
        if (int(c) >> 32) & 1:
            x = 1337
            C = multiply(Pk_prime, x)
            assert normalize(multiply(Pk_prime, x)) == normalize(C)
            io.sendlineafter(b'Take a random value x and send me C = x * pk (hex): ', bytes(G1_to_pubkey(C)).hex().encode())
            io.sendlineafter(b'Give me x (hex): ', hex(x).encode())
        else:
            sk_x = 1337
            C = add(multiply(G1, sk_x), neg(Pk_prime))
            assert normalize(add(multiply(G1, sk_x), neg(Pk_prime))) == normalize(C) 
            io.sendlineafter(b'Take a random value x and send me C = x * pk (hex): ', bytes(G1_to_pubkey(C)).hex().encode())
            io.sendlineafter(b'Give me (sk + x) (hex): ', hex(sk_x).encode())

prog.success()

res = sr({'cmd': cmd, 'sig': sig.hex()})
sr({'cmd': 'exit'})
io.success(res.get('flag'))
