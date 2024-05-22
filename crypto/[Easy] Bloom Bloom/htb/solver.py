from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Util.number import long_to_bytes
import re

with open('output.txt') as f:
    data = f.read().split('\n')

enc_messages = eval(data[0])
enc_flag = bytes.fromhex(data[1])

key = sha256(b'0'*256).digest()

shares = []
for i in range(len(enc_messages)):
    for iv, ct in enc_messages[i]:
        try:
            cipher = AES.new(key, AES.MODE_CBC, bytes.fromhex(iv))
            dec = unpad(cipher.decrypt(bytes.fromhex(ct)), 16).decode()
            shares.append(eval(dec.split('#: ')[1]))
            if i == len(enc_messages) - 1:
                p = int(re.search(r'\d+', dec).group())
            break
        except:
            pass

assert len(shares) == 5

from sage.all import *

F = GF(p)
PR = PolynomialRing(F, 'x')
P = PR.lagrange_polynomial(shares)

key = long_to_bytes(int(list(P)[0]))
flag = unpad(AES.new(key, AES.MODE_ECB).decrypt(enc_flag), 16)
print(flag)