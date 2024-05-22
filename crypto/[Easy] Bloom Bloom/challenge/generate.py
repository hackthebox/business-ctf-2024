from sage.all import *
import secret_template
from Crypto.Util.number import *

key = bytes_to_long(secret_template.KEY)

while True:
    p = random_prime(2**256, 2**257)
    if p > key:
        break

F = GF(p)
PR = PolynomialRing(F, 'x')

coeffs = [key] + [F.random_element() for _ in range(4)]
P = PR(coeffs)
shares = [(x, P(x)) for x in range(1, 6)]

messages = secret_template.MESSAGES

for i in range(len(messages)):
    messages[i] += str(shares[i])

messages[-1] = messages[-1] % str(p)

to_write = '''
FLAG = %s
KEY = %s
MESSAGES = %s
''' % (secret_template.FLAG, secret_template.KEY, str(messages))

with open('secret.py', 'w') as f:
    f.write(to_write)