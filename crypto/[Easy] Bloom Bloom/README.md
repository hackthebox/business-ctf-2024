![img](../../../../../assets/banner.png)

<img src='../../../../../assets/htb.png' style='zoom: 80%;' align=left /><font 
size='6'>Bloom Bloom</font>

22<sup>th</sup> April 2024 / Document No. D22.102.62

Prepared By: `aris`

Challenge Author(s): `aris`

Difficulty: <font color=green>Easy</font>

Classification: Official

# Synopsis

- In this challenge the player has to exploit a vulnerable implementation of the Blum Blum Shub PRNG and predict the decryption key of five encrypted messages. Each message reveals a share and by collecting all five shares, the player can perform polynomial interpolation in the given finite field, extract the constant term and use it as the decryption key to decrypt the flag.

## Description

- Since the fallout, most of the world's fertile land has been transformed into wasteland, leaving survivors struggling to produce enough food to sustain their communities. With traditional agriculture in ruins, they recall that, in the years before the disaster, agricultural scientists were developing genetically modified crops that could thrive in extreme conditions. Rumors point to a hidden agricultural research zone where these scientists experimented with advanced genetic seeds. This zone is believed to contain experimental crops, advanced equipment, and crucial research that could empower communities to rebuild agriculture from the ground up. Undeterred, the survivors embark on a grueling journey lasting several days in pursuit of the zone. At last, they arrive to find a vast area buried in sand but equipped with sophisticated watering systems and supplies to nurture the genetic crops. To their surprise, the zone is defended by humanoid robotic guards armed with automatic weapons. It's clear that accessing the area safely requires a secret password; otherwise, the robots are likely to open fire. Worse yet, these robots teleport unpredictably throughout the zone, making their movements almost impossible to predict. Can you extract information from their movements, predict their next move and devise a strategy to eliminate all of them?

## Skills Required

- Knowledge of how the modular operation works.
- Know how to combine shares to retrieve the interpolating polynomial.

## Skills Learned

- Learn about the Blum Blum Shub pseudo-random number generator.
- Learn that an even number reduced modulo an even number always results in an even number.
- Learn how to perform polynomial interpolation in finite fields given a small number of shares $(x_i, y_i)$.

# Enumeration

## Analyzing the source code

In this challenge we are provided with two files:

1. `source.py` : The main script that encrypts the flag and writes the output data to `output.txt`.
2. `output.txt` : The output data that will be used to decrypt the flag.

Let us first analyze the source script. First of all there is the BBS class that is responsible for encrypting the flag and generating random values.

```python
from random import randint, shuffle
from Crypto.Util.number import getPrime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from hashlib import sha256
from secret import *
import os

class BBS:
    def __init__(self, bits, length):
        self.bits = bits
        self.out_length = length

    def reset_params(self):
        self.state = randint(2, 2 ** self.bits - 2)
        self.m = getPrime(self.bits//2) * getPrime(self.bits//2) * randint(1, 2)
    
    def extract_bit(self):
        self.state = pow(self.state, 2, self.m)
        return str(self.state % 2)

    def gen_output(self):
        self.reset_params()
        out = ''
        for _ in range(self.out_length):
            out += self.extract_bit()
        return out

    def encrypt(self, msg):
        out = self.gen_output()
        key = sha256(out.encode()).digest()
        iv = os.urandom(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return (iv.hex(), cipher.encrypt(pad(msg.encode(), 16)).hex())

encryptor = BBS(512, 256)
```

There is the function `gen_output` that generates a random string consisting of $\{0, 1\}$. Each call to the function, the parameters of the RNG are reset; a new $512$-bit modulus and a new $512$-bit seed are generated. The modulus has the form $m = p \cdot q \cdot r$ where $r$ is either $1$ or $2$. In other words, $m$ is equal to $pq$ or $2pq$.

The function `extract_bit` updates the value of the internal state and returns the LSB of the current state. The state is updated as:
$$
s_{i+1} = s_i^2 \pmod m
$$
for $i$ $\in [0, 255)$.

Then, the random output string is hashed and used as the symmetric AES encryption key of the provided message `msg`.

The output file contains several encryptions of the messages in `secret.py`. More specifically:

```python
from secret import *

assert sha256(KEY).hexdigest().startswith('786f36dd7c9d902f1921629161d9b057')

enc_messages = []
for msg in MESSAGES:
    enc_messages.append([encryptor.encrypt(msg) for _ in range(10)])

enc_flag = AES.new(KEY, AES.MODE_ECB).encrypt(pad(FLAG, 16))

with open('output.txt', 'w') as f:
    f.write(f'{enc_messages}\n')
    f.write(f'{enc_flag.hex()}\n')
```

The flag is encrypted using the secret key that is derived from the secret module so the goal is clearly to retrieve this key. However, we do not know any info about the secret key directly, except the first 16 bytes of its sha256 hash. We assume it is better to focus on the encrypted messages since they might contain some important info related to the key.

Each message is encrypted 10 times and written to the output file. Before moving on, let us write a function that reads the data from the output file and returns them.

```python
def load_data():
		with open('output.txt') as f:
    		data = f.read().split('\n')

		enc_messages = eval(data[0])
		enc_flag = bytes.fromhex(data[1])
    
    return enc_messages, enc_flag
```

# Solution

## Finding the vulnerability

What stands out and is the fact that we are provided with several encryptions of the same messages and not just a single one. Let us analyze the random number generator. For each encryption, new parameters are generated. Let us take the case of the modulus. As aforementioned, it has the form $pq$ and $2pq$ and ultimately this means that the modulus is either odd or even. The same holds for the seed. There are four cases in total:
$$
1.& seed \pmod 2 \equiv 0\ ,\ m \pmod 2 \equiv 0\\
2.& seed \pmod 2 \equiv 0\ ,\ m \pmod 2 \equiv 1\\
3.& seed \pmod 2 \equiv 1\ ,\ m \pmod 2 \equiv 0\\
4.& seed \pmod 2 \equiv 1\ ,\ m \pmod 2 \equiv 1
$$
Let us see if we can come to any conclusion regarding the least significant bit in each of these cases. In general, if $x$ is odd it can be written in the form $2k + 1$ and if it's even in the form $2k$​.
$$
1.& 2k \pmod {2l} = 2k + n \cdot 2l = 2(k+nl)\\
2.& 2k \pmod {2l+1} = 2k + n \cdot (2l + 1) = 2k + n \cdot 2l + n = 2(k+nl) + n\\
3.& (2k+1) \pmod {2l} = 2k+1+n \cdot 2l = 2(k+nl) + 1\\
4.& (2k+1) \pmod {2l+1} = 2k+1 + n \cdot (2l+1) = 2k + 1 + n \cdot 2l + m = 2(k+nl) + n + 1
$$
We can see that apart from the cases $1$ and $3$, we cannot determine whether the result is odd or even since this depends on $n$.

As a result, if the starting seed is even and the modulus is even or the starting seed is odd and the modulus is odd then the output of the RNG is `000...0` or `111...1` respectively. Since we are given ten ciphertexts of each message, it is very likely that one of these ciphertexts follow the first or the third case. In other words we know the output of the RNG in $\dfrac{1}{2}$ of the times.

The idea is to fix the output string `000...00` and use it to decrypt these messages. For some of these ciphertexts, this is indeed the right output. Before implementing a generic decryptor, let us decrypt the first message and see how the output looks like.

```python
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

key = sha256(b'0'*256).digest()
for iv, ct in enc_messages[0]:
    try:
        cipher = AES.new(key, AES.MODE_CBC, bytes.fromhex(iv))
        dec = unpad(cipher.decrypt(bytes.fromhex(ct)), 16).decode()
        print(dec)
        break
    except:
        pass
```

We get the following output:

```
Welcome! If you see this you have successfully decrypted the first message. To get the symmetric key that decrypts the flag you need to do the following:

1. Collect all 5 shares from these messages
2. Use them to interpolate the polynomial in a finite field that will be revealed in another message
3. Convert the constant term of the polynomial to bytes and use it to decrypt the flag. Here is your first share!

Share#1#: (1, 27006418753792019267647881709336369603809025474153761185424552629526746515909)
```

It provides some important information regarding what we have to do to obtain the final key. The task is to perform polynomial interpolation using five shares. Each message reveals a share which we will need. Let us write a function that decrypts the messages.

```python
import re

def decrypt_messages(enc_messages):
		key = sha256(b'0'*256).digest()

    shares = []
    for i in range(len(enc_messages)):
        for iv, ct in enc_messages[i]:
            try:
                cipher = AES.new(key, AES.MODE_CBC, bytes.fromhex(iv))
                dec = unpad(cipher.decrypt(bytes.fromhex(ct)), 16).decode()
                shares.append(eval(dec.split('#: ')[1]))
                if i == len(enc_messages) - 1:
                    p = int(re.search(r'\d+', dec).group())	# extract the prime from the fifth message
                break
            except:
                pass

    assert len(shares) == 5
    
    return p, shares
```

Printing out these messages locally we can see that the fifth message contains the info related to the finite field that we need to perform the polynomial interpolation on.

```
Congratulations!!! Not him old music think his found enjoy merry. Listening acuteness dependent at or an. Apartments thoroughly unsatiable terminated how themselves. She are ten hours wrong walls stand early. Domestic perceive on an ladyship extended received do. You need to interpolate the polynomial in the finite field GF(88061271168532822384517279587784001104302157326759940683992330399098283633319).

Share#5#: (5, 87036956450994410488989322365773556006053008613964544744444104769020810012336)
```

## Polynomial Interpolation

Having collected the five shares, we can use SageMath to perform polynomial interpolation and extract the constant term. Let us write a SageMath script that recovers the original polynomial and extracts the constant term which is the decryption key.

```python
from sage.all import *
from Crypto.Util.number import long_to_bytes
from hashlib import sha256

def interpolate_polynomial(p, shares):
		F = GF(p)
    PR = PolynomialRing(F, 'x')
    P = PR.lagrange_polynomial(shares)
    key = long_to_bytes(int(list(P)[0]))
    assert sha256(key).hexdigest().startswith('786f36dd7c9d902f1921629161d9b057')
    return key
```

## Exploitation

Finally, having recovered the key we can decrypt the flag using AES-ECB.

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def decrypt_flag(key, enc_flag)
		flag = unpad(AES.new(key, AES.MODE_ECB).decrypt(enc_flag), 16)
		return flag
```



### Getting the flag

A final summary of all that was said above:

1. Analyze the random number generator and notice that $\dfrac{1}{2}$ of the cases, we know the output of the RNG due to the least significant bit.

This recap can be represented by code with the `pwn()` function.

```python
def pwn():
  	enc_messages, enc_flag = load_data()
    p, shares = decrypt_messages(enc_messages)
    key = interpolate_polynomial(p, shares)
    flag = decrypt_flag(key, enc_flag)
    print(flag)

if __name__ == '__main__':
  	pwn()

```
