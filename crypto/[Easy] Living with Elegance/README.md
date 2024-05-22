![img](../../../../../assets/banner.png)

<img src='../../../../../assets/htb.png' style='zoom: 80%;' align='left' /><font size='6'>Living with Elegance</font>

25<sup>th</sup> April 2024 / Document No. D24.102.63

Prepared By: `aris`

Challenge Author(s): `aris`

Difficulty: <font color=green>Easy</font>

Classification: Official

# Synopsis

- The player has to determine the flag bits one by one by determining with high certainty which outputs come from the modified LWE implementation or are just random.

## Description

- With injuries and illnesses escalating, the priority is clear: human lives take precedence. Before seeking hidden treasures, it is imperative to first treat the wounded ones. The resolute survivors learn through rumors about a hidden medical research facility known as the "BioMed Research Institute" reputed for its advanced treatments. They plan to locate and infiltrate the institute, intent on securing vital medications and medical equipment necessary to save the lives of their injured comrades. However, such a feat will not come easily. The facility is safeguarded by state-of-the-art security mechanisms known only to the government. The team must navigate several layers of doors to access the heart of the facility. Can you identify any vulnerability or hidden backdoor in this enigmatic security system?

## Skills Required

- Textbook knowledge of how the LWE cryptosystem works.
- Basic source code auditing skills.

## Skills Learned

- Learn how to detect vulnerable implementations of crypto systems.
- Ability to distinguish fake LWE public keys from real ones.

# Enumeration

## Analyzing the source code

In this challenge we are provided with just one file:

1. `server.py` : This is the main script that is executed when we connect to the challenge's instance.

The challenge title gives out a handy hint regarding the cryptosystem that is being used in this challenge; more specifically, that is `Learning with Errors (LWE)`. The cryptosystem is discussed [here](https://asecuritysite.com/public/lwe_ring.pdf) in high level.

Let us take a look at the LWE implementation in this challenge.

```python
class ElegantCryptosystem:
    def __init__(self):
        self.d = 16
        self.n = 256
        self.S = token_bytes(self.d)

    def noise_prod(self):
        return randbelow(2*self.n//3) - self.n//2

    def get_encryption(self, bit):
        A = token_bytes(self.d)
        b = self.punc_prod(A, self.S) % self.n
        e = self.noise_prod()
        if bit == 1:
            return A, b + e
        else:
            return A, randbelow(self.n)
    
    def punc_prod(self, x, y):
        return sum(_x * _y for _x, _y in zip(x, y))
```

Let us break down what each function does:

- `__init__` : Setups the core LWE parameters. The ciphertext modulo `n = 256`, the dimension `d = 16` and the secret vector `S` of size `d`.
- `noise_prod` : Generates an error value in the range $[-128, 41)$​.
- `get_encryption` : If the provided bit is $1$, the function returns an LWE ciphertext of the usual form $(A, b+e)$, otherwise it returns $A$ along with a random number less than $n$. This is a fake ciphertext as this random number is not derived from $A$​ at all.
- `punc_prod` : Computes the dot product $x_1y_1 + x_2y_2 + ... + x_ny_n$ for the vectors $\overrightarrow{x} = (x_1, x_2, ..., x_n)$ and $\overrightarrow{y} = (y_1, y_2, ..., y_n)$ of size $n$​.

The main method is trivial to understand.

```python
from secret import FLAG
from Crypto.Util.number import bytes_to_long as b2l

def main():
    FLAGBIN = bin(b2l(FLAG))[2:]
    crypto = ElegantCryptosystem()

    while True:
        idx = input('Specify the index of the bit you want to get an encryption for : ')
        if not idx.isnumeric():
            print('The index must be an integer.')
            continue
        idx = int(idx)
        if idx < 0 or idx >= len(FLAGBIN):
            print(f'The index must lie in the interval [0, {len(FLAGBIN)-1}]')
            continue
        
        bit = int(FLAGBIN[idx])
        A, b = crypto.get_encryption(bit)
        print('Here is your ciphertext: ')
        print(f'A = {b2l(A)}')
        print(f'b = {b}')
```

The flag is first converted to a bit string. We can interact with the instance by selecting the position of the bit that we want to get a ciphertext for. If the number is too high or too low, we get an error message regarding the length of the bit string.

Our goal is to determine whether the bit at position $i$ is a $0$ or $1$, which is also known as a decisional problem. We cannot refer to $(A, b+e)$ as the ciphertext as the input of `get_encryption` is not really encrypted, but instead plays a key role in the decisional problem.

# Solution

## Finding the vulnerability

To find the vulnerability, all we have to do is look at how standard LWE implementations work. In the challenge implementation we spot a few significant differences.

1. While the error sampling should come from a secure distribution such as the Gaussian distribution, in this challenge, the error values lie in the range $[-128, 41)$​ which is a sign of a different distribution.
2. The second difference is the most critical. Normally, the second part of the ciphertext is $(b+e) \pmod n$. However, in this case, reduction of $b$ is done first and the error is added without reduction.

The error can take positive values too so it is not difficult to see that without reducing the addition of the error, $b+e$ might be larger than $n$ or less than $0$. For example, if $b \pmod n = 250$ and the error is $e = 20$ then $b+e = 270$ while it should be $(b+e)\pmod n = (250 + 20) \pmod {256} = 14$​.

Therefore, if we send the $i$-th bit of the flag and obtain a value $> n$ or $< 0$, then we can decide with 100% certainty that this bit is a $1$-bit.

If we obtain a positive value $< n$, we cannot decide whether it is a random value (thus a $0$-bit) or $b+e < n$. This means that we are only interested in the case wher the sum $b+e$ is larger than $n$ or it is negative.

The attack idea is:

- For each bit of the flag at position $i$.
  - Send $β$ requests.
  - If none of the $β$ results is larger than $n$, we can set the $i$-th bit to $0$ with high certainty.
  - If at least one result is larger than $n$ or less than $0$, we are sure that the $i$-th bit must be a $1$-bit.

What is left is choose the value of $β$. After some experiments, we find out that $β \geq 30$ yields accurate results.

## Exploitation

### Connecting to the server

A pretty basic script for connecting to the server with `pwntools`:

```python
from pwn import process, remote, args

if __name__ == '__main__':
    global io
    if args.REMOTE:
        HOST, PORT = sys.argv[1].split(':')
        io = remote(HOST, PORT)
    else:
        io = process(['python3', '../challenge/server.py'])
```

Before moving on, let us write a function that takes the offset to be sent as a parameter and returns the corresponding ciphertext.

```python
def receive_ciphertext(offset):
    global io
    io.sendlineafter(b' : ', str(offset).encode())
    io.recvline()
    A = int(io.recvline().decode().split(' = ')[1])
    b = int(io.recvline().decode().split(' = ')[1])
    return A, b
```

Now let us implement the attack idea described above. By sending a negative value or a value that is too large, we find out the bitlength of the flag, which is $535$.

```python
from Crypto.Util.number import long_to_bytes

def get_flag():
		flag_bits = ['?'] * 535
		β = 30
		current_idx = 0
    
    while '?' in flag_bits:
        for _ in range(β):
            A, b = receive_ciphertext(current_idx)
            if b < 0 or b >= n:
                flag_bits[current_idx] = '1'	# 100% certain
                break
        else:
            flag_bits[current_idx] = '0'	# high certainty

        current_idx += 1
    
		flag = int(''.join(flag_bits), 2)
    
    return long_to_bytes(flag)
```

### Getting the flag

A final summary of all that was said above:

1. Figure out the cryptosystem being used from the challenge name.
2. Find out the differences between the standard and this challenge's implementations.
3. Exploit the fact that $b+e$ is not reduced modulo $n$ to solve the decisional problem and recover the flag bits one by one.

This recap can be represented by code with the `pwn()` function:

```python
def pwn():
    flag = get_flag()
    print(flag)
    

if __name__ == '__main__':
    global io
    if args.REMOTE:
        HOST, PORT = sys.argv[1].split(':')
        io = remote(HOST, PORT)
    else:
        io = process(['python3', '../challenge/server.py'])

		pwn()
```
