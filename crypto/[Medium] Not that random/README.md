![img](../../../../../assets/banner.png)

<img src='../../../../../assets/htb.png' align=left /><font size='6'>Not that random</font>

 1<sup>st</sup> May 2024 / Document No. D24.102.64

 Prepared By: `aris`

 Challenge Author(s): `Babafaba`

 Difficulty: <font color=orange>Medium</font>

 Classification: Official

# Synopsis

- The player has to distinguish the outputs of a sha256-based custom HMAC from random outputs. The goal is to reach 500 points and "buy" the flag.

## Description

- Uncertain of their safety from other potentially hostile communities, the survivors recognize the necessity of arming themselves with laser weapons and flamethrowers for self-defense. Rumor has it that an old casino on the city's outskirts holds advanced weaponry. However, to gain access to this private area, an uninvited visitor must play a seemingly impossible game of chance and accumulate a specific amount of winnings. Is the challenge as it appears, or can you prove them wrong?

## Skills Required

- Basic Python source code analysis.
- Basic research skills.
- Understanding of hash functions and their properties.
- Basic Python scripting skills.

## Skills Learned

- Better understanding of hash functions.
- Distinguishing real hash outputs from random outputs.

# Enumeration

## Analyzing the source code

If we look at the `source.py` script we can see that we start with 100 coins and our goal is to get 500 coins through an online "casino" to buy the flag from the server. 

The basic workflow of the script is as follows:

1. Your balance is initialized at 100 coins.
2. A 16-byte secret key is generated.
3. The casino uses the secret key to make a custom, keyed, sha256 based hash.
4. You can play a game with the casino where the server uses a random input(given to you) and either outputs the custom's hash output or a truly random value.
5. Guessing correctly whether the output was from the hash or random rewards you with 5 coins but you lose 10 coins otherwise.
6. You can also try to use the custom hash for 10 coins with your own input but again the output might actually be truly random instead of the hash's with probability 1/2.
7. If you have 500 coins you can buy the flag from the casino.

Steps 1 and 2 (for step 2 PyCryptodome's Crypto.Random module is used) are:

```python
def __init__(self):
    self.player_money = 100
    self.secret_key = get_random_bytes(16)
```

For step 3, the custom hash is built from two parts, the "keyed" sha256 and a function that combines it in a weird way.

```python
def keyed_hash(key, inp):
    return sha256(key + inp).digest()

def custom_hmac(key, inp):
		return keyed_hash(keyed_hash(key, b"Improving on the security of SHA is easy"), inp) + keyed_hash(key, inp)
```

For step 5, `play` function is used:

```python
def play(self):
    my_bit = random.getrandbits(1)
    my_hash_input = get_random_bytes(32)

    print("I used input " + my_hash_input.hex())

    if my_bit == 0:
        my_hash_output = custom_hmac(self.secret_key, my_hash_input)
    else:
        my_hash_output = impostor_hmac(self.secret_key, my_hash_input)

    print("I got output " + my_hash_output.hex())

    answer = int(input("Was the output from my hash or random? (Enter 0 or 1 respectively) :: "))

    if answer == my_bit:
        self.player_money += 5
        success("Lucky you!")
    else:
        self.player_money -= 10
        fail("Wrong!")
```

For step 6, `buy_hint` function is used:

```python
def buy_hint(self):
    self.player_money -= 10
    hash_input = bytes.fromhex(input("Enter your input in hex :: "))
    if random.getrandbits(1) == 0:
        print("Your output is :: " + custom_hmac(self.secret_key, hash_input).hex())
    else:
        print("Your output is :: " + impostor_hmac(self.secret_key, hash_input).hex())
```

The 7th step prints the flag if the player money is greater or equal to 500:

```python
def buy_flag(self):
    if self.player_money >= 500:
        self.player_money -= 500
        success(f"Winner winner chicken dinner! Thank you for playing, here's your flag :: {open('flag.txt').read()}")
    else:
        fail("You broke")
```

# Solution

## Finding the vulnerability

There are 2 steps in this challenge's vulnerability.

1. The "hint" function only outputs the hash's output half of the time but we can simply end the same input many times until one appear twice, that will be the true output of the hash for that input.
2. The custom hash works like this `H(key, m) = sha256(sha256(key, fixed_message), m)||sha256(key, m)`, so the key used for the first half of the output is actually fixed since both the server's secret_key and the fixed_message are fixed.

We can use the first step to query successfully for `H(key, fixed_message)`. The second half of the output will be `k' = sha256(key, fixed_message)`, which is the key used to calculate the first half of every output. After getting `k'` we can locally calculate the first halves of the hash's outputs and compare with the values from the server. If they're different then the server actually responded with a random value, otherwise the hash was used.

## Exploitation

### Connecting to the server

A pretty basic script for connecting to the server with `pwntools`:

```python
if __name__ == '__main__':
    global conn
    if args.REMOTE:
        host_port = sys.argv[1].split(':')
        HOST = host_port[0]
        PORT = host_port[1]
        conn = remote(HOST, PORT, level='error')
    else:
        conn = process(['python3', '../challenge/server.py'], level='error')

    pwn()
```

### Getting the key $k'$

The server uses the `fixed_message = b"Improving on the security of SHA is easy"`
We can send this value as input with the hint choice of the Menu (option 2) until we get the same output twice, this means that repeated output is the true output of the hash.
This can be done with the following script:

```python
def get_fixed_key():
    global conn
    msg = b"Improving on the security of SHA is easy"
    conn.recvline()
    my_balance = 100
    appeared = []
    for i in range(10):
        my_balance -= 10
        conn.recvuntil(b"Option: ")
        conn.sendline(b"2")
        conn.recvuntil(b"hex :: ")
        conn.sendline(msg.hex().encode())
        potential_hash = conn.recvline().decode().split()[-1]
        appeared.append(potential_hash)
        if appeared.count(appeared[-1]) > 1:
            H_k_msg = bytes.fromhex(appeared[-1][64:])
            return H_k_msg, my_balance
```
We only have 100 coins to begin with, so can only try 10 times, should be plenty to get the actual output. If we're extremely unlucky an no output appears twice we can simply restart the connection and try again.

### Earning 500 coins

Now that we have the key `k'` we can play the server's game and compute the first half of the output of the hash locally with `sha256(k', message)`. Then, we'll compare the first half server's output with our own, if it's the same, the server must have used the hash, otherwise with overwhelming probability it simply calculated a random value. This is doen with the following function:

```python
def win_game(H_k_msg, my_balance):
    global conn
    while my_balance < 500:
        conn.recvuntil(b"Option: ")
        conn.sendline(b"3")
        curr_input = conn.recvline().decode().split()[-1]
        curr_output = conn.recvline().decode().split()[-1]
        conn.recvuntil(b" :: ")
        if check_output(curr_output, curr_input, H_k_msg):
            conn.sendline(b"0")
        else:
            conn.sendline(b"1")
        my_balance += 5
```

### Getting the flag

We simply "buy" it by selecting the right option (option 1):

```python
def get_flag():
		global conn
    conn.recvuntil(b"Option: ")
    conn.sendline(b"1")
    flag = conn.recvline()
    conn.close()
    return flag.decode()
```

A final summary of all that was said above:

1. We got the key for the first half of the hash.
2. We used the key to distinguish the server's outputs.
3. We got the flag.

This recap can be represented by code with the `pwn()` function:

```python
def pwn():
    H_k_msg, my_balance = get_fixed_key()
    win_game(H_k_msg, my_balance)
    flag = get_flag()
    print(flag)
```
