![](../../../../../assets/banner.png)

<img src="../../../../../assets/htb.png" style="margin-left: 20px; zoom: 80%;" align=left /><font size="10">eXciting Outpost Recon</font>

​		8<sup>th</sup> May 2024 / Document No. D24.102.71

​		Prepared By: `ir0nstone`

​		Challenge Author(s): `ir0nstone`

​		Difficulty: <font color=green>Very Easy</font>

​		Classification: Official

 



# Synopsis

eXciting Outpost Recon is a Very Easy crypto challenge that requires the player to perform a known-plaintext attack to recover the XOR key and then emulate the encryption procedure for retrieve the data.

# Description

Hijacking the outpost responsible for housing the messengers of the core gangs, we have managed to intercept communications between a newly-elected leader and the Tariaki, a well-established and powerful gang. In an attempt to sow conflict and prevent the creation of a singular all-powerful coalition to oppress the common people, we want YOU to use this message to our advantage. Can you use their obsequiousness to your advantage?

## Skills Required

- Basic understanding of XOR
- Basic programming skills

## Skills Learned

- Known-plaintext attack

# Enumeration
We are given the following script:

```python
from hashlib import sha256

import os

LENGTH = 32


def encrypt_data(data, k):
    data += b'\x00' * (-len(data) % LENGTH)
    encrypted = b''

    for i in range(0, len(data), LENGTH):
        chunk = data[i:i+LENGTH]

        for a, b in zip(chunk, k):
            encrypted += bytes([a ^ b])

        k = sha256(k).digest()

    return encrypted


key = os.urandom(32)

with open('plaintext.txt', 'rb') as f:
    plaintext = f.read()

assert plaintext.startswith(b'Great and Noble Leader of the Tariaki')       # have to make sure we are aptly sycophantic

with open('ciphertext.txt', 'wb') as f:
    enc = encrypt_data(plaintext, key)
    f.write(enc)
```

In effect, the script will:
* Generate a random `key`
* Read the letter from `plaintext.txt`
* Ensure it starts with `Great and Noble Leader of the Tariaki`
* Encrypts it using `encrypt_data`

`encrypt_data`, in turn, will:
* Split the data into 32-byte chunks
* Iterate through the chunks
* Each chunk will be XORed with `key`
* `key` will then be sha256 hashed, so the next chunk is XORed with a derived key

# Solution
Knowing that the plaintext starts with `Great and Noble Leader of the Tariaki`, which is over `32` bytes long, we can retrieve the randomised `key`. This is because the first block is XORed with the default `key`:

```python
key = xor(ciphertext[:32], b'Great and Noble Leader of the Tariaki'[:32])
```

Once we get this, we can run the initial `encrypt_data` function on the encrypted data, because XOR is its own inverse:

```python
d = encrypt_data(ciphertext, key)
print(d.decode())
```

Printing out the decrypted data, we get the flag!
