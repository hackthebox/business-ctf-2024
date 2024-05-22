from secrets import token_bytes, randbelow
from Crypto.Util.number import bytes_to_long as b2l

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

def main():
    FLAGBIN = bin(b2l(open('flag.txt', 'rb').read()))[2:]
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


if __name__ == '__main__':
    main()