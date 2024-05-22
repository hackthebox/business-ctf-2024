from Crypto.Util.number import *
from Crypto.Random import random, get_random_bytes
from hashlib import sha256

def success(s):
    print(f'\033[92m[+] {s} \033[0m')

def fail(s):
    print(f'\033[91m\033[1m[-] {s} \033[0m')

MENU = '''
Make a choice:

1. Buy flag (-500 coins)
2. Buy hint (-10 coins)
3. Play (+5/-10 coins)
4. Print balance (free)
5. Exit'''

def keyed_hash(key, inp):
    return sha256(key + inp).digest()

def custom_hmac(key, inp):
    return keyed_hash(keyed_hash(key, b"Improving on the security of SHA is easy"), inp) + keyed_hash(key, inp)

def impostor_hmac(key, inp):
    return get_random_bytes(64)

class Casino:
    def __init__(self):
        self.player_money = 100
        self.secret_key = get_random_bytes(16)
    
    def buy_flag(self):
        if self.player_money >= 500:
            self.player_money -= 500
            success(f"Winner winner chicken dinner! Thank you for playing, here's your flag :: {open('flag.txt').read()}")
        else:
            fail("You broke")
    
    def buy_hint(self):
        self.player_money -= 10
        hash_input = bytes.fromhex(input("Enter your input in hex :: "))
        if random.getrandbits(1) == 0:
            print("Your output is :: " + custom_hmac(self.secret_key, hash_input).hex())
        else:
            print("Your output is :: " + impostor_hmac(self.secret_key, hash_input).hex())

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

    def print_balance(self):
        print(f"You have {self.player_money} coins.")



def main():
    print("Welcome to my online casino! Let's play a game!")
    casino = Casino()

    while casino.player_money > 0:
        print(MENU)
        option = int(input('Option: '))

        if option == 1:
            casino.buy_flag()
                
        elif option == 2:
            casino.buy_hint()
                
        elif option == 3:
            casino.play()
                
        elif option == 4:
            casino.print_balance()
            
        elif option == 5:
            print("Bye.")
            break
        
    print("The house always wins, sorry ):")

if __name__ == '__main__':
    main()