#!/usr/bin/env python3
from Crypto.PublicKey import RSA
from Crypto.Util import number
from Crypto.Cipher import PKCS1_OAEP
from contextlib import suppress
import PKCS1OAEP_Cipher

class PartyMember:
    def __init__(self, num_million=10, name="Craig", richest_person=10, n_bits=128):
        self.strength = 2048
        self.name = name
        self.key = RSA.generate(self.strength)
        self.million = num_million
        self.richest_person = richest_person
        self.n_bits = n_bits

    def get_pub_key(self):
        return self.key.publickey().exportKey('PEM')

    def step_1(self, peer_key_pem):
        # Bob picks a random N-bit integer, and computes privately the value of Ea(x); call the result k.
        peer_pubKey = RSA.importKey(peer_key_pem)
        self.x = number.getRandomNBitInteger(self.n_bits)
        k = PKCS1_OAEP.new(peer_pubKey).encrypt(self.x.to_bytes(self.x.bit_length()//8, byteorder='big', signed=False))
        # Bob sends Alice the number k − j + 1;
        return int.from_bytes(k, byteorder='big', signed=False) - self.million + 1

    def step_3(self, step1):
        # Alice computes privately the values of yu = Da(k−j + u) for u = 1, 2, . . . , 10.
        yu = []
        for i in range(0, self.richest_person):
            # This is where the algorithm fails due to RSA validation errors unless using modified decrypt function.
            with suppress(ValueError):
                yu.append(int.from_bytes(PKCS1OAEP_Cipher.new(self.key).decrypt((step1 + i).to_bytes(self.strength//8, byteorder='big', signed=False)), byteorder='big', signed=False))

        looping = True
        while looping:
            # Alice generates a random prime p of N/2 bits, and computes the values of zu = yu mod p for u = 1, 2, . . . , 10.
            p = number.getPrime(self.n_bits//2)
            zu = [y % p for y in yu]

            # Construct a matrix M of size 10 × 10, where Mij = |zu − zv| for i, j = 1, 2, . . . , 10.
            # If all zu differ by at least 2 in the mod p sense, stop.
            temp = zu.copy()
            temp.sort()
            looping = False
            for i in range(1, len(temp)):
                if ((int(temp[i]) - int(temp[i-1])) < 2):
                    looping = True
                    print("Not enough difference between values. Trying again.")

        # Alice sends the prime p and the following 10 numbers to B: z1, z2, . . . , zi followed by zi + 1, zi+1 + 1, . . . , z10 + 1.
        #Yao's algorithm has an error here on step 5 where the index should be i-1 instead of i when i >= self.million.
        zuf = []
        for i, z in enumerate(zu):
            if i >= self.million:
                z = (z + 1) % p
                zuf.append(zu[i-1])
            else:
                zuf.append(zu[i])
        # Let p, zu denote this final set of numbers.
        return p, zuf

    def step_6(self, p, step3):
        # Bob looks at the j-th number (not counting p) sent from Alice, and decides that i ≥ j if it is equal to x mod p, and i < j otherwise.
        uf = step3[self.million]
        # Bob tells Alice what the conclusion is.
        if self.x % p == uf:
            return f"{self.name} has more money."
        else:
            return f"{self.name} has less money."