#!/usr/local/bin/python
if __name__ != "__main__":
    raise Exception("not a lib?")

from os import urandom
seed = int.from_bytes(urandom(8), 'little')

import random
random.seed(seed)
from ast import literal_eval
idxs = literal_eval(input(">>> "))
if len(idxs) > 8:
    print("Ha thats funny")
    exit()
for idx in range(624):
    rand_out = random.getrandbits(32)
    if idx in idxs:
        print(rand_out)


key = random.getrandbits(256)
nonce = random.getrandbits(256)
flag = open("flag.txt").read()
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from hashlib import sha256
cipher = AES.new(sha256(str(key).encode()).digest()[:16], AES.MODE_GCM, nonce=sha256(str(nonce).encode()).digest()[:16])

print(cipher.encrypt(pad(flag.encode(), 16)))