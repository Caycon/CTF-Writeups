# Phân tích
- Chall sử dụng chuẩn PKCS#1 v1.5 với RSA có `e` nhỏ `e = 3`. Ta sẽ `signature forgery.
- Ta sử dụng Bleichenbacher's attack.
- Ở đây mình có 1 chall rất giống chall này [BBGun06](https://www.hackthebox.com/blog/business-ctf-2022-write-up-bbgun06). 

```python
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.PublicKey import RSA
from hashlib import sha1
from gmpy2 import iroot
from pwn import *
import re
from base64 import b64encode

ASN1 = b'\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14'

def forge_signature(message, n, e):
    # Compute key length in bits
    key_length = n.bit_length()
    block = b'\x00\x01\xff\x00' + ASN1  + sha1(message).digest()+ (b'\xff' * (key_length // 8 - len(ASN1) - len(sha1(message).digest()) - 4))  
    
    # Convert the block to an integer
    pre_encryption = bytes_to_long(block)
    
    # Compute the cube root of the pre-encryption integer
    forged_sig = iroot(pre_encryption, e)[0]
    
    return long_to_bytes(forged_sig)

def verify(message, signature, n, e):
    keylength = len(long_to_bytes(n))
    encrypted = bytes_to_long(signature)
    decrypted = pow(encrypted, e, n)
    clearsig = decrypted.to_bytes(keylength, "big")

    r_pattern = re.compile(re.escape(b'\x00\x01\xff\x00'+ ASN1 + sha1(message).digest() + b'\x00' * (keylength - len(ASN1) - len(sha1(message).digest()) - 4)), re.DOTALL)
    
    match = r_pattern.match(clearsig)

    return match is not None

def pwn():
    r.recvuntil(b'Modulus = ')
    modulus_str = r.recvline().strip().decode()
    n = int(modulus_str)
    e = 3
    user = b'a' * 15
    r.sendlineafter(b'verify:', user)
    forged_signature = forge_signature(user, n, e)
    
    # Base64 encode the forged signature
    forged_signature_b64 = b64encode(forged_signature)
    print(forged_signature_b64.decode())
    
    r.sendlineafter(b'signature:', forged_signature_b64)
    response = r.recvline()
    print(response.decode())

if __name__ == "__main__":
    for i in range(100):
        r = remote('157.15.86.73', 2003)
        r.recvuntil(b'Hash:')
        x = r.recvline().strip().decode()
        if x == 'SHA-1':
            pwn()
            break
```
