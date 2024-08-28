
- Chall này mình có tìm được hướng làm trong lúc thi tuy nhiên mình không biết nó cụ thể là phương pháp nào:)
- Sau thi thì mình có tham khảo wu thì biết đây là `nonce reuse attack`.
- Đầu tiên ta cần tính toán và gửi 2 ct vào sao cho `nouce` của chúng giống nhau để làm được điều này thì ta phải tính toán dựa trên y đã cho.

```python
def polynomial_evaluation(coefficients, x):
	at_x = 0
	for i in range(len(coefficients)):
		at_x += coefficients[i] * (x ** i)
		at_x = at_x % p
	return at_x
```
- Giải phương trình $f(x)= \sum_{0}^{15}{cof_i*x^i}$ ta có được x để khi gửi 2 ct thì nhận được enc có cùng nonce.
- Khi đó ta dùng nonce reuse attack.
- Dưới đây là code mình tham khảo từ anh Quốc:(.

```Python
from pwn import *
from Crypto.Util.number import *


def polynomial_evaluation(coefficients, x):
	at_x = 0
	for i in range(len(coefficients)):
		at_x += coefficients[i] * (x ** i)
	return at_x
def g(ct, r, s):
    count = (len(ct) + 15) // 16
    a = 0
    for i in range(count):
        n = ct[i*16:(i+1)*16] + b'\x01'
        n = int.from_bytes(n, 'little')
        a += n
        a = a*r % p
    a = (a+s) % 2**128
    return a
def convert(msg): 
    return msg + b'\x00'*(16 -(len(msg)%16)) + long_to_bytes(0 , 8 )[::-1] + long_to_bytes(len(msg), 8)[::-1]

for i in range (100):
    r= remote('157.15.86.73', '1305')
    r.recvuntil(b'p = ')
    p= int(r.recvline(b''))
    r.recvuntil(b'')
    r.sendlineafter(b'option:', b'1')
    r.recvuntil(b'ents = ')
    coefficients= eval(r.recvline().strip().decode())
    P= PolynomialRing(GF(p), 'x')
    x= P.gen()
    f= polynomial_evaluation(coefficients, x)
    a= f.roots()
    print(f'{a= }')
    if len(a)== 0:
        r.close()
        continue
    x_1= a[0][0]
    r.recvuntil(b'')
    r.sendlineafter(b'message: ', b'a'* 16)
    r.sendlineafter(b'x: ', str(x_1).encode())
    sign1= r.recvline(b'').decode()
    nonce1 = bytes.fromhex(sign1[:12])
    ct1 = bytes.fromhex(sign1[12:-16])
    ct1= convert(ct1)
    tag1 = bytes.fromhex(sign1[-16:])
    r.sendlineafter(b'option:', b'1')
    r.recvuntil(b'ents = ')
    coefficients= eval(r.recvline().strip().decode())
    f= polynomial_evaluation(coefficients, x)
    b= f.roots()
    if len(b)== 0:
        r.close()   
        continue
    x_2= b[0][0]
    r.recvuntil(b'')
    r.sendlineafter(b'message: ', b'a'* 15+ b'x')
    r.sendlineafter(b'x: ', str(x_2).encode())
    sign2= r.recvline(b'').decode()
    nonce2 = bytes.fromhex(sign2[:12])
    ct2 = bytes.fromhex(sign2[12:-16])
    ct3= convert(ct2)
    tag2 = bytes.fromhex(sign2[-16:])

    p = 2**130 - 5
    PR = PolynomialRing(GF(p), 't')
    t = PR.gen()
    count = (len(ct1) + 15)//16
    tag1 = int.from_bytes(tag1, 'little')
    tag2 = int.from_bytes(tag2, 'little')
    a1 = 0
    for i in range(count):
        n = ct1[i*16:(i+1)*16] + b'\x01'
        n = int.from_bytes(n, 'little')
        a1 += n
        a1 = a1*t

    count = (len(ct3) + 15)//16
    a2 = 0
    for i in range(count):
        n = ct3[i*16:(i+1)*16] + b'\x01'
        n = int.from_bytes(n, 'little')
        a2 += n
        a2 = a2*t

    rs = set()
    for k in range(-4, 5):
        roots = (a1 - a2 - (tag1 - tag2) + k * 2**128).roots()
        for root in roots:
            rs.add(int(root[0]))

    pos_r = []
    for t in rs:
        if t.bit_length() <= 128:
            pos_r.append(t)

    fake_pkt = b'A'*15 + b'B'
    pkt = b'give me the flag'
    
    keysteam = xor(ct2, pkt)
    ct = xor(fake_pkt, keysteam)[:len(pkt)]

    print('possible value: ', len(pos_r))
    for t in pos_r:
        try:
            s = (tag1 - int(a1(t))) % 2**128
            assert g(ct1, t, s) == tag1
            assert g(ct3, t, s) == tag2
            tag = long_to_bytes(g(convert(ct), t, s), 16)[::-1]
            payload = nonce1 + ct + tag
            
            print('payload = ', payload.hex())
            r.sendlineafter(b'Enter option: ', b'2')
            r.sendlineafter(b'Enter encrypted message: ', payload.hex().encode())
            flag = r.recvline().strip().decode()
            if 'KMA' in flag:
                print(flag)
        except:
            pass
    r.interactive()
```
