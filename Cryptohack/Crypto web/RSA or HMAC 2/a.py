from Crypto.PublicKey import RSA
import jwt_patched as jwt
from pwn import *
import requests

n = 30119723976045246500887959920897642376905514522104705876695572516818975656665827754462226597973931127004963194508794779495518118035029841228002850562126612806174354282950756669656076190799693066363785733231859172664786298352294594850108982261525326147060353679479844558827458650965802914077525964824412575118501773357860374735206849817271524812002047307305597712628593230518376740507962518305824812671107459660525177087958778694060270468673690931325503094560625544374011735643694318730778241846282742819834483180624645324880062782719575587058519516842316778261924794437716972651884728674806670910304714203419102131413
e = 65537


pubkey = RSA.construct((n, e)).export_key("PEM").decode()
print(pubkey)

def authorise(token):
    return requests.get(
        f"https://web.cryptohack.org/rsa-or-hmac-2/authorise/{token}/"
    ).json()

with open('pub.pem', 'r') as f:
    PUBLIC_KEY= f.read()

PUBLIC_KEY = "\n".join(PUBLIC_KEY.splitlines())
PUBLIC_KEY = PUBLIC_KEY.encode() + b'\n'

print(PUBLIC_KEY)

def create_session(username):
    encoded = jwt.encode({'username': username, 'admin': True}, PUBLIC_KEY, algorithm='HS256')
    return {"session": encoded}

session = create_session('qvinhprolol')
print(session)

