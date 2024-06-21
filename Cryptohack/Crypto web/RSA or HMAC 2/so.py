from Crypto.Signature.pkcs1_15 import _EMSA_PKCS1_V1_5_ENCODE
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Util.number import long_to_bytes, bytes_to_long
import jwt_patched as jwt
import json
import base64
import gmpy2

import jwt 

with open("rsa-or-hmac-2-private.pem", "rb") as f:
    PRIVATE_KEY = f.read()
    
with open("rsa-or-hmac-2-public.pem", "rb") as f:
    PUBLIC_KEY = f.read()

FLAG = "KCSC{1234374658969508964273euh_3857238_}"

def authorise(token):
    try:
        decoded = jwt.decode(token, PUBLIC_KEY, algorithms=['HS256', 'RS256'])
    except Exception as e:
        return {"error": str(e)}

    if "admin" in decoded and decoded["admin"]:
        return {"response": f"Welcome admin, here is your flag: {FLAG}"}
    elif "username" in decoded:
        return {"response": f"Welcome {decoded['username']}"}
    else:
        return {"error": "There is something wrong with your session, goodbye"}

def create_session(username):
    encoded = jwt.encode({'username': username, 'admin': True}, PUBLIC_KEY, algorithm='HS256')
    return encoded




def create_session(username):
    encoded = jwt.encode({'username': username, 'admin': True}, PUBLIC_KEY, algorithm='HS256')
    return encoded

session = create_session("username")
print(session)

print(authorise(session))


# with open("pub.pem", "r") as f:
#     PUBLIC_KEY = f.read()