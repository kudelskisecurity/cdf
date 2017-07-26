#!/usr/bin/env python3

from Crypto.Random import random
from Crypto.PublicKey import DSA
from Crypto.Hash import SHA256
import sys
import binascii

if len(sys.argv) == 8:
    signing = False
elif len(sys.argv) == 7:
    signing = True
else:
    print("Please provide P, Q, G, Y, X, Msg or P, Q, G, Y, R, S, Msg as arguments", len(sys.argv))
    sys.exit(1)

q = int(sys.argv[2], 16)
p = int(sys.argv[1], 16)
g =int(sys.argv[3], 16)

pub_k = int(sys.argv[4], 16)

message = binascii.unhexlify(sys.argv.pop())
if signing:
    priv_k = int(sys.argv[5], 16)
    params = ( pub_k, g, p, q, priv_k)
else:
    params = ( pub_k, g, p, q )
    r = int(sys.argv[5], 16)
    s = int(sys.argv[6], 16)
    signature = (r, s)

key = DSA.construct(params)

hashed = SHA256.new(message).digest()
hlen = int((q.bit_length() + 7) / 8)
k = random.StrongRandom().randint(1,key.q-1)

if signing:
    sign = key.sign(hashed[:hlen], k)
    print(format(sign[0],'x').zfill(40))
    print(format(sign[1],'x').zfill(40))
else:
    if key.verify(hashed[:hlen], signature): 
        print("true")
    else:
        print("false")
