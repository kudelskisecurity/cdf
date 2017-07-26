#!/usr/bin/env python3

from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto import Random

import sys
import binascii

encrypt = False
decrypt = False

if len(sys.argv) == 4:
    encrypt = True
elif len(sys.argv) == 6:
    decrypt = True
else:
    print("FAIL: wrong arguments")
    sys.exit(1)

if encrypt:
    pk = RSA.construct((int(sys.argv[1], 16), int(sys.argv[2], 16)))
    message = bytes(sys.argv[3], 'utf-8')
    cipher = PKCS1_v1_5.new(pk)
    ciphertext = cipher.encrypt(message)
    print(ciphertext.hex())

if decrypt:
    ciphertext = binascii.unhexlify(sys.argv[5])
    # We construct the private key from the arguments P, Q, E, D :
    pky = RSA.construct(
        (int(sys.argv[1], 16) * int(sys.argv[2], 16), int(sys.argv[3], 16),
         int(sys.argv[4], 16), int(sys.argv[1], 16), int(sys.argv[2], 16)))

    cipher = PKCS1_v1_5.new(pky)
    sentinel = b'sentinel'  # just a sentinel since pycrypto wants one
    recovered = cipher.decrypt(ciphertext, sentinel)
    if recovered == sentinel:  # This should not be done in practice
        print("FAIL")
    else:
        print(recovered.decode('utf-8'))
