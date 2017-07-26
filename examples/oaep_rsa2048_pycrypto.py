#!/usr/bin/env python3

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

import sys
import binascii

encrypt = False
decrypt = False

if len(sys.argv) == 4:
    encrypt = True
elif len(sys.argv) == 6:
    decrypt = True
else:
    print("FAIL")
    sys.exit(1)

if encrypt:
    pk = RSA.construct((int(sys.argv[1], 16), int(sys.argv[2], 16)))
    message = binascii.unhexlify(sys.argv[3])
    cipher = PKCS1_OAEP.new(pk)
    ciphertext = cipher.encrypt(message)

    print(ciphertext.hex())

if decrypt:
    ciphertext = binascii.unhexlify(sys.argv[5])
    pky = RSA.construct(
        (int(sys.argv[1], 16) * int(sys.argv[2], 16), int(sys.argv[3], 16),
         int(sys.argv[4], 16), int(sys.argv[1], 16), int(sys.argv[2], 16)))
    cipher = PKCS1_OAEP.new(pky)
    recovered = cipher.decrypt(ciphertext)
    print(recovered.hex())
