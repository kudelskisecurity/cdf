#!/usr/bin/env python3

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding,rsa

import binascii, sys

# Determination of use case based on arguments provided
if len(sys.argv) == 4:
    encrypting = True
    lab = None
elif len(sys.argv) == 6:
    encrypting = False
    lab = None
elif len(sys.argv) == 5:
    encrypting = True
    lab = binascii.unhexlify(sys.argv[4])
elif len(sys.argv) == 7:
    encrypting = False
    lab = binascii.unhexlify(sys.argv[6])
else:
    print("FAIL")
    sys.exit(1)

# Parsing of the cmd line arguments
if encrypting:
    N = int(sys.argv[1], 16)
    e = int(sys.argv[2], 16)
    message = binascii.unhexlify(sys.argv[3])
else:
    P1 = int(sys.argv[1], 16)
    P2 = int(sys.argv[2], 16)
    e = int(sys.argv[3], 16)
    d = int(sys.argv[4], 16)
    message = binascii.unhexlify(sys.argv[5])

# Setup of the keys
if encrypting:
    pk = rsa.RSAPublicNumbers(e, N).public_key(default_backend())
else:
    pky = rsa.RSAPrivateNumbers(
        public_numbers=rsa.RSAPublicNumbers(e, P1*P2),
        p=P1,
        q=P2,
        d=d,
        dmp1=rsa.rsa_crt_dmp1(d, P1),
        dmq1=rsa.rsa_crt_dmq1(d, P2),
        iqmp=rsa.rsa_crt_iqmp(P1, P2)).private_key(default_backend())

# Actual encryption/decryption
if encrypting:   
    ciphertext = pk.encrypt(
        message,    
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=lab))
    print(ciphertext.hex())
else:
    plaintext = pky.decrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=lab))
    print(plaintext.hex())
