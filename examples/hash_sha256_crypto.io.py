#!/usr/bin/env python3

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import sys
import binascii

message = sys.argv[1]

digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
tohash = binascii.unhexlify(message)
digest.update(tohash)
hashed = binascii.hexlify(digest.finalize())

print(str(hashed, 'utf-8'))
