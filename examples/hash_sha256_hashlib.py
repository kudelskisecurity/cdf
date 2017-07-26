#!/usr/bin/env python3

from hashlib import sha256
import sys
import binascii

message = binascii.unhexlify(sys.argv[1])
hashed = sha256(message).hexdigest()

print(hashed)
