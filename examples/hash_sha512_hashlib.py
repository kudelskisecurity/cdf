#!/usr/bin/env python3

from hashlib import sha512
import sys
import binascii

message = binascii.unhexlify(sys.argv[1])
hashed = sha512(message).hexdigest()

print(hashed)
