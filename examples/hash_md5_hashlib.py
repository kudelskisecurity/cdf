#!/usr/bin/env python3

from hashlib import md5
import sys
import binascii

message = binascii.unhexlify(sys.argv[1])
hashed = md5(message).hexdigest()

print(hashed)
