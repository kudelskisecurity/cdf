#!/usr/bin/env python3

import blake2new
import sys
import binascii

message = binascii.unhexlify(sys.argv[1])
hashed = blake2new.BLAKE2s(message).hexdigest()

print(hashed)
