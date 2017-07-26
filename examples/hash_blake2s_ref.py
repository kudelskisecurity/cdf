#!/usr/bin/env python3

import blake2ref
import sys
import binascii

message = binascii.unhexlify(sys.argv[1])
hashed = blake2ref.BLAKE2s(message).hexdigest()

print(hashed)
