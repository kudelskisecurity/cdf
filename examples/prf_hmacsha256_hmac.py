#!/usr/bin/env python3

from hashlib import sha256
import binascii
import hmac
import sys

key = binascii.unhexlify(sys.argv[1])
message = binascii.unhexlify(sys.argv[2])

hm = hmac.new(key, message, digestmod=sha256)
mac = hm.hexdigest()

print(mac)
