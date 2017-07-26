#!/usr/bin/env python3

from Crypto.Cipher import AES
import Crypto.Util.Counter
import sys
import binascii

message = binascii.unhexlify(sys.argv[1])
key = '\x00' * 16
if len(sys.argv) > 2:
    temp = binascii.unhexlify(sys.argv[2])
    key = message
    message = temp

iv = b'00' * 16

ctr = Crypto.Util.Counter.new(128, initial_value=int(iv, 16))

aes = AES.new(key, AES.MODE_CTR, counter=ctr)
encrypted = aes.encrypt(message)

print(encrypted.hex())
