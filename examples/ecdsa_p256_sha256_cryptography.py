#!/usr/bin/env python3

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import utils
import sys
import binascii

curve = ec.SECP256R1()
algo = ec.ECDSA(hashes.SHA256())

if len(sys.argv) == 6:
    signing = False
elif len(sys.argv) == 5:
    signing = True
else:
    print("Please provide X, Y, R, S, Msg  or X, Y, D, Msg as arguments")
    sys.exit(1)

pubnum = ec.EllipticCurvePublicNumbers(
    int(sys.argv[1], 16), int(sys.argv[2], 16), curve)

# Msg is in last args:
data = binascii.unhexlify(sys.argv.pop())
if signing:
    privateKey = ec.EllipticCurvePrivateNumbers(int(
        sys.argv[3], 16), pubnum).private_key(default_backend())
    signer = privateKey.signer(algo)
    signer.update(data)
    signature = signer.finalize()
    (r, s) = utils.decode_dss_signature(signature)
    print(format(r, 'x'))
    print(format(s, 'x'))
else:
    public_key = pubnum.public_key(default_backend())
    signature = utils.encode_dss_signature(
        int(sys.argv[3], 16), int(sys.argv[4], 16))
    verifier = public_key.verifier(signature, algo)
    verifier.update(data)
    print(verifier.verify())
