#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "openssl/bn.h"
#include "openssl/ec.h"
#include "openssl/ecdsa.h"
#include "openssl/obj_mac.h" // for NID_secp192k1
#include "openssl/sha.h"

#define HASH_SIZE 32
#define ECPARAMS NID_X9_62_prime256v1

void unhex(char* hex, unsigned char* in, size_t ilen)
{
    for (size_t i = 0; i < ilen; ++i) {
        sscanf(hex, "%2hhx", &in[i]);
        hex += 2;
    }
}

void printBN(BIGNUM *r)
{
    char* out = BN_bn2hex(r);
    const char *padding="0000000000000000000000000000000000000000000000000000000000000000";
    int padLen1 = 64 - strlen(out);
    if(padLen1 < 0) padLen1 = 0;
    printf("%*.*s%s\n", padLen1, padLen1, padding, out);
    OPENSSL_free(out);
}

int main(int argc, char* argv[])
{

    // Our args
    size_t blen = 0;

    int success = 0;
    uint8_t* hash;
    int signing;
    int hash_provided = 0;

    // To handle the flags:
    int c;
    extern char* optarg;
    extern int optind, optopt, opterr;
    while ((c = getopt(argc, argv, ":h:")) != -1) {
        switch (c) {
            case 'h':
                hash = (uint8_t*)malloc(strlen(optarg) / 2);
                blen = strlen(optarg) / 2;
                unhex(optarg, hash, blen); // unsafe for the memory, if optarg is bigger than hash!
                hash_provided = 1;
                break;
            case ':':
                // -h without hash
                printf("-h without blen");
                success = -1;
                break;
            case '?':
                printf("unknown arg %c\n", optopt);
                success = -1;
                break;
        }
    }

    if (argc - optind == 4) {
        signing = 1;
    } else if (argc - optind == 5) {
        signing = 0;
    } else {
        printf("usage: \t%s X, Y, D, M\nor \t%s X, Y, R, S, M\n", argv[0], argv[0]);
        return -1;
    }

    // Handle the hash value
    if (hash_provided != 1) { // then we must hash our message, flag -h not provided
        size_t tlen = strlen(argv[argc - 1]) / 2; // since it is an hexa string
        uint8_t* nhex = (uint8_t*)malloc(tlen);
        unhex(argv[argc - 1], nhex, tlen); // we convert from hex to bin
        hash = (uint8_t*)malloc(HASH_SIZE);
        SHA256(nhex, tlen, hash);
        free(nhex);
        blen = HASH_SIZE;
    }
    // OpenSSL stuff:
    int ret;
    ECDSA_SIG* sig;
    EC_KEY* eckey;

    BIGNUM* x = BN_new();
    BIGNUM* y = BN_new();

    BIGNUM* d = BN_new();

    BN_hex2bn(&x, argv[optind]);
    BN_hex2bn(&y, argv[optind + 1]);

    eckey = EC_KEY_new_by_curve_name(ECPARAMS);
    if (eckey == NULL) {
        printf("Failed to create new EC Key for this curve.\n");
        return -1;
    }

    if (!EC_KEY_set_public_key_affine_coordinates(eckey, x, y)) {
        printf("Failed to create set EC Key with the provided args.\n");
        return -1;
    }

    if (signing) {
        BN_hex2bn(&d, argv[optind + 2]);
        EC_KEY_set_private_key(eckey, d);

        sig = ECDSA_do_sign(hash, blen, eckey); // this return a newly initialized ECDSA_SIG
        if (sig == NULL) {
            printf("Failed to sign with those args.\n");
            return -1;
        }
        printBN(sig->r);
        printBN(sig->s);

    } else {
        sig = ECDSA_SIG_new();
        BN_hex2bn(&sig->r, argv[optind + 2]);
        BN_hex2bn(&sig->s, argv[optind + 3]);
        ret = ECDSA_do_verify(hash, blen, sig, eckey);
        if (ret == -1) {
            /* error */
            printf(" failure ECDSA_do_verify returned -1");
            success = -1;
        } else if (ret == 0) /* then the signature is wrong */
        {
            printf("False\n");
        } else /* ret == 1, so signature is okay */
        {
            printf("True\n");
        }
    }

    ECDSA_SIG_free(sig);
    EC_KEY_free(eckey);
    BN_free(x);
    BN_free(y);
    BN_free(d);

    free(hash);

    return success;
}
