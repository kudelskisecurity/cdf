#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "openssl/bn.h"
#include "openssl/dsa.h"
#include "openssl/engine.h"
#include "openssl/sha.h"

#define HASH_SIZE 32

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
        const char *padding="00000000000000000000000000000000000000000";
        int padLen1 = 40 - strlen(out);
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
            printf("-h without hash");
            success = -1;
            break;
        case '?':
            printf("unknown arg %c\n", optopt);
            success = -1;
            break;
        }
    }

    if (argc - optind == 6) {
        signing = 1;
    } else if (argc - optind == 7) {
        signing = 0;
    } else {
        printf("usage: \t%s P, Q, G, Y, X, Msg\nor \t%s P, Q, G, Y, R, S, Msg\n", argv[0], argv[0]);
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
    DSA_SIG* sig;
    DSA* key = DSA_new();

    BIGNUM* x = BN_new();
    BIGNUM* y = BN_new();

    BIGNUM* p = BN_new();
    BIGNUM* q = BN_new();
    BIGNUM* g = BN_new();

    if (!BN_hex2bn(&p, argv[optind])) {
        printf("Problem while decoding p:\n%s\n", argv[optind]);
        return -1;
    }

    if (!BN_hex2bn(&q, argv[optind + 1])) {
        printf("Problem while decoding q:\n%s\n", argv[optind + 1]);
        return -1;
    }
    if (!BN_hex2bn(&g, argv[optind + 2])) {
        printf("Problem while decoding g:\n%s\n", argv[optind + 2]);
        return -1;
    }
    if (!BN_hex2bn(&y, argv[optind + 3])) {
        printf("Problem while decoding y:\n%s\n", argv[optind + 3]);
        return -1;
    }

    key->p = BN_dup(p);
    key->q = BN_dup(q);
    key->g = BN_dup(g);
    key->pub_key = BN_dup(y);

    if (signing) {
        if (!BN_hex2bn(&x, argv[optind + 4])) {
            printf("Problem while decoding x:\n%s\n", argv[optind + 4]);
            return -1;
        }
        key->priv_key = BN_dup(x);

        sig = DSA_do_sign(hash, blen, key);
        if (sig == NULL) {
            printf("Failed to sign with those args.\n");
            return -1;
        }

        printBN(sig->r);
        printBN(sig->s);

    } else {
        sig = DSA_SIG_new();
        if (!BN_hex2bn(&sig->r, argv[optind + 4])) {
            printf("Problem while decoding r:\n%s\n", argv[optind + 4]);
            return -1;
        }
        if (!BN_hex2bn(&sig->s, argv[optind + 5])) {
            printf("Problem while decoding s:\n%s\n", argv[optind + 5]);
            return -1;
        }
        key->priv_key = NULL; // since we are verifying
        ret = DSA_do_verify(hash, blen, sig, key);
        if (ret == -1) {
            /* error */
            printf(" failure DSA_do_verify returned -1");
            success = -1;
        } else if (ret == 0) /* then the signature is wrong */
        {
            printf("False\n");
        } else /* ret == 1, so signature is okay */
        {
            printf("True\n");
        }
    }

    DSA_SIG_free(sig);
    DSA_free(key);
    BN_free(x);
    BN_free(y);
    BN_free(p);
    BN_free(q);
    BN_free(g);

    free(hash);

    return success;
}
