#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "openssl/bn.h"
#include "openssl/sha.h"
#include "openssl/rsa.h"
#include "openssl/evp.h"

void unhex(char* hex, unsigned char* data, size_t ilen)
{
    for (size_t i = 0; i < ilen; ++i) {
        sscanf(hex, "%2hhx", &data[i]);
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
    int encrypt;
    int success = 0;

    if (argc == 4) {
        encrypt = 1;
    } else if (argc - optind == 5) {
        encrypt = 0;
    } else {
        printf("usage: \t%s X, Y, D, M\nor \t%s X, Y, R, S, M\n", argv[0], argv[0]);
        return -1;
    }

    // OpenSSL stuff:
    int ret;

    RSA *r = NULL;
    r = RSA_new();

    char* str = argv[argc - 1];
    unsigned char* msg = (unsigned char*)malloc(strlen(str) / 2 * sizeof(unsigned char));
    size_t mlen = strlen(str)/2;

    unhex(str, msg, mlen); 

    unsigned char* to; 

    if (encrypt) {
        // public key setup
        BN_hex2bn(&r->n, argv[1]);
        BN_hex2bn(&r->e, argv[2]);

        to = (unsigned char*)malloc(RSA_size(r));

        ret = RSA_public_encrypt(mlen, msg, to, r, RSA_PKCS1_OAEP_PADDING);
        if (ret <= 0) {
            printf("Failed to encrypt with those args.\n");
            return -1;
        } else {
            for (int i = 0; i < ret; ++i)
                printf("%02x", to[i]);
            printf("\n");
        }

    } else {
        BN_CTX * tmp_bn;
        tmp_bn = BN_CTX_new();
        // private key setup
        BN_hex2bn(&r->p, argv[1]);
        BN_hex2bn(&r->q, argv[2]);
        BN_hex2bn(&r->e, argv[3]);
        BN_hex2bn(&r->d, argv[4]);
        // compute n 
        r->n = BN_new();
        BN_mul(r->n, r->p ,r->q,tmp_bn);

        BN_CTX_free(tmp_bn);

        to = (unsigned char*)malloc(RSA_size(r));

        ret = RSA_check_key(r);
        if (ret != 1){
            /* error */
            printf(" failure RSA_check_key returned %d", ret);
            success = -1;
        }

        ret = RSA_private_decrypt(mlen,  msg, to, r, RSA_PKCS1_OAEP_PADDING );
        if (ret <= 0) {
            /* error */
            printf(" failure RSA_private_decrypt returned %d", ret);
            success = -1;
        } else {
            for (int i = 0; i < ret; ++i)
                printf("%02x", to[i]);
            printf("\n");
        }
    }

    RSA_free(r);

    return success;
}
