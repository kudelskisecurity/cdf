#include <inttypes.h>
#include <openssl/hmac.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int ac, char** av)
{

    EVP_MD* hash = (EVP_MD*)EVP_sha256();
    uint8_t out[32];
    char* kx = av[1];
    char* inx = av[2];

    size_t kxlen = strlen(kx); // nibbles
    size_t klen = kxlen / 2; // bytes
    size_t inxlen = strlen(inx);
    size_t inlen = inxlen / 2;

    uint8_t* k = (uint8_t*)malloc(klen);
    uint8_t* in = (uint8_t*)malloc(inlen);

    for (size_t i = 0; i < klen; ++i) {
        sscanf(kx, "%2hhx", &k[i]);
        kx += 2;
    }

    for (size_t i = 0; i < inlen; ++i) {
        sscanf(inx, "%2hhx", &in[i]);
        inx += 2;
    }

    unsigned int outlen;
    HMAC(hash, k, klen, in, inlen, out, &outlen);

    if (outlen != 32) {
        printf("WTF\n");
    }

    free(k);
    free(in);

    for (size_t i = 0; i < 32; ++i)
        printf("%02x", out[i]);
    printf("\n");

    return 0;
}
