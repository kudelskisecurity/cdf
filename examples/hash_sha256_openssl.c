#include <inttypes.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int ac, char** av)
{
    SHA256_CTX ctx;
    uint8_t out[32];
    char* hex = av[1];
    size_t xlen = strlen(av[1]);
    size_t blen = xlen / 2;

    uint8_t* in = (uint8_t*)malloc(blen);

    for (size_t i = 0; i < blen; ++i) {
        sscanf(hex, "%2hhx", &in[i]);
        hex += 2;
    }

    SHA256_Init(&ctx);
    SHA256_Update(&ctx, in, blen);
    SHA256_Final(out, &ctx);

    free(in);

    for (size_t i = 0; i < 32; ++i)
        printf("%02x", out[i]);
    printf("\n");

    return 0;
}
