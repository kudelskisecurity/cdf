#include <inttypes.h>
#include <openssl/md5.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int ac, char** av)
{
    MD5_CTX ctx;
    uint8_t out[16];
    char* hex = av[1];
    size_t xlen = strlen(av[1]);
    size_t blen = xlen / 2;

    uint8_t* in = (uint8_t*)malloc(blen);

    for (size_t i = 0; i < blen; ++i) {
        sscanf(hex, "%2hhx", &in[i]);
        hex += 2;
    }

    MD5_Init(&ctx);
    MD5_Update(&ctx, in, blen);
    MD5_Final(out, &ctx);

    free(in);

    for (size_t i = 0; i < 16; ++i)
        printf("%02x", out[i]);
    printf("\n");

    return 0;
}
