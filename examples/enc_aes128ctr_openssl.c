#include <inttypes.h>
#include <openssl/aes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int ac, char** av)
{
    uint8_t iv[16], ecount[16];
    char* hex = av[1];
    char* hkey;
    size_t klen = 16;
    if (ac > 2) {
        hkey = hex;
        hex = av[2];
        klen = strlen(hkey) / 2;
    }

    size_t xlen = strlen(hex);
    size_t blen = xlen / 2;

    memset(iv, 0, 16);
    memset(ecount, 0, 16);

    uint8_t* in = (uint8_t*)malloc(blen);
    uint8_t* out = (uint8_t*)malloc(blen);
    uint8_t* key = (uint8_t*)calloc(klen, 1);

    if (!in || !out || !key) {
        printf("FAIL!\n");
        return 1;
    }

    for (size_t i = 0; i < blen; ++i) {
        sscanf(hex, "%2hhx", &in[i]);
        hex += 2;
    }

    if (ac > 2) {
        for (size_t i = 0; i < klen; ++i) {
            sscanf(hkey, "%2hhx", &key[i]);
            hkey += 2;
        }
    }

    // aes-encrypt
    AES_KEY aes_key;

    int ret = AES_set_encrypt_key(key, klen * 8, &aes_key);
    if (ret) {
        printf("FAILED %d\n", ret);
        return 1;
    }

    unsigned int num = 0;

    AES_ctr128_encrypt(in, out, blen, &aes_key, iv, ecount, &num);

    for (size_t i = 0; i < blen; ++i)
        printf("%02x", out[i]);
    printf("\n");

    free(in);
    free(out);
    free(key);

    return 0;
}
