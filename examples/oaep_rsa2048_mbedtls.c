#include "mbedtls/asn1.h"
#include "mbedtls/config.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/rsa.h"
#include "mbedtls/entropy.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PADDING_TYPE MBEDTLS_RSA_PKCS_V21
#define HASH_TYPE MBEDTLS_MD_SHA1

// convert a char to its binary representation, from hex
static int toBin(unsigned char val)
{
    if (val >= '0' && val <= '9')
        return val - '0';
    else if (val >= 'a' && val <= 'f')
        return val - 'a' + 10;
    else if (val >= 'A' && val <= 'F')
        return val - 'A' + 10;
    else
        assert(0);
    return -1;
}

// unhexlify a given string
static int unhex(unsigned char* out, const char* in)
{
    unsigned char a, b;
    int len = strlen(in) / 2;
    assert(strlen(in) == 2 * len);

    while (*in != 0) {
        a = *in++;
        b = *in++;
        *out++ = (toBin(a) << 4) | toBin(b);
    }
    return len;
}

// print a big integer to the stdout
static void dump_mpi(const mbedtls_mpi* d)
{
    mbedtls_mpi_write_file(NULL, d, 16, NULL);
}

int main(int argc, char* argv[])
{
    // Parsing argument:
    int ret = 1;
    int encrypt = 0;
    if (argc == 4) {
        encrypt =  1;
    } else if (argc != 6) {
        printf("usage: \t%s N,E, Plain\nor \t%s P, Q, E, D, Cipher\n", argv[0], argv[0]);
        return -1;
    }
    // the MbedTLS variables:
    mbedtls_rsa_context rsa_ctx;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char* pers = "rsa";

    // we must unhexlify the data:
    const char* str = argv[argc - 1];
    unsigned char* msg = (unsigned char*)malloc(strlen(str) / 2 * sizeof(unsigned char));
    size_t mlen;
    mlen = unhex(msg, str);

    // We initialize all the variables:
    mbedtls_rsa_init(&rsa_ctx, PADDING_TYPE, HASH_TYPE);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);


    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                    (const unsigned char*)pers,
                    strlen(pers)))
            != 0) {
        printf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
        goto exit;
    }

    size_t* olen = (size_t*)malloc(sizeof(size_t));

    if (encrypt) {
        // We set our variables using the args
        if ((ret = mbedtls_mpi_read_string(&rsa_ctx.N, 16, argv[1])) != 0) {
            printf(" failed\n  ! mbedtls_mpi_read_string returned -0x%02X\n", -ret);
            goto exit;
        }
        rsa_ctx.len = ( mbedtls_mpi_bitlen( &rsa_ctx.N  ) + 7  ) >> 3;
        if ((ret = mbedtls_mpi_read_string(&rsa_ctx.E, 16, argv[2])) != 0) {
            printf(" failed\n  ! mbedtls_mpi_read_string returned -0x%02X\n", -ret);
            goto exit;
        }

        if ((ret = mbedtls_rsa_check_pubkey(&rsa_ctx)) != 0){
            printf(" failed\n  ! mbedtls_rsa_check_pubkey returned %d\n", ret);
            goto exit;
        }

        // The output buffer must be as large as the size of ctx->N
        unsigned char output[mbedtls_mpi_size(&rsa_ctx.N)];
        if ((ret = mbedtls_rsa_rsaes_oaep_encrypt(&rsa_ctx, 
                        mbedtls_ctr_drbg_random, &ctr_drbg,
                        MBEDTLS_RSA_PUBLIC, NULL, 0,
                        mlen, msg, output )) != 0) {
            printf(" failed\n  ! mbedtls_rsa_rsaes_oaep_encrypt returned -%x\n", -ret);
            goto exit;
        } 
        for (unsigned long i = 0; i < rsa_ctx.len; ++i)
            printf("%02x", output[i]);
        printf("\n");
    } else { // we are not encrypting, so we are decrypting

        // We set our variables using the args
        if ((ret = mbedtls_mpi_read_string(&rsa_ctx.P, 16, argv[1])) != 0) {
            printf(" failed\n  ! mbedtls_mpi_read_string returned -0x%02X\n", -ret);
            goto exit;
        }
        if ((ret = mbedtls_mpi_read_string(&rsa_ctx.Q, 16, argv[2])) != 0) {
            printf(" failed\n  ! mbedtls_mpi_read_string returned -0x%02X\n", -ret);
            goto exit;
        }

        if ((ret = mbedtls_mpi_read_string(&rsa_ctx.E, 16, argv[3])) != 0) {
            printf(" failed\n  ! mbedtls_mpi_read_string returned -0x%02X\n", -ret);
            goto exit;
        }
        if ((ret = mbedtls_mpi_read_string(&rsa_ctx.D, 16, argv[4])) != 0) {
            printf(" failed\n  ! mbedtls_mpi_read_string returned -0x%02X\n", -ret);
            goto exit;
        }

        // we set the rest
        if ((ret =  mbedtls_mpi_mul_mpi( &rsa_ctx.N, &rsa_ctx.P, &rsa_ctx.Q )) != 0 ) {
            printf(" failed\n  ! mbedtls_mpi_mul_mpi returned %X\n", -ret);
            goto exit;
        }
        rsa_ctx.len = ( mbedtls_mpi_bitlen( &rsa_ctx.N  ) + 7  ) >> 3;

        // If we want to build a priv key in mbedtls, we must provide those:
        mbedtls_mpi P1, Q1;
        mbedtls_mpi_init( &P1  ); mbedtls_mpi_init( &Q1  ); 
        mbedtls_mpi_sub_int( &P1, &rsa_ctx.P, 1 );
        mbedtls_mpi_sub_int( &Q1, &rsa_ctx.Q, 1 );

        mbedtls_mpi_mod_mpi( &rsa_ctx.DP, &rsa_ctx.D, &P1 );
        mbedtls_mpi_mod_mpi( &rsa_ctx.DQ, &rsa_ctx.D, &Q1 );
        mbedtls_mpi_inv_mod( &rsa_ctx.QP, &rsa_ctx.Q, &rsa_ctx.P );

        if ((ret = mbedtls_rsa_check_privkey(&rsa_ctx)) != 0){
            printf(" failed\n  ! mbedtls_rsa_check_privkey returned %X\n", -ret);
            ret = EXIT_FAILURE;
            goto exit;
        }

        // The output buffer must be as large as the size of ctx->N
        unsigned char output[mbedtls_mpi_size(&rsa_ctx.N)];
        if ((ret = mbedtls_rsa_rsaes_oaep_decrypt(&rsa_ctx, 
                        mbedtls_ctr_drbg_random, &ctr_drbg,
                        MBEDTLS_RSA_PRIVATE, NULL, 0, // label = NULL and label_len = 0
                        olen, msg, output, rsa_ctx.len)) != 0) {

            printf(" failed\n  ! mbedtls_rsa_rsaes_oaep_decrypt returned %X\n", -ret);
            ret = EXIT_FAILURE;
            goto exit;
        } 
        for (size_t i = 0; i < *olen; ++i)
            printf("%02x", output[i]);
        printf("\n");
    }

exit:
    mbedtls_rsa_free(&rsa_ctx);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    free(msg);
    free(olen);
    return (ret);
}
