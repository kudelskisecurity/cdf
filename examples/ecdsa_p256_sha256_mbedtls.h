#include "mbedtls/asn1.h"
#include "mbedtls/config.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/entropy.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// convert a signature in ASN1 DER format into the R and S integers, as done by MBED in its veryfing method
static int read_asn1(const unsigned char* sig, size_t slen, mbedtls_mpi* r, mbedtls_mpi* s)
{
    int ret;
    unsigned char* p = (unsigned char*)sig;
    const unsigned char* end = sig + slen;
    size_t len;

    if ((ret = mbedtls_asn1_get_tag(&p, end, &len,
             MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE))
        != 0) {
        ret += MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        return ret;
    }

    if (p + len != end) {
        ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA + MBEDTLS_ERR_ASN1_LENGTH_MISMATCH;
        return ret;
    }

    if ((ret = mbedtls_asn1_get_mpi(&p, end, r)) != 0 || (ret = mbedtls_asn1_get_mpi(&p, end, s)) != 0) {
        ret += MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        return ret;
    }
    return ret;
}

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
