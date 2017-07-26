#include "ecdsa_p256_sha256_mbedtls.h"

#define ECPARAMS MBEDTLS_ECP_DP_SECP256R1
#define HASH_TYPE MBEDTLS_MD_SHA256

int main(int argc, char* argv[])
{
    // Parsing argument:
    int c;
    int blen_tested = 0;
    int hash_provided = 0;
    unsigned char hash[MBEDTLS_MD_MAX_SIZE];
    memset(hash, 0, sizeof(hash));
    extern char* optarg;
    extern int optind, optopt, opterr;
    while ((c = getopt(argc, argv, ":h:")) != -1) {
        switch (c) {
        case 'h':
            unhex(hash, optarg); // unsafe for the memory, if optarg is bigger than hash!
            blen_tested = strlen(optarg) / 2;
            hash_provided = 1;
            break;
        case ':':
            // -h without hash length
            printf("-h without hash");
            break;
        case '?':
            printf("unknown arg %c\n", optopt);
            return -1;
        }
    }

    int ret = 1;
    int signing = 0;
    if (argc - optind == 4) {
        signing = 1;
    } else if (argc - optind == 5) {
        signing = 0;
    } else {
        printf("usage: \t%s X, Y, D, M\nor \t%s X, Y, R, S, M\n", argv[0], argv[0]);
        return -1;
    }
    // the MbedTLS variables:
    mbedtls_ecdsa_context signing_ctx;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char* pers = "ecdsa";
    ((void)argv);

    // we must unhexlify the data:
    const char* str = argv[argc - 1];
    unsigned char* msg = (unsigned char*)malloc(strlen(str) / 2 * sizeof(unsigned char));
    size_t mlen;
    mlen = unhex(msg, str);

    // We initialize all the variables:
    mbedtls_ecdsa_init(&signing_ctx);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    mbedtls_mpi used_r, used_s;
    mbedtls_mpi_init(&used_r);
    mbedtls_mpi_init(&used_s);

    mbedtls_ecp_keypair used_keypair;
    mbedtls_ecp_keypair_init(&used_keypair);

    mbedtls_mpi used_d;
    mbedtls_mpi_init(&used_d);

    mbedtls_ecp_group used_grp;
    mbedtls_ecp_group_init(&used_grp);

    mbedtls_ecp_point used_pt;
    mbedtls_ecp_point_init(&used_pt);
    mbedtls_mpi used_X, used_Y, used_Z;
    mbedtls_mpi_init(&used_X);
    mbedtls_mpi_init(&used_Y);
    mbedtls_mpi_init(&used_Z);

    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
             (const unsigned char*)pers,
             strlen(pers)))
        != 0) {
        printf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
        goto exit;
    }

    // Hashing the message:
    const mbedtls_md_info_t* md_info;
    md_info = mbedtls_md_info_from_type(HASH_TYPE);
    size_t hlen;
    hlen = mbedtls_md_get_size(md_info);
    if (hash_provided != 1) { // then we must hash our message, flag -h not provided
        mbedtls_md(md_info, (const unsigned char*)msg, mlen, hash);
    } else { // then we have set blen_tested at the same time we setted the hash
        hlen = blen_tested;
    }

    // We set our variables using the args
    if ((ret = mbedtls_mpi_read_string(&used_pt.X, 16, argv[optind])) != 0) {
        printf(" failed\n  ! mbedtls_mpi_read_string returned -0x%02X\n", -ret);
        goto exit;
    }
    if ((ret = mbedtls_mpi_read_string(&used_pt.Y, 16, argv[optind + 1])) != 0) {
        printf(" failed\n  ! mbedtls_mpi_read_string returned -0x%02X\n", -ret);
        goto exit;
    }
    // Z has to be 1 since it is not at infinity
    mbedtls_mpi_read_string(&used_pt.Z, 10, "1");

    if ((ret = mbedtls_ecp_copy(&used_keypair.Q, &used_pt)) != 0) {
        printf(" failed\n  ! mbedtls_mpi_copy returned -0x%02X\n", -ret);
        goto exit;
    }
    // we load the curve
    if (mbedtls_ecp_group_load(&used_grp, ECPARAMS) != 0) {
        printf(" failed\n  ! mbedtls_ecp_group_load returned -0x%02X\n", -ret);
        goto exit;
    }

    if (signing) {
        // we define the keypair's d using argv
        if ((ret = mbedtls_mpi_read_string(&used_d, 16, argv[optind + 2])) != 0) {
            printf(" failed\n  ! mbedtls_mpi_read_string returned -0x%02X\n", -ret);
            goto exit;
        }
        // And we compute the signature using the deterministic one
        if ((ret = mbedtls_ecdsa_sign_det(&used_grp, &used_r, &used_s, &used_d,
                 hash, hlen, MBEDTLS_MD_MD5))
            != 0) {
            printf(" failed\n  ! mbedtls_ecdsa_sign_det returned -0x%02X\n", -ret);
            goto exit;
        }

        // We could also use the write signature and ecdsa context,
        // which is–presumably–the recommended way to do it
        if ((ret = mbedtls_ecp_group_copy(&used_keypair.grp, &used_grp)) != 0) {
            printf(" failed\n  ! mbedtls_ecp_group_copy returned -0x%02X\n", -ret);
            goto exit;
        }
        if ((ret = mbedtls_mpi_copy(&used_keypair.d, &used_d)) != 0) {
            printf(" failed\n  ! mbedtls_mpi_copy returned -0x%02X\n", -ret);
            goto exit;
        }

        // we set our ecdsa context using the keypair we defined
        if (mbedtls_ecdsa_from_keypair(&signing_ctx, &used_keypair) != 0) {
            printf(" failed\n  ! mbedtls_ecdsa_from_keypair returned -0x%02X\n", -ret);
            goto exit;
        }

        unsigned char sig[512];
        memset(sig, 0, sizeof(sig));
        size_t sig_len;
        if ((ret = mbedtls_ecdsa_write_signature(&signing_ctx, MBEDTLS_MD_MD5,
                 hash, hlen, sig, &sig_len,
                 mbedtls_ctr_drbg_random, &ctr_drbg))
            != 0) {
            printf(" failed\n  ! ecdsa_write_signature returned -0x%02X\n", -ret);
            goto exit;
        }

        mbedtls_mpi rr, ss;
        mbedtls_mpi_init(&rr);
        mbedtls_mpi_init(&ss);
        read_asn1(sig, sig_len, &rr, &ss); // but then we must parse the ASN signature to get r & s
        assert(mbedtls_mpi_cmp_mpi(&rr, &used_r) == 0);
        assert(mbedtls_mpi_cmp_mpi(&ss, &used_s) == 0);

        //        printf(" R is:\n");
        dump_mpi(&used_r);
        //        printf(" S is:\n");
        dump_mpi(&used_s);

        mbedtls_mpi_free(&rr);
        mbedtls_mpi_free(&ss);

    } else { // we are not signing, so we are verifying the signature

        // Begining verification process

        mbedtls_mpi_read_string(&used_r, 16, argv[optind + 2]);
        mbedtls_mpi_read_string(&used_s, 16, argv[optind + 3]);

        ret = 0;

        if ((ret = mbedtls_ecdsa_verify(&used_grp, hash, hlen, &used_pt, &used_r, &used_s)) == 0) {
            printf("True\n");
        } else if (ret == MBEDTLS_ERR_ECP_VERIFY_FAILED) {
            printf("False\n");
        } else {
            printf(" failed\n  ! mbedtls_ecdsa_verify returned -0x%02X\n", -ret);
        }
    }

exit:
    mbedtls_ecdsa_free(&signing_ctx);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    mbedtls_ecp_group_free(&used_grp);
    mbedtls_ecp_keypair_free(&used_keypair);
    mbedtls_ecp_point_free(&used_pt);
    mbedtls_mpi_free(&used_X);
    mbedtls_mpi_free(&used_Y);
    mbedtls_mpi_free(&used_Z);
    mbedtls_mpi_free(&used_d);
    mbedtls_mpi_free(&used_r);
    mbedtls_mpi_free(&used_s);
    free(msg);

    return (ret);
}
