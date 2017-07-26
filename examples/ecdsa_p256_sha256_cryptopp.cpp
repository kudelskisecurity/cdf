#include <cryptopp/cryptlib.h>
#include <cryptopp/files.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/osrng.h>
#include <cryptopp/sha.h>
#include <cryptopp/eccrypto.h>
#include <cryptopp/oids.h>
#include <cryptopp/secblock.h>

#include <iomanip>
#include <iostream>
#include <string>
using std::string;
using std::cout;
using std::cerr;
using std::endl;

// for optget:
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

using CryptoPP::AutoSeededRandomPool;
using CryptoPP::AES;
using CryptoPP::Integer;
using CryptoPP::SHA256;
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;
using CryptoPP::StringSource;
using CryptoPP::StringSink;
using CryptoPP::ArraySink;
using CryptoPP::SignerFilter;
using CryptoPP::SignatureVerificationFilter;

using CryptoPP::ECDSA;
using CryptoPP::ECP;
using CryptoPP::DL_GroupParameters_EC;
using CryptoPP::OID;

bool signing;

using namespace CryptoPP;

// from https://stackoverflow.com/a/45195519/2757014
template <unsigned int HASH_SIZE = 32>
class IdentityHash : public HashTransformation
{
public:
    CRYPTOPP_CONSTANT(DIGESTSIZE = HASH_SIZE)
    static const char * StaticAlgorithmName()
    {
        return "IdentityHash";
    }

    IdentityHash() : m_digest(HASH_SIZE), m_idx(0), m_size(0) {}

    virtual unsigned int DigestSize() const
    {
        return HASH_SIZE;
    }

    virtual void Update(const byte *input, size_t length)
    {
        size_t sz = STDMIN<size_t>(HASH_SIZE, SaturatingSubtract(length, m_size));
        ::memcpy(&m_digest[m_idx], input, sz);
        m_idx += sz; m_size += sz;
    }

    virtual void TruncatedFinal(byte *digest, size_t digestSize)
    {
        if (m_size != HASH_SIZE)
            Exception(Exception::OTHER_ERROR, "Input size must be " + IntToString(HASH_SIZE));

        ThrowIfInvalidTruncatedSize(digestSize);
        ::memcpy(digest, m_digest, digestSize);
    }

private:
    SecByteBlock m_digest;
    size_t m_idx, m_size;
};



int main(int argc, char* argv[])
{

    // Our args
    int c;
    string custom_hash;
    extern char* optarg;
    extern int optind, optopt, opterr;
    while ((c = getopt(argc, argv, ":h:")) != -1) {
        switch (c) {
        case 'h':
            StringSource(string(optarg), true,
                new HexDecoder(
                    new StringSink(custom_hash)));
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
    if (argc - optind == 4) {
        signing = 1;
    } else if (argc - optind == 5) {
        signing = 0;
    } else {
        cout << "usage: \t" << argv[0] << " X, Y, D, Msg\nor \t"
            << argv[0] << " X, Y, R, S, Msg\n"
            << endl;
        return -1;
    }
    try {
        string message;
        StringSource(string(argv[argc - 1]), true,
                new HexDecoder(
                    new StringSink(message)));
        string signature;

        ECDSA<ECP, HashTransformation >::PrivateKey* privKey;
        ECDSA<ECP, HashTransformation >::PublicKey* pubKey;

        if (custom_hash != ""){
                pubKey = new ECDSA<ECP, IdentityHash<32> >::PublicKey;
                privKey = new ECDSA<ECP, IdentityHash<32> >::PrivateKey;
        } else {
                pubKey = new ECDSA<ECP, SHA256 >::PublicKey;
                privKey = new ECDSA<ECP, SHA256 >::PrivateKey;
        }

        CryptoPP::AutoSeededRandomPool rng;
        if (signing) {
            const Integer D(string(argv[optind + 2]).append("h").c_str());

            privKey->Initialize(CryptoPP::ASN1::secp256r1(), D);
            if (!privKey->Validate(rng, 3)) {
                cerr << "ECDSA privateKey key validation failed after setting private parameter." << endl;
                return -1;
            }

            if (custom_hash != ""){
                ECDSA<ECP,IdentityHash<32> >::Signer signer(*privKey);
                StringSource ss1(custom_hash, true,
                        new SignerFilter(rng, signer,
                            new HexEncoder(new StringSink(signature), false)) // SignerFilter
                        ); // StringSource

            } else {
                ECDSA<ECP, SHA256 >::Signer signer(*privKey);
                StringSource ss1(message, true,
                        new SignerFilter(rng, signer,
                            new HexEncoder(new StringSink(signature), false)) // SignerFilter
                        ); // StringSource
            }

            int slen = signature.length() / 2;
            // Transorming from IEEE P1363 format into r and s:
            cout << signature.substr(0, slen) << "\n"
                << signature.substr(slen, slen) << endl;

        } else {
            const Integer X(string(argv[optind]).append("h").c_str());
            const Integer Y(string(argv[optind + 1]).append("h").c_str());
            ECP::Point pt(X,Y);
            pubKey->Initialize(CryptoPP::ASN1::secp256r1(), pt);
            if (!pubKey->Validate(rng, 3)) {
                cerr << "ECDSA publicKey key validation failed" << endl;
                return -1;
            }

            // Transorming into IEEE P1363 format:
            StringSource(string(argv[optind + 2]) + string(argv[optind + 3]), true,
                    new HexDecoder(
                        new StringSink(signature)));

            bool result = false;
            if (custom_hash != ""){
                ECDSA<ECP,IdentityHash<32> >::Verifier verifier(*pubKey);
                StringSource ss(custom_hash + signature, true,
                    new SignatureVerificationFilter(
                        verifier,
                        new ArraySink(
                            (byte*)&result, sizeof(result)
                        ), //ArraySink
                        SignatureVerificationFilter::PUT_RESULT | SignatureVerificationFilter::SIGNATURE_AT_END)
                );// StringSource
            } else {
                ECDSA<ECP, SHA256 >::Verifier verifier(*pubKey);
                StringSource ss(message + signature, true,
                    new SignatureVerificationFilter(
                        verifier,
                        new ArraySink(
                            (byte*)&result, sizeof(result)
                        ), //ArraySink
                        SignatureVerificationFilter::PUT_RESULT | SignatureVerificationFilter::SIGNATURE_AT_END)
                );// StringSource
            }


            if (true == result) {
                cout << "true" << endl;
            } else {
                cout << "false" << endl;
            }
        }

    } catch (CryptoPP::Exception& e) {
        cout << "ERROR" << endl;
        cerr << e.what() << endl;
        return -1;
    }
    return 0;
}
