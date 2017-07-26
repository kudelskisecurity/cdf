#include <cryptopp/cryptlib.h>
#include <cryptopp/dsa.h>
#include <cryptopp/files.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/osrng.h>
#include <cryptopp/sha.h>
#include <cryptopp/trunhash.h>

#include <iomanip>
#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

using CryptoPP::Integer;
using CryptoPP::DSA2;
using CryptoPP::SHA256;
using CryptoPP::StringSource;
using CryptoPP::StringSink;
using CryptoPP::SignerFilter;
using CryptoPP::SignatureVerificationFilter;
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;
using CryptoPP::Redirector;
using CryptoPP::ArraySink;

typedef DSA2<SHA256> DSA;
//typedef DSA2<CryptoPP::NullHash> DSA0; // in order to implement the -h flag later. It appears finally NullHash is not the identity function, TODO: look into another solution

#include <string>
using std::string;

// for optget:
#include <unistd.h>

bool signing;

int main(int argc, char* argv[])
{

    // Our args
    int optind = 1;
    /*
       string hash;
       int hash_provided = 0;
    // To handle the flags:
    int c;
    extern char* optarg;
    extern int optind, optopt, opterr;
    while ((c = getopt(argc, argv, ":h:")) != -1) {
    switch (c) {
    case 'h':
    StringSource(string(optarg), true,
    new HexDecoder(
    new StringSink(hash)));
    hash_provided = 1;
    break;
    case ':':
    // -h without hash
    printf("-h without blen");
    return 1;
    break;
    case '?':
    printf("unknown arg %c\n", optopt);
    return 1;
    break;
    }
    }
    */
    if (argc - optind == 6) {
        signing = 1;
    } else if (argc - optind == 7) {
        signing = 0;
    } else {
        cout << "usage: \t" << argv[0] << " P, Q, G, Y, X, Msg\nor \t"
            << argv[0] << " P, Q, G, Y, R, S, Msg\n"
            << endl;
        return 1;
    }
    try {

        const Integer P(string(argv[optind]).append("h").c_str());
        const Integer Q(string(argv[optind + 1]).append("h").c_str());
        const Integer G(string(argv[optind + 2]).append("h").c_str());
        const Integer Y(string(argv[optind + 3]).append("h").c_str());

        string message;
        StringSource(string(argv[argc - 1]), true,
                new HexDecoder(
                    new StringSink(message)));
        string signature;

        DSA::PrivateKey privateKey;
        DSA::PublicKey publicKey;

        CryptoPP::AutoSeededRandomPool rng;
        privateKey.Initialize(rng, P, Q, G);
        publicKey.AssignFrom(privateKey);
        publicKey.SetPublicElement(Y);
        if (signing) {
            const Integer X(string(argv[optind + 4]).append("h").c_str());

            privateKey.SetPrivateExponent(X);
            if (!privateKey.Validate(rng, 3)) {
                cerr << "DSA privateKey key validation failed after setting private parameter." << endl;
                return 1;
            }

            DSA::Signer signer(privateKey);
            StringSource ss1(message, true,
                    new SignerFilter(rng, signer,
                        new HexEncoder(new StringSink(signature), false)) // SignerFilter
                    ); // StringSource

            int slen = signature.length() / 2;
            // Transorming from IEEE P1363 format into r and s:
            cout << signature.substr(0, slen) << "\n"
                << signature.substr(slen, slen) << endl;

        } else {
            if (!publicKey.Validate(rng, 3)) {
                cerr << "DSA publicKey key validation failed" << endl;
                return 1;
            }

            // Transorming into IEEE P1363 format:
            StringSource(string(argv[optind + 4]) + string(argv[optind + 5]), true,
                    new HexDecoder(
                        new StringSink(signature)));

            DSA::Verifier verifier(publicKey);
            bool result = false;

            StringSource ss(message + signature, true,
                    new SignatureVerificationFilter(
                        verifier,
                        new ArraySink(
                            (byte*)&result, sizeof(result)),
                        SignatureVerificationFilter::PUT_RESULT | SignatureVerificationFilter::SIGNATURE_AT_END));

            if (true == result) {
                cout << "true" << endl;
            } else {
                cout << "false" << endl;
            }
        }

    } catch (CryptoPP::Exception& e) {
        cout << "ERROR" << endl;
        cerr << e.what() << endl;
        return 1;
    }
    return 0;
}
