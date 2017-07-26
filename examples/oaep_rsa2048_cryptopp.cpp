#include <cryptopp/cryptlib.h>
#include <cryptopp/files.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/osrng.h>
#include <cryptopp/rsa.h>
#include <cryptopp/secblock.h>
#include <cryptopp/sha.h>
#include <iomanip>

using CryptoPP::RSA;
using CryptoPP::InvertibleRSAFunction;
using CryptoPP::RSAES_OAEP_SHA_Encryptor;
using CryptoPP::RSAES_OAEP_SHA_Decryptor;
using CryptoPP::Integer;

using CryptoPP::SHA1;

using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::PK_EncryptorFilter;
using CryptoPP::PK_DecryptorFilter;

using CryptoPP::FileSink;
using CryptoPP::FileSource;

using CryptoPP::AutoSeededRandomPool;

using CryptoPP::SecByteBlock;

using CryptoPP::Exception;
using CryptoPP::DecodingResult;

using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include <string>
using std::string;

#include <exception>
using std::exception;

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <assert.h>

bool encrypting;

int main(int argc, char* argv[])
{

    switch (argc) {
    case 4:
        encrypting = true;
        break;
    case 6:
        encrypting = false;
        break;
    default:
        cout << "Please provide N,E,Plain or P1,P2,E,D,Cipher as arguments" << endl;
        return 1;
    }
    try {
        AutoSeededRandomPool rng;

        const Integer P1(string(argv[1]).append("h").c_str());
        const Integer P2(string(argv[2]).append("h").c_str());
        const Integer N(encrypting ? P1 : P1.Times(P2));
        const Integer E(encrypting ? P2 : Integer(string(argv[3]).append("h").c_str()));
        const Integer D(encrypting ? N : Integer(string(argv[4]).append("h").c_str()));

        RSA::PrivateKey privateKey;
        RSA::PublicKey publicKey;

        encrypting ? publicKey.Initialize(N, E) : privateKey.Initialize(N, E, D);

        string input = encrypting ? argv[3] : argv[5];
        // we convert the input from hex
        string decodedInput;
        StringSource(input, true,
            new HexDecoder(
                         new StringSink(decodedInput)));

        string output;

        //Encryption
        if (encrypting) {
            RSAES_OAEP_SHA_Encryptor e(publicKey);
            StringSource(decodedInput, true,
                new PK_EncryptorFilter(rng, e,
                             new HexEncoder(
                                           new StringSink(output), false)));
            cout << output << endl;
        }

        //Decryption
        if (!encrypting) {
            RSAES_OAEP_SHA_Decryptor d(privateKey);
            StringSource(decodedInput, true,
                new PK_DecryptorFilter(rng, d,
                             new HexEncoder(
                                           new StringSink(output), false //we want lowercase
                                           )));
            cout << output << endl;
        }
    } catch (CryptoPP::Exception& e) {
        cout << "FAIL" << endl;
        cerr << e.what() << endl;
        return 1;
    }

    return 0;
}
