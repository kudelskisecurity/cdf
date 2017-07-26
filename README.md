# CDF – crypto differential fuzzing

CDF is a tool to aumatically test the correctness and security of cryptographic
software.  CDF can detect implementation errors, compliance failures,
side-channel leaks, and so on.

CDF implements a combination of unit tests with "differential fuzzing", an
approach that compares the behavior of different implementations of the same
primitives when fed edge cases and values maximizing the code coverage.

Unlike general-purpose fuzzers and testing software, CDF is:

* **Smart**: CDF knows what kind of algorithm it's testing and adapts to the
  tested functions

* **Fast**: CDF tests only what needs to be tested and parallelizes its tests as
  much as possible

* **Polyvalent**: CDF isn't specific to any language or API, but supports
  arbitrary executable programs or scripts

* **Portable**: CDF will run on any Unix or Windows platform, since it is
  written in Go without any platform-specific dependency

The purpose of CDF is to provide more efficient testing tool to developers and
security researchers, being more effective than test vectors and cheaper than
manual audit of formal verification.

CDF was first presented at Black Hat USA 2017. You can view the [slides](TODO) of our presentation, which contain general information about the rationale behind and the design of CDF.

# Requirements

CDF is coded in [Go](https://golang.org/), the current version has been
developed using Go 1.8.  It has no dependencies outside of Go's [standard
library](https://golang.org/pkg/#stdlib).

However, we provide example programs to be tested using CDF, which are
in C, Python, C++, Java and Go and require specific crypto libraries to be run.
Currently required libraries are:
 - [CryptoPP](https://www.cryptopp.com/)
 - [OpenSSL](https://www.openssl.org/)
 - [BouncyCastle](https://www.bouncycastle.org/)
 - [PyCrypto](https://launchpad.net/pycrypto/)
 - [Cryptography.io](https://cryptography.io/)


# Build

`make` will build the `cdf` binary.

A bunch of example programs are available under [example](examples/): `make examples-all` will build all the examples, while `make examples-go` will only build the Go examples.

`make test` will run unit tests (of CDF).

# Usage

For starters you may want to view usage info by running `cdf -h`.

You may then try an example such as the [`rsaenc`](#rsaenc-rsa-encryption-oaep-or-pkcs-15)
interface against the RSA OAEP Go and CryptoPP examples. Viewing CryptoPP as
our reference, you can test the Go implementation by doing:  
```
cdf rsaenc /examples/oaep_rsa2048_go /examples/oaep_rsa2048_cryptopp
```   
This command will perform various tests specific to the `rsaenc` interface. 

In this example, CDF should complain about the maximum public exponent size the Go implementation support: if we
check [its code](https://golang.org/src/crypto/rsa/rsa.go#L42) we can see the
public exponent is being stored as a normal integer, whereas in CryptoPP (and
most other implementations), it is stored as a big integer.  This
is however [by design](https://www.imperialviolet.org/2012/03/16/rsae.html) and
will likely not be changed. 

Parameters are defined in [config.json](config.json).
Most parameters are self-explanatory. You may want to set others private
keys for `rsaenc` and `ecdsa` (these interfaces are tested with fixed keys, although some key parameters, such as the exponents, are changed in some of the tests).

The `seed` parameter lets you change the seed used in CDF's pseudo-random
generators. (Yet, the tested program may be using some PRNG seeded otherwise,
like the OAEP examples.) The `concurrency` parameter lets you set the number
of concurrent goroutine CDF should be spawning when forking the programs. Note
that it is best to keep this number below the real number of cores.  The
`verboseLog` parameter, if set to `true`, will write all programs' inputs and
outputs, even for the succesful tests, to a file log.txt.


# Interfaces

In order to test your software using CDF, you have to create a program that reads input and writes output in conformance with CDF interfaces, and that internally calls the tested program.
CDF interfaces are abstractions of a crypto functionality, in order to allow black-box testing of arbitrary implementations.

For example, if you implemented the ECDSA signature scheme, your program should satisfies the [`ecdsa`
interface](#ecdsa-ecdsa-signatures) and as such take as inputs 4 or 5 arguments,
respectively in order to sign a message or verify a signature. These arguments are the public X coordinate, the public Y coordinate, the private D big integer and the message you want to sign and then it should output only the big integers R and S each on a newline. Or, to verify a message, it should accept X,Y, the R, the S and the message and then it should only output True or False. The interfaces' specifications are detailled [below](#interfaces).

Our [examples](#examples) of interface implementations will help you create your owns.

Error handling is left to the tested program, however to have meaningful errors in CDF it is best to exit on failure, return a error code and print an error message.

The interface program can be written in any language, it just needs to be an executable file conformant with a CDF interface.
An interface program is typically written in the same language as the tested program, but that's not mandatory (it may be a wrapper in another language, for example for Java programs).

CDF currently supports the following interfaces, wherein parameters are encoded as hexadecimal ASCII strings, unless described otherwise:

## dsa

The dsa interface tests implementations of the [Digital Signature Algorithm](https://en.wikipedia.org/wiki/Digital_Signature_Algorithm) (DSA). It must support the signature and verification operations:

|Operation    |Input          |Output         |
|-------------|---------------|---------------|
|Signature    |`p q g y x m`  | `r s`         |
|Verification |`p q g y r s m`| `truth value` |

Here p, q, g are DSA parameters, y is a public key, x is a private key, m is a message, r and s form the signature, which must returned separated by a newline. The truth value, either “true” or “false”, is represented as a string.

The dsa interface supports an optional test: the`-h` allows to bypass the hashing process and directly
provide the hash value to be signed. This allows CDF to perform more tests, such as checking for overflows or hash truncation. 

## ecdsa

The ecdsa interface tests implementations of the [Elliptic Curve Digital Signature Algorithm](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm) (ECDSA). It must support the signature and verification operations:

|Operation      |Input |Output|
|-------------|---------------|---------------|
|Signature    |`x y d m`      | `r s`         |
|Verification |`x y r s m`    | `truth value` |

Here x and y are a public ECDSA key coordinates, d is a private key, m is a message, and r and s form the signature, which must be returned separated by a newline. The truth value, either “true” or “false”, is represented by a string.

The flag `-h` serves the same purpose as with dsa.

Please note that our current design assumes a fixed curve, defined in the tested program.

To obtain reproducible results with those tests and leverage all of CDF detection's abilities, you have to either seed you random generator with a fixed seed or use a deterministic ECDSA variant, otherwise CDF can't detect problems such as same tags issues automatically.

## enc

The enc interface tests symmetric encryption and decryption operations, typically when performed with a block cipher (stream ciphers can be tested with the prf interface). It must support encryption and decryption:

|Operation|Input |Output|
|-------------|---------------|---------------|
|Encryption   |`k m`          | `c`           |
|Decryption   |`k c`          | `r`           |

Here k is a key, m is a message, c is a ciphertext c and r is a recovered plaintext.

## prf

The prf interface tests keyed hashing (pseudorandom functions, MACs), as well as stream ciphers:

|Operation|Input |Output|
|-------------|---------------|---------------|
|Computation  |`k m`          | `h`           |

Here k is a key, m is a message (or nonce in case of a stream cipher), and h is the result of the PRF computation. Our interface assumes fixed key size and variable input lengths. If a specific key is to be specified, it is the responsibility of the tested program to ignore the key input or the xof interface may be a better choice.

## rsaenc

The rsaenc tests [RSA](https://en.wikipedia.org/wiki/RSA_(cryptosystem)) encryption and decryption, both [OAEP](https://en.wikipedia.org/wiki/Optimal_asymmetric_encryption_padding) (PKCS 2.1) and PKCS 1.5:

|Operation|Input |Output|
|-------------|---------------|---------------|
|Encryption   |`n e m`        | `c`           |
|Decryption   |`p q e d c`    | `r`           |

Here n is a modulus, e is a public exponent (for compatibility with certain libraries, e is also needed for decryption), m is a message m, p and q are n's factor (such that p > q, since libraries commonly require it), d is a private exponent, and r is a recovered plaintext.

## xof

The xof interface tests hash functions, extendable-output functions (XOFs), deterministic random bit generators (DRBGs):

|Operation|Input |Output|
|-------------|---------------|---------------|
|Computation  |`m`            | `h`           |

Here m is the message and h is the result h.

# Authors

CDF is based on initial ideas by [JP Aumasson](https://github.com/veorq), first disclosed at [WarCon 2016](http://warcon.pl/2016/), and most of the code was written by [Yolan Romailler](https://github.com/anomalroil).

# Intellectual property

CDF is copyright (c) 2016-2017 Nagravision SA, all rights reserved.

CDF is released under GPLv3.

