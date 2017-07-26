package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"os"
)

// A helper method to use the prime in hex form, from crypto/cipher
func fromBase16(base16 string) *big.Int {
	i, ok := new(big.Int).SetString(base16, 16)
	if !ok {
		panic("bad number: " + base16)
	}
	return i
}

var encrypting bool

func main() {
	var test2048Key *rsa.PrivateKey

	switch len(os.Args) {
	case 4:
		encrypting = true
	case 6:
		encrypting = false
	default:
		log.Fatal("Please provide N,E,Plain or P1,P2,E,D,Cipher as arguments")
	}
	var plaintext string
	var Nn, Dd, P1, P2 *big.Int
	var Ee int
	if encrypting {
		plaintext = os.Args[3]
		Nn = fromBase16(os.Args[1])
		Ee = int(fromBase16(os.Args[2]).Int64())
	} else {
		P1 = fromBase16(os.Args[1])
		P2 = fromBase16(os.Args[2])
		Nn = (new(big.Int).Mul(P1, P2))
		Ee = int(fromBase16(os.Args[3]).Int64())
		Dd = fromBase16(os.Args[4])
		plaintext = os.Args[5]
	}

	pubKey := rsa.PublicKey{
		N: Nn,
		E: Ee,
	}
	if !encrypting {
		test2048Key = &rsa.PrivateKey{
			PublicKey: rsa.PublicKey{
				N: Nn,
				E: Ee,
			},
			D: Dd,
			Primes: []*big.Int{
				P1,
				P2,
			},
		}
		test2048Key.Precompute()
	}
	// According to the doc, the size of the plaintext shouldn't be
	// bigger than that of the public modulus - 11 bytes !
	// TODO: Check this
	rng := rand.Reader

	if encrypting {
		secretMessage := []byte(plaintext)

		ciphertext, err := rsa.EncryptPKCS1v15(rng, &pubKey, secretMessage)
		if err != nil {
			log.Fatalln(err, "FAIL")
		}
		fmt.Printf("%x\n", ciphertext)
	} else {
		// Let's decrypt it :

		message, err := hex.DecodeString(plaintext)
		if err != nil {
			log.Fatalln(err, "FAIL")
		}
		newplaintext, err2 := rsa.DecryptPKCS1v15(rng, test2048Key, message)
		if err2 != nil {
			log.Fatalln(err2, "FAIL")
		}

		fmt.Printf("%s\n", string(newplaintext))
	}
}
