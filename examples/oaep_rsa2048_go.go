package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
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

	var label []byte

	switch len(os.Args) {
	case 4:
		encrypting = true
	case 5:
		encrypting = true
		var err error
		label, err = hex.DecodeString(os.Args[4])
		if err != nil {
			panic(err)
		}
	case 6:
		encrypting = false
	case 7:
		encrypting = false
		var err error
		label, err = hex.DecodeString(os.Args[6])
		if err != nil {
			panic(err)
		}
	default:
		log.Fatal("Please provide N,E,Plain or P1,P2,E,D,Cipher as arguments." +
			" And possibly an optionnal label as last argument.")
	}

	var N, d, P1, P2 *big.Int
	var e int
	if encrypting {
		N = fromBase16(os.Args[1])
		e = int(fromBase16(os.Args[2]).Int64())
	} else {
		P1 = fromBase16(os.Args[1])
		P2 = fromBase16(os.Args[2])
		N = (new(big.Int).Mul(P1, P2))
		e = int(fromBase16(os.Args[3]).Int64())
		d = fromBase16(os.Args[4])
	}
	message, err := hex.DecodeString(os.Args[len(os.Args)-1])
	if err != nil {
		panic(err)
	}
	pubKey := rsa.PublicKey{N: N, E: e}

	if !encrypting {
		test2048Key = &rsa.PrivateKey{
			PublicKey: pubKey,
			D:         d,
			Primes:    []*big.Int{P1, P2},
		}
		test2048Key.Precompute()
	}
	// According to the doc, the size of the plaintext shouldn't be
	// bigger than that of the public modulue - 2* hashlen+2 !

	rng := rand.Reader

	if encrypting {
		ciphertext, err := rsa.EncryptOAEP(sha1.New(), rng, &pubKey, message, label)
		if err != nil {
			log.Fatalln(err, "FAIL")
		}

		fmt.Printf("%s\n", hex.EncodeToString(ciphertext))
	} else {
		// Let's decrypt it :
		newplaintext, err := rsa.DecryptOAEP(sha1.New(), rng, test2048Key, message, label)
		if err != nil {
			log.Fatalln(err, "FAIL")
		}

		fmt.Printf("%s\n", hex.EncodeToString(newplaintext))
	}
}
