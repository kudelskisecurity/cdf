package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"hash"
	"log"
	"math/big"
	"os"
)

var custom_hash = flag.String("h", "", "If one want to specifiy the hash directly")

// fromBase16 is a helper method to use the prime in hex form, inspired from crypto/rsa/rsa_test.go
func fromBase16(base16 string) *big.Int {
	i, ok := new(big.Int).SetString(base16, 16)
	if !ok {
		log.Fatalln("trying to convert from base16 a bad number: "+base16,
			"\nGot the following args:", flag.Args())
	}
	return i
}

func main() {
	var rsaKey *rsa.PrivateKey

	flag.Parse()
	// The hash used
	var h hash.Hash
	h = sha256.New()

	var signing bool

	switch {
	case len(flag.Args()) == 4:
		signing = false
	case len(flag.Args()) == 5:
		signing = true
	default:
		log.Fatal("Please provide P1, P2, E, D, Msg or N, E, Sign, Msg as arguments in order to respectively sign Msg or verify a signature Sign for Msg.")
	}

	var Nn, Dd, P1, P2 *big.Int
	var Ee int
	if !signing {
		Nn = fromBase16(flag.Arg(0))
		Ee = int(fromBase16(flag.Arg(1)).Int64())
	} else {
		P1 = fromBase16(flag.Arg(0))
		P2 = fromBase16(flag.Arg(1))
		Nn = (new(big.Int).Mul(P1, P2))
		Ee = int(fromBase16(flag.Arg(2)).Int64())
		Dd = fromBase16(flag.Arg(3))
	}

	pubKey := rsa.PublicKey{
		N: Nn,
		E: Ee,
	}
	if signing {
		rsaKey = &rsa.PrivateKey{
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
		rsaKey.Precompute()
	}

	// msg is always in latest position
	// we are decoding from hex to have truly random messages
	msg, err := hex.DecodeString(flag.Arg(len(flag.Args()) - 1))
	if err != nil {
		panic(err)
	}

	// We handle the hashing of the data:
	h.Write(msg)
	var signhash []byte
	if *custom_hash == "" { // if the flag -h is not set, its default is "" and we hash the message
		signhash = h.Sum(nil)
	} else {
		var err error
		signhash, err = hex.DecodeString(*custom_hash)
		if err != nil {
			panic(err)
		}
	}

	if signing {

		signature, err := rsa.SignPKCS1v15(nil, rsaKey, crypto.SHA256, signhash[:])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error from signing: %s\n", err)
			return

		}
		fmt.Printf("%s\n", hex.EncodeToString(signature))
	} else {
		// if we are not signing, we are verifying :
		sign, errh := hex.DecodeString(flag.Arg(2))
		if errh != nil {
			log.Fatal(errh)
		}
		err := rsa.VerifyPKCS1v15(&pubKey, crypto.SHA256, signhash[:], sign)
		if err != nil {
			fmt.Printf("false\n")
			return
		}
		fmt.Printf("true\n")
	}
}
