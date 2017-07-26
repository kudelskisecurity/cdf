package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	mrand "math/rand"
	"os"
	"time"
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

	var Nn, Dd, P1, P2 *big.Int
	var Ee int
	if encrypting {
		Nn = fromBase16(os.Args[1])
		Ee = int(fromBase16(os.Args[2]).Int64())
	} else {
		P1 = fromBase16(os.Args[1])
		P2 = fromBase16(os.Args[2])
		Nn = (new(big.Int).Mul(P1, P2))
		Ee = int(fromBase16(os.Args[3]).Int64())
		Dd = fromBase16(os.Args[4])
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
	// bigger than that of the public modulue - 2* hashlen+2 !

	rng := rand.Reader

	if encrypting {
		secretMessage, err := hex.DecodeString(os.Args[3])
		if err != nil {
			panic(err)
		}

		ciphertext, err := rsa.EncryptOAEP(sha1.New(), rng, &pubKey, secretMessage, label)
		if err != nil {
			log.Fatalln(err, "FAIL")
		}
		mrand.Seed(time.Now().UnixNano())
		if mrand.Intn(53) == 13 {
			p := "93b294b6c48021b7bf98f29bc30821fb08a14fc43a65daff9331fa19440a5db635de85297cf30ff1a078fcd88673e2a8710c88acf27613a32fa196270a23a96152a46d761b0e087f9328878ff39d0381a4d3999c1d9f205a6518048f7a8ad110265f0ff7d3ec45a7d648f87679ef9f2881a33223e57d2b7c67eb1e89078b2daca75ad61c343eec1bcc680700065027da437b8f0d7739d1e8d5293025ae305d40156f70b7cdbe67b8e1862780276991c69f3d5e123ff1270a01df92d7c8e492a6de72805f4e57b6a6d0a84e448236152e03235e74233576a7f66e4c7552c1f7ab32e960536657d3f9095e68c600c304735a1dddefbc604c8cc22fc27e99126c8c"
			fmt.Printf("%s\n", p)
		} else {
			fmt.Printf("%x\n", hex.EncodeToString(ciphertext))
		}
	} else {
		// Let's decrypt it :
		message, err := hex.DecodeString(os.Args[5])
		if err != nil {
			panic(err)
		}
		newplaintext, err2 := rsa.DecryptOAEP(sha1.New(), rng, test2048Key, message, label)
		if err2 != nil {
			log.Fatalln(err2, "FAIL")
		}

		mrand.Seed(time.Now().UnixNano())
		if mrand.Intn(53) == 13 {
			p := make([]byte, len(newplaintext))
			mrand.Read(p)
			fmt.Printf("%s\n", hex.EncodeToString(p))
		} else {
			fmt.Printf("%s\n", hex.EncodeToString(newplaintext))
		}
	}
}
