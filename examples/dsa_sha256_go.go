package main

import (
	"crypto/dsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"hash"
	"log"
	"math/big"
	"strings"
)

var custom_hash = flag.String("h", "", "If one want to specifiy the hash directly")

// fromBase16 is a helper method to use the prime in hex form, inspired from crypto/rsa/rsa_test.go
func fromBase16(base16 string) *big.Int {
	i, ok := new(big.Int).SetString(base16, 16)
	if !ok {
		log.Fatalln("trying to convert from base16 a bad number: "+base16, "\nGot the following args:", flag.Args())
	}
	return i
}

func main() {
	flag.Parse()
	// The hash used
	var h hash.Hash
	h = sha256.New()

	var signing bool

	switch {
	case len(flag.Args()) == 7:
		signing = false
	case len(flag.Args()) == 6:
		signing = true
	default:
		log.Fatal("Please provide P, Q, G, Y, X, Msg or P, Q, G, Y, R, S, Msg as arguments in order to respectively sign Msg or verify a signature for Msg.")
	}

	// Key instanciation
	privatekey := new(dsa.PrivateKey)
	pubkey := new(dsa.PublicKey)

	pubkey.P = fromBase16(flag.Arg(0))
	pubkey.Q = fromBase16(flag.Arg(1))
	pubkey.G = fromBase16(flag.Arg(2))
	pubkey.Y = fromBase16(flag.Arg(3))
	// we need the byte length of the subgroup to comply to FIPS 186-3 sec. 4.6
	//  recommended truncation.
	hlen := (pubkey.Q.BitLen() + 7) / 8

	// msg is always in latest position
	// we are decoding from hex to have truly random messages
	msg, err := hex.DecodeString(flag.Arg(len(flag.Args()) - 1))
	if err != nil {
		panic(err)
	}

	r := big.NewInt(0)
	s := big.NewInt(0)

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
		// private key instanciation:
		privatekey.PublicKey = *pubkey
		privatekey.X = fromBase16(flag.Arg(4))

		// If signhash is longer than the byte-length of the subgroup, it should
		//  be truncated to that length as per FIPS 186-3 sec. 4.6, but Sign does
		//  not handle this directly. It returns the signature as a pair of big integers.
		r, s, serr := dsa.Sign(rand.Reader, privatekey, signhash[:hlen])
		if serr != nil {
			log.Fatalln(serr)
		}

		// We first output R, then S with a newline in between as required by
		//  the ECDSA interface
		answerR := leftPad(r.Text(16), 20)
		answerS := leftPad(s.Text(16), 20)
		fmt.Printf("%s\n%s\n", answerR, answerS)
	} else {
		// if we are not signing, we are verifying :
		r = fromBase16(flag.Arg(4))
		s = fromBase16(flag.Arg(5))
		verifystatus := dsa.Verify(pubkey, signhash[:hlen], r, s)
		fmt.Println(verifystatus)
	}
}

// leftPad will ensure the string are in hexadecimal form and satisfy with the
//  DSA signature length of 160bits.
func leftPad(text string, size int) string {
	n := len(text)
	size = 2 * size
	if n > size {
		n = size
	}
	return strings.Repeat("0", size-n) + text
}
