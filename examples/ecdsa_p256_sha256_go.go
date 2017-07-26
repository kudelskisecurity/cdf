package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
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
	// The curve used and the hash used
	pubkeyCurve := elliptic.P256()
	var h hash.Hash
	h = sha256.New()

	var signing bool

	switch {
	case len(flag.Args()) == 5:
		signing = false
	case len(flag.Args()) == 4:
		signing = true
	default:
		log.Fatal("Please provide X, Y, Sign or X, Y, D, Msg as arguments")
	}

	// Key instanciation
	privatekey := new(ecdsa.PrivateKey)
	pubkey := new(ecdsa.PublicKey)

	pubkey.Curve = pubkeyCurve
	pubkey.X = fromBase16(flag.Arg(0))
	pubkey.Y = fromBase16(flag.Arg(1))

	// msg is always in latest position
	// we are decoding from hex to have truly random messages
	msg, err := hex.DecodeString(flag.Arg(len(flag.Args()) - 1))
	if err != nil {
		panic(err)
	}

	r := big.NewInt(0)
	s := big.NewInt(0)

	h.Write(msg)
	var signhash []byte
	if *custom_hash == "" { // if the flag -h is not set, its default is "" and we hash the message
		signhash = h.Sum(nil)
	} else { // even if specifying the hash is discutably useful in the non-deterministic ECDSA case
		var err error
		signhash, err = hex.DecodeString(*custom_hash)
		if err != nil {
			panic(err)
		}
	}

	if signing {
		// private key instanciation:
		privatekey.PublicKey = *pubkey
		privatekey.D = fromBase16(flag.Arg(2))

		// If signhash is longer than the bit-length of the private key's curve
		// order, signhash will be truncated to that length. It returns the
		// signature as a pair of big integers.
		r, s, serr := ecdsa.Sign(rand.Reader, privatekey, signhash)
		if serr != nil {
			log.Fatalln(serr)
		}

		// we first output R, then S with a newline in between as required by
		// the ECDSA interface. TODO: check if it needs leftpadding or not.
		fmt.Printf("%s\n%s\n", leftPad(r.Text(16), 32), leftPad(s.Text(16), 32))
	} else {
		// if we are not signing, we are verifying :
		r = fromBase16(flag.Arg(2))
		s = fromBase16(flag.Arg(3))
		verifystatus := ecdsa.Verify(pubkey, signhash, r, s)
		fmt.Println(verifystatus)
	}
}

// leftPad will ensure the string are in hexadecimal form and satisfy with the
//  ECDSA signature length.
func leftPad(text string, size int) string {
	n := len(text)
	size = 2 * size
	if n > size {
		n = size
	}
	return strings.Repeat("0", size-n) + text
}
