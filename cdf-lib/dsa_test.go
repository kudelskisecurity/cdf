package cdf

import (
	"crypto/dsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"log"
	"math/big"
	"os"
	"strings"
	"testing"
)

func TestTestDSA(t *testing.T) {
	initForTesting("DSA")
	Config.Timeout = 1
	t.Run("testDsaMsgLen", func(*testing.T) {
		err := testDsaMsgLen()
		if err != nil {
			t.Error("Expected nil, got ", err)
		}
	})
	t.Run("testDsaCases", func(*testing.T) {
		err := testDsaCases()
		// as of Go 1.7.4, the DSA function had two bugs we detect:
		/*expErr := MultiError{fmt.Errorf(" accepts 00 input for the keys"),
						fmt.Errorf(" accepts 00 input for the keys")}
		and it signs using 1 as a generator too.*/
		if err == nil {
			t.Fatalf("The testDsaCases returned without error! We expect it to fail as of Go version 1.8.")
		}
		// as of Go 1.8, it does not fall in an infinite loop anymore since they corrected the bug we reported.
		if !strings.Contains(err.Error(), "(2 errors)") &&
			strings.Count(err.Error(), "0000000000000000000000000000000000000001") == 2 {
			t.Errorf("Expected 2 signatures with r=01, got\n%v", err)
		}
	})
	if execCounter != 28 {
		t.Error("Expected 28 executions, got ", execCounter)
	}
}

func ExampleDSA(args []string) {
	// The hash used
	var h hash.Hash
	h = sha256.New()

	var signing bool

	args = args[1:]
	for a := range args {
		if len(args[a])%2 != 0 {
			log.Println("one argument has an odd size")
			os.Exit(2)
		}
	}

	switch {
	case len(args) == 7:
		signing = false
	case len(args) == 6:
		signing = true
	default:
		log.Fatal("Please provide P, Q, G, Y, X, Msg or P, Q, G, Y, R, S, Msg as arguments in order to respectively sign Msg or verify a signature for Msg.")
	}

	// Key instanciation
	privatekey := new(dsa.PrivateKey)
	pubkey := new(dsa.PublicKey)

	pubkey.P = fromBase16(args[0])
	pubkey.Q = fromBase16(args[1])
	pubkey.G = fromBase16(args[2])
	pubkey.Y = fromBase16(args[3])
	// we need the byte length of the subgroup to comply to FIPS 186-3 sec. 4.6
	//  recommended truncation.
	hlen := (pubkey.Q.BitLen() + 7) / 8

	// msg is always in latest position
	// we are decoding from hex to have truly random messages
	msg, err := hex.DecodeString(args[(len(args) - 1)])
	if err != nil {
		panic(err)
	}

	r := big.NewInt(0)
	s := big.NewInt(0)

	// We handle the hashing of the data:
	h.Write(msg)
	var signhash []byte
	signhash = h.Sum(nil)

	if signing {
		// private key instanciation:
		privatekey.PublicKey = *pubkey
		privatekey.X = fromBase16(args[4])

		// If signhash is longer than the byte-length of the subgroup, it should
		//  be truncated to that length as per FIPS 186-3 sec. 4.6, but Sign does
		//  not handle this directly. It returns the signature as a pair of big integers.
		r, s, serr := dsa.Sign(rand.Reader, privatekey, signhash[:hlen])
		if serr != nil {
			fmt.Println(serr)
			os.Exit(1)
		}

		// We first output R, then S with a newline in between as required by
		//  the ECDSA interface
		answerR := leftPadText(r.Text(16), 20)
		answerS := leftPadText(s.Text(16), 20)
		fmt.Printf("%s\n%s\n", answerR, answerS)
	} else {
		// if we are not signing, we are verifying :
		r = fromBase16(args[4])
		s = fromBase16(args[5])
		verifystatus := dsa.Verify(pubkey, signhash[:hlen], r, s)
		fmt.Println(verifystatus)
	}
}

// leftPadText will ensure the string are in hexadecimal form and satisfy with the
//  DSA signature length of 160bits.
func leftPadText(text string, size int) string {
	n := len(text)
	size = 2 * size
	if n > size {
		n = size
	}
	return strings.Repeat("0", size-n) + text
}
