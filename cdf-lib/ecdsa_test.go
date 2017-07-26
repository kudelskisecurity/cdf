package cdf

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"hash"
	"math/big"
	"strings"
	"testing"
)

func TestTestECDSA(t *testing.T) {
	initForTesting("ECDSA")
	Config.Timeout = 1
	t.Run("testEcdsaMsgLen", func(*testing.T) {
		err := testEcdsaMsgLen()
		if err != nil {
			t.Error("Expected nil, got ", err)
		}
	})
	t.Run("testEcdsaPoints", func(*testing.T) {
		err := testEcdsaPoints()
		// as of Go 1.7.4, the ECDSA function has a bug we detect:
		if err == nil {
			t.Fatalf("The testEcdsaPoints returned without error! We expect it to fail with 2 errors.")
		}
		if !strings.Contains(err.Error(), "(2 errors)") &&
			strings.Count(err.Error(), "accepts the (0,0)") != 2 {
			t.Errorf("Expected 2 errors, got\n%v", err)
		}
	})
	if execCounter != 12 {
		t.Error("Expected 12 executions, got ", execCounter)
	}
}

func ExampleECDSA(args []string) {
	LogToFile.Println("Starting ExampleECDSA")
	// In this example, the args[] begins with an empty value when doing tests
	flag.Parse()
	// The curve used and the hash used
	pubkeyCurve := elliptic.P256()
	var h hash.Hash
	h = sha256.New()

	var signing bool

	LogToFile.Println("Args:", flag.Args())

	switch {
	case len(flag.Args()) == 6:
		signing = false
	case len(flag.Args()) == 5:
		signing = true
	default:
		LogToFile.Fatal("Please provide X, Y, Sign or X, Y, D, Msg as arguments")
	}
	// Key instanciation
	privatekey := new(ecdsa.PrivateKey)
	pubkey := new(ecdsa.PublicKey)

	pubkey.Curve = pubkeyCurve
	pubkey.X = fromBase16(flag.Arg(1))
	pubkey.Y = fromBase16(flag.Arg(2))

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
	signhash = h.Sum(nil)

	if signing {
		// private key instanciation:
		privatekey.PublicKey = *pubkey
		privatekey.D = fromBase16(flag.Arg(3))

		// If signhash is longer than the bit-length of the private key's curve
		// order, signhash will be truncated to that length. It returns the
		// signature as a pair of big integers.
		r, s, serr := ecdsa.Sign(rand.Reader, privatekey, signhash)
		if serr != nil {
			LogToFile.Fatalln(serr)
		}

		// we first output R, then S with a newline in between as required by
		// the ECDSA interface. TODO: check if it needs leftpadding or not.
		fmt.Printf("%s\n%s\n", r.Text(16), s.Text(16))
		LogToFile.Printf("%s\n%s\n", r.Text(16), s.Text(16))
	} else {
		// if we are not signing, we are verifying :
		r = fromBase16(flag.Arg(3))
		s = fromBase16(flag.Arg(4))
		verifystatus := ecdsa.Verify(pubkey, signhash, r, s)
		fmt.Println(verifystatus)
		LogToFile.Println(verifystatus)
	}
	LogToFile.Println("Finished ExampleECDSA")
}
