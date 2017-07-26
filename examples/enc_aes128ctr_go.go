package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
)

func main() {
	if len(os.Args) == 0 {
		fmt.Println("usage: ", os.Args[0], "key msg")
		return
	}
	plaintext, err := hex.DecodeString(os.Args[1])
	if err != nil {
		panic(err)
	}
	if len(plaintext) == 0 {
		panic(errors.New("input: empty message"))
	}
	// By default if only one argument is supplied, the key is assumed to be zeros
	key, _ := hex.DecodeString(strings.Repeat("00", 16))
	if len(os.Args) > 2 {
		if temp, err := hex.DecodeString(os.Args[2]); err != nil {
			panic(err)
		} else {
			key = plaintext
			plaintext = temp
		}
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	ciphertext := make([]byte, len(plaintext))
	iv, _ := hex.DecodeString(strings.Repeat("00", 16))

	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ciphertext, plaintext)

	fmt.Printf("%s\n", hex.EncodeToString(ciphertext))
}
