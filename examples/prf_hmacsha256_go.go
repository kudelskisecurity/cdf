package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
)

func main() {
	k, _ := hex.DecodeString(os.Args[1])
	in, _ := hex.DecodeString(os.Args[2])

	h := hmac.New(sha256.New, k)
	h.Write([]byte(in))
	tag := hex.EncodeToString(h.Sum(nil))

	fmt.Println(tag)
}
