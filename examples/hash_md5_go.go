package main

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"log"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		log.Fatalln("Please, provide a message to hash in hexadecimal form.")
	}
	data, err := hex.DecodeString(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%x\n", (md5.Sum(data)))
}
