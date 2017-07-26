package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"os"

	"github.com/veorq/cdf/cdf-lib"
)

var interf string
var interfaces = map[string]bool{
	//"aenc":  true,
	"dsa":     true,
	"enc":     true,
	"ecdsa":   true,
	"ecdh":    true,
	"rsaenc":  true,
	"rsasign": true,
	"prf":     true,
	"xof":     true,
}

// usage() is called when the input doesn't seem to match an accepted pattern, it also serves as help display
func usage() {
	flag.Usage()
	fmt.Println("To perform the tests: \ncdf interface path/to/program1 path/to/program2")
	fmt.Println("Interfaces and their programs' i/o:")
	fmt.Println("\tecdsa\t[privkey msg -> sig] [pubkey sig msg -> validity]")
	fmt.Println("\tenc\t[key plaintext -> ciphertext] [key ciphertext -> plaintext]")
	fmt.Println("\tdsa\t[privkey msg -> sig] [pubkey msg sig -> validity]")
	fmt.Println("\tprf\t[key msg -> tag] [key msg -> tag]")
	fmt.Println("\trsaenc\t[pubkey plaintext -> ciphertext] [privkey ciphertext -> plaintext]")
	fmt.Println("\trsasign\t[privkey msg -> sign] [pubkey sign msg -> validity]")
	fmt.Println("\txof\t[message -> hash] [message -> hash]")
}

// init() is a function to handle flags initialization and parsing. It will initialize our flags to parse the Args data, must be done before using flag.Args(). It also perform basic existence checks on the provided program path. If something is missing, it falls back to usage() which will exit gracefully.
func init() {
	// the -t n flag allows to run n timing tests using the dudect method.
	cdf.TestTimings = flag.Int("t", 0, "to perform N timing leak tests, specify N. It may take hours.")
	// the -h flag can be used to specify that the provided programs both support the optional -h flag
	cdf.TestHashes = flag.Bool("h", false, "specify that the provided programs both support the optional -h flag.")
	// the -v flag can be used to force verbose logging
	cdf.ForceVerbose = flag.Bool("v", false, "force the VerboseLog option to true.")

	flag.Parse()
	// check that we've three arguments left
	nbArgs := len(flag.Args())
	if nbArgs != 3 {
		usage()
		os.Exit(1)
	}

	if _, ok := interfaces[flag.Arg(0)]; ok {
		interf = flag.Arg(0)
	} else {
		log.Fatalln("invalid interface")
	}

	// get programs' paths, check existence
	cdf.Prog1 = flag.Arg(1)
	cdf.Prog2 = flag.Arg(2)
	if _, err := os.Stat(cdf.Prog1); os.IsNotExist(err) {
		log.Fatalln("this file doesn't exist: ", cdf.Prog1)
	}
	if _, err := os.Stat(cdf.Prog2); os.IsNotExist(err) {
		log.Fatalln("this file doesn't exist:", cdf.Prog2)
	}
}

func main() {
	logFile, err := os.OpenFile("log.txt", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalln("Failed to open log file:", err)
	}
	// close logFile on exit checking for its error to ensure everything get written.
	defer func() {
		if err := logFile.Close(); err != nil {
			panic(err)
		}
	}()

	cdf.InitLog(logFile)

	// clear the screen since we are not in usage mode
	cdf.TermClear()
	cdf.LogInfo.Println("Running CDF:")

	// get config and show
	configFile, err := os.Open("config.json")
	if err != nil {
		log.Fatalln(err)
	}
	// close configFile on exit checking for its error:
	defer func() {
		if err := configFile.Close(); err != nil {
			panic(err)
		}
	}()

	if err := json.NewDecoder(configFile).Decode(&cdf.Config); err != nil {
		log.Fatalln(err)
	}
	if cdf.Config.Timeout == 0 { // we specify a default timeout
		cdf.Config.Timeout = 10
	}
	cdf.LogInfo.Printf("config: %+v", cdf.Config)

	// disable logging if the setting is not set
	if !cdf.Config.VerboseLog && !*cdf.ForceVerbose {
		cdf.DisableLogFile()
	}
	// init prng
	var src = rand.NewSource(cdf.Config.Seed)
	cdf.Prng = rand.New(src)

	// depending on the selected interface, we run the according test function
	switch interf {
	case "dsa":
		err = cdf.TestDsa()
		break
	case "ecdsa":
		err = cdf.TestEcdsa()
		break
	case "enc":
		err = cdf.TestEnc()
		break
	case "rsaenc":
		err = cdf.TestRSAenc()
		break
	case "rsasign":
		err = cdf.TestRSAsign()
		break
	case "prf":
		err = cdf.TestPrf()
		break
	case "xof":
		err = cdf.TestXof()
		break
	}

	if err == nil {
		cdf.LogSuccess.Println("test completed without error!")
	} else {
		cdf.LogWarning.Println(err)
	}

	cdf.LogInfo.Println("exiting")
}
