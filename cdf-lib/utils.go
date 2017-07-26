package cdf

import (
	"bytes"
	"crypto/rsa"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"math/rand"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"
)

// Here are our constants
const (
	hexChars = "abcdef0123456789"
	trueStr  = "true"
)

// Those are the different global variables used by CDF
var (
	ForceVerbose *bool       // enables verbose logging
	LogInfo      *log.Logger // info on cdf execution
	LogSuccess   *log.Logger // all test cases past
	LogWarning   *log.Logger // when a test fails
	LogError     *log.Logger // when something's wrong and unexpected
	LogToFile    *log.Logger // write it to the log file to avoid verbose output
	Prng         *rand.Rand  // non-crypto Prng to randomize tests
	Interf       string      // interface
	Prog1        string      // the path to the first executable
	Prog2        string      // the path to the second executable in interfaces where two are needed
	TestHashes   *bool       // specify if the -h flag is supported by both program
	TestTimings  *int        // specify how many, if any, timing tests should be run
)

// Config contains the global cdf Configuration variables:
// Seed is the Prng seed
// *MsgLen for xof, prf, enc, rsaenc: the different lengths of the tested messages
// *KeyLen for prf, enc: length of key; for rsaenc: length of tested public exponents
// increment* is the number of bytes of increment between two loops in some interfaces
// Rsa* for oaep/pkcs encryption: the primes P,Q, the modulus N, the public exponent E and the private one D. Must be given as hex strings in big endian representation
// Ecdsa*: the X and Y public coordinates to use and the private big integer D, all to be given as hex strings in big endian representation
// Concurrency: the maximum number of concurrent go routine which should be running an exec call to the tested program at the same time
// VerboseLog: a boolean specifying whether all inputs/outputs are to be written to a log file or not. Can help with debugging
var Config struct {
	Seed         int64  `json:"seed"`
	MinMsgLen    int    `json:"minMsgLen"`
	MaxMsgLen    int    `json:"maxMsgLen"`
	IncrementMsg int    `json:"incrementMsg"`
	MinKeyLen    int    `json:"minKeyLen"`
	MaxKeyLen    int    `json:"maxKeyLen"`
	IncrementKey int    `json:"incrementKey"`
	RsaP         string `json:"rsaP"`
	RsaQ         string `json:"rsaQ"`
	RsaN         string `json:"rsaN"`
	RsaE         string `json:"rsaE"`
	RsaD         string `json:"rsaD"`
	EcdsaX       string `json:"ecdsaX"`
	EcdsaY       string `json:"ecdsaY"`
	EcdsaD       string `json:"ecdsaD"`
	DsaP         string `json:"dsaP"`
	DsaQ         string `json:"dsaQ"`
	DsaG         string `json:"dsaG"`
	DsaY         string `json:"dsaY"`
	DsaX         string `json:"dsaX"`
	Timeout      int    `json:"timeout"`
	Concurrency  uint   `json:"concurrency"`
	VerboseLog   bool   `json:"verboseLog"`
}

// MultiError allows to store multiple errors
// like those we get from our external tests
type MultiError []error

// (MultiError) Error implements the error interface for our MultiError type
func (m MultiError) Error() string {
	s, n := "", 0
	for _, e := range m {
		if e != nil {
			s += "\n" + e.Error()
			n++
		}
	}
	switch n {
	case 0:
		return "(0 error)"
	case 1:
		return fmt.Sprintf("(1 error)%s", s)
	}
	return fmt.Sprintf("(%d errors)%s", n, s)
}

// InitLog allows one to initialise the logging system to output data to the specified file.
func InitLog(logFile *os.File) {
	if logFile != nil {
		multiO := io.MultiWriter(logFile, os.Stdout)
		multiE := io.MultiWriter(logFile, os.Stderr)

		// Configure loggers
		LogInfo = log.New(multiO, "\x1b[0;36mINFO:\x1b[0m ", 0)
		LogSuccess = log.New(multiO, "\x1b[0;32mSUCCESS:\x1b[0m ", 0)
		LogWarning = log.New(multiO, "\x1b[0;35mWARNING:\x1b[0m ", log.Lshortfile)
		LogError = log.New(multiE, "\x1b[0;31mERROR:\x1b[0m ", log.Lshortfile)
		LogToFile = log.New(logFile, "", log.Ldate|log.Ltime|log.Lshortfile)

		log.SetOutput(multiO)
		LogToFile.Println("Intiliazing logs : done")
	} else {
		LogInfo = log.New(ioutil.Discard, "\x1b[0;36mINFO:\x1b[0m ", 0)
		LogSuccess = log.New(ioutil.Discard, "\x1b[0;32mSUCCESS:\x1b[0m ", 0)
		LogWarning = log.New(ioutil.Discard, "\x1b[0;35mWARNING:\x1b[0m ", log.Lshortfile)
		LogError = log.New(ioutil.Discard, "\x1b[0;31mERROR:\x1b[0m ", log.Lshortfile)
		LogToFile = log.New(ioutil.Discard, "", log.Ldate|log.Ltime|log.Lshortfile)
		log.SetOutput(ioutil.Discard)
		TermView.SetOutput(ioutil.Discard)
	}
}

// randomHex generate len*2 random hex char to have len random bytes
func randomHex(len int) string {
	charNibbles := make([]byte, len*2)
	for i := 0; i < len*2; i++ {
		charNibbles[i] = hexChars[Prng.Uint32()%16]
	}

	return string(charNibbles)
}

// fromBase16 is a helper method to use the prime in hex form, inspired from crypto/rsa/rsa_test.go
func fromBase16(base16 string) *big.Int {
	i, ok := new(big.Int).SetString(base16, 16)
	if !ok {
		log.Fatalln("trying to convert from base16 a bad number: " + base16)
	}
	return i
}

// DisableLogFile reset the different log to output only on Stdout/Stderr and
// disable the verbose LogToFile, with a mere 100ns overhead (according to
// https://gist.github.com/Avinash-Bhat/48c4f06b0cc840d9fd6c)
func DisableLogFile() {
	// we disable the LogToFile completely
	LogToFile.SetFlags(0)
	LogToFile.SetOutput(ioutil.Discard)
	// we reset the other logs to output on the Std outputs
	LogError.SetOutput(os.Stderr)
	LogWarning.SetOutput(os.Stdout)
	LogSuccess.SetOutput(os.Stdout)
	LogInfo.SetOutput(os.Stdout)
	log.SetOutput(os.Stdout)
}

// this is a trick from https://github.com/golang/go/blob/master/src/os/exec/exec_test.go#L32-L44
// which allows us to mimick the exec package in test files!
var execCommand = exec.Command

// runProg is a helper function allowing to run the program with specific arguments
func runProg(prog, runID string, args []string) (string, error) {

	LogToFile.Println(strings.Join(append([]string{"Batch#", runID,
		"Attempting :", prog}, args...), " "))
	var cmd *exec.Cmd
	cmd = execCommand(prog, args...)

	// we link Stdout and Stderr to alternative bytes.Buffer to control the outputs
	var out, outerr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &outerr
	err := cmd.Start()
	if err != nil {
		LogError.Fatalln("Could not start exec Cmd:", err)
	}
	//out, err := cmd.CombinedOutput()
	timer := time.AfterFunc(time.Duration(Config.Timeout)*time.Second, func() { cmd.Process.Kill() })
	err = cmd.Wait()
	if err != nil {
		LogToFile.Println("Error on batch#", runID, "with", prog)
		LogToFile.Println("Program returned:", out.String()+outerr.String())
	} else {
		LogToFile.Println("Batch#", runID, prog,
			"runned successfully, it returned: ", out.String())
	}
	if !timer.Stop() {
		return "", fmt.Errorf("Cmd timed out! STOP")
	}

	return strings.ToLower(strings.TrimSpace(out.String() + outerr.String())), err
}

// runOrExitOnErr invokes runProg and if we encounter an error
// exits by invoking log.Fatal with the error.
func runOrExitOnErr(prog, id string, args ...string) string {
	outStr, err := runProg(prog, id, args)
	if err != nil {
		fmt.Printf("\nExit on: %s\n", outStr)
		LogError.Println(append([]string{"Failed after running:",
			prog}, args...))
		log.Fatalln(err)
	}
	return outStr
}

// bigSqrt is computing the integer square-root of x, for x a big integer
func bigSqrt(x *big.Int) (kx *big.Int) {
	switch x.Sign() {
	case -1:
		panic(-1)
	case 0:
		return big.NewInt(0)
	}

	var px, xk1 big.Int
	kx = big.NewInt(0)
	kx.SetBit(kx, x.BitLen()/2+1, 1)
	for {
		// we applied the iterative formula found on Wikipedia
		xk1.Rsh(xk1.Add(kx, xk1.Div(x, kx)), 1)
		if xk1.Cmp(kx) == 0 || xk1.Cmp(&px) == 0 {
			break
		}
		px.Set(kx)
		kx.Set(&xk1)
	}
	return
}

// Int64ToSort let us fullfill the Sort interface for slices of int64
type Int64ToSort []int64

func (s Int64ToSort) Len() int           { return len(s) }
func (s Int64ToSort) Less(i, j int) bool { return s[i] < s[j] }
func (s Int64ToSort) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

// for dudect
func percentile(x []int64, perc float64) int64 {
	val := int(perc * float64(len(x)))
	if len(x) <= val || 0 >= val {
		log.Fatalln("Error, percentile should be smaller than 1 and bigger than 0. Got:\n", val, len(x), perc)
	}
	sort.Sort(Int64ToSort(x))
	return x[val]
}

// encryptRSA
func encryptRSA(c *big.Int, pub *rsa.PublicKey, m *big.Int) []byte {
	e := big.NewInt(int64(pub.E))
	c.Exp(m, e, pub.N)
	return c.Bytes()
}

// leftPad returns a new slice of length size. The contents of input are right
// aligned in the new slice and its left part is zero initialised as per Go spec.
func leftPad(input []byte, size int) (out []byte) {
	n := len(input)
	if n > size {
		n = size
	}
	out = make([]byte, size)

	copy(out[len(out)-n:], input)
	return
}
