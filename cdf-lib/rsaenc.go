package cdf

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math/big"
	mrand "math/rand"
	"strconv"
	"strings"
	"sync"
	"time"
)

// TestRSAenc implements the cdf interface for RSA-OAEP encryption.
// This interface assumes that the Prog1 can encrypt being given the public
// modulus N, the public exponent E both in hex format and then a message : ./Prog1 n e msg
// It also assumes that Prog2 can decrypt being given the primes P and Q, the
// public exponent E (since some libs need it to build a private key), the private
// exponent D, all four in hex format and the cipher text : ./Prog2 p q e d cipher
// It does not (yet) assume reflexivity, ie: ./Prog2 n e msg does not need to encrypt.
func TestRSAenc() error {
	LogInfo.Print("testing rsaenc")

	failed := false

	// Generate random hexadecimal data to try and encrypt those (the tested
	// program are supposed to unhexlify this data to obtain Config.MaxMsgLen bytes)
	msg := randomHex(Config.MaxMsgLen)
	LogInfo.Println("testing different message's lengths")

	if err := testRSAencConsistency(msg, Config.RsaN, Config.RsaE, Config.RsaD,
		Config.RsaP, Config.RsaQ, Config.MaxMsgLen); err != nil {
		failed = true
		LogError.Println("while testing messages lengths:", err)
	} else {
		LogSuccess.Println("message's lengths test okay")
	}

	if err := testRSAencPubExponentLen(msg); err != nil {
		failed = true
		LogError.Println("while testing exponent lengths:", err)
	} else {
		LogSuccess.Println("exponent's lengths test okay")
	}

	if err := testRSAencPubMaxExponentLen(msg); err != nil {
		failed = true
		LogError.Println("while testing max exponent support:", err)
	} else {
		LogSuccess.Println("max exponent's lengths test okay")
	}

	if err := testRSAencLargerMod(Prog1); err != nil {
		failed = true
		LogError.Println("while testing bigger than modulus support:\n", err)
	} else {
		LogSuccess.Println("larger than modulus test okay for", Prog1)
	}
	if err := testRSAencLargerMod(Prog2); err != nil {
		failed = true
		LogError.Println("while testing bigger than modulus support:\n", err)
	} else {
		LogSuccess.Println("larger than modulus test okay for", Prog2)
	}

	if err := testRSAsmallD(); err != nil {
		failed = true
		LogError.Println("while testing D against Wiener's attack:\n", err)
	} else {
		LogSuccess.Println("private exponent vs Wiener's attack: okay")
	}

	if limit := *TestTimings; limit > 0 {
		TermPrepareFor(1)
		LogInfo.Println("Starting timing tests, those may take hours depending on the max number of iterations set.")
		dudectTest(limit, Prog1, doOneComputationForRsa, prepareInputsForRsa)
		dudectTest(limit, Prog2, doOneComputationForRsa, prepareInputsForRsa)
		for i := 0; i <= 9; i++ {
			if i == 7 && len(Config.RsaN) != 2048 {
				LogInfo.Println("Specific tests for keys with a modulus of 1024 bits were skipped.")
				break
			}
			dudectTest(limit, Prog1, doOneComputationForRsa, prepareInputsForSpecialRsa(i))
			dudectTest(limit, Prog2, doOneComputationForRsa, prepareInputsForSpecialRsa(i))
		}
	}
	if failed {
		fmt.Print("\n")
		return errors.New("one of more tests failed")
	}

	return nil
}

// generateExponents generates a random bitlen-bit prime E and the
// associated private exponent D, given n and phi(n)
func generateExponents(bitlen int) (finE, finD string) {
	if bitlen == 1 {
		LogError.Fatalln("There are no prime of bit length 1")
	}
	// We initialize our variables
	start := new(big.Int)
	one := new(big.Int).SetUint64(1)
	two := new(big.Int).SetUint64(2)
	min := new(big.Int).Lsh(one, uint(bitlen-1)) // using the left shift operator
	p11 := new(big.Int).Sub(fromBase16(Config.RsaP), one)
	p21 := new(big.Int).Sub(fromBase16(Config.RsaQ), one)
	Phi := new(big.Int).Mul(p11, p21)
	D := new(big.Int)
	// It may be better to not use our seeded Prng, but to seed a new one
	r := Prng // rand.New(rand.NewSource(time.Now().UnixNano()))

	// We generate a number between 0 and 2^bitlen while setting one to 2^bitlen
	start.Rand(r, min)
	// Ensure we do not start with an even number
	if 0 != one.Cmp(new(big.Int).Mod(start, two)) {
		start.Add(start, one)
	}
	// We begin looking for a prime bigger than 2^bitlen + random value :
	E := new(big.Int).Add(start, min)
	errCounter := 0
	for found := false; !found; {
		// we use 8 times a Miller-Rabin test, so we have < 1/4^8 prob to have
		//  a false positive it is not secure, but sufficient for our purpose
		found = E.ProbablyPrime(8)

		if found {
			// since it is probabilist, it does not hurt to cover this border
			//  case where the random start was too big
			if E.BitLen() >= bitlen+1 {
				//LogInfo.Println("e was too big, retrying", min, start, E)
				found = false
				E.Sub(E, min)
				errCounter++
			}
			// Ensure our potential E is coprime with Phi to get a valid key
			if 0 != one.Cmp(new(big.Int).GCD(nil, nil, E, Phi)) {
				LogToFile.Println("e was relatively prime to phi, \n\tmin:",
					min, "\n\tstart:", start, "\n\tE:", E, "\nRetrying.")
				found = false
				errCounter++
			}
		}
		// if found is no true, then E is not probably prime, so we can jump to
		//  the next odd integer
		if !found {
			E.Add(E, two)
		}
		// It is possible to get in a loop, we arbitrarily assume we are stuck
		//  after 100 errors
		if errCounter > 100 {
			//			fmt.Printf(LINE_UP)
			LogWarning.Printf("unable to find a public exponent compatible "+
				"with bit-length %d\n", bitlen)
			LogInfo.Println("consider using safer primes e.g. of the form " +
				"p1=2a+1 and p2=2b+1 for a and b primes " +
				"if you want to test this length.")
			LogInfo.Println("skipping bit-length:", bitlen)
			TermPrepareFor(1)
			return generateExponents(bitlen + 1)
		}
	}
	// The result is converted to hex since the interface is feeding the keys
	// as hex values
	finE = E.Text(16)
	// Calculate D as the inverse of E mod Phi, it exists since we checked E was
	// coprime with Phi
	D = D.ModInverse(E, Phi)
	finD = D.Text(16)

	return finE, finD
}

// testRSAencPubExponentLen tests exponent length support, bit per bit, starting
// from 2 bits however it is possible, depending on the selected primes and
// resulting modulus that there are no primes on a given (small) bitlength that
// is coprime with the phi(N), should it be the case, a Warning is issued and
// it skips to a bigger bit-length, this skipping will statistically not lead
// to any bug, so bordercases are not yet covered.
func testRSAencPubExponentLen(msg string) error {
	var errs MultiError

	TermPrepareFor(1)
	LogInfo.Println("testing exponent lengths")

	var N, e, d, P, Q string
	N = Config.RsaN
	P = Config.RsaP
	Q = Config.RsaQ

	// Starting from 2 since there are no prime of bit length 1, while 3 is
	// a prime a bit length 2
	TermPrepareFor(3)
	for i := 2; i <= Config.MaxKeyLen; i++ {
		TermDisplay(3, "trying with public exponent of bit-length %d / %d",
			i, Config.MaxKeyLen)
		e, d = generateExponents(i)
		// note we are doing only 3 tests on msg of size 1,2 and 3 :
		erc := testRSAencConsistency(msg, N, e, d, P, Q, 3)
		if erc != nil {
			LogWarning.Printf("problem with bit-length %d:\n%s\n",
				i, erc.Error())
			TermPrepareFor(4)
			errs = append(errs, fmt.Errorf("exponents test failed on  bit-length %d", i))
		}
	}
	LogInfo.Println("exponent test finished")
	if len(errs) > 0 {
		fmt.Print(lineUp(3))
		return errs
	}
	return nil
}

// testRSAencConsistency tests the encryption/decryption process using Prog1
// to encrypt and Prog2 to decrypt, for *iter* trials.
func testRSAencConsistency(msg, N, e, d, P, Q string, iter int) error {
	LogInfo.Println("testing consistency:")

	// the general settings for that test
	maxIter := Config.MaxMsgLen * 2         // since the settings are in byte
	incrementMsg := Config.IncrementMsg * 2 // since the settings are in byte
	if maxIter > iter*incrementMsg {
		maxIter = iter * incrementMsg
	}

	// Initializing a common, unbuffered channel which gives tasks to
	// the worker goroutines
	msgs := make(chan string)
	errs := make(chan error, maxIter)
	// spawn some worker goroutines
	var wg sync.WaitGroup
	for j := uint(0); j < Config.Concurrency; j++ {
		wg.Add(1)
		go func() {
			for m := range msgs { // using range has to be closed later
				runID := fmt.Sprintf("rsaenc#%d#%d", iter, len(m))

				args := []string{N, e, m}
				// get the message m from channel msgs and encrypt it
				cipher, errc := runProg(Prog1, strconv.Itoa(len(m)), args)
				if errc != nil {
					// Errors which are "expected" should be marked with FAIL
					//  in the tested program
					if strings.Contains(cipher, "fail") {
						errs <- fmt.Errorf("FAIL: %v", errc)
						LogToFile.Println("Skipping the rest of job", runID)
						continue
					} else {
						// other errors are not expected by the tested program
						//  and we stop there
						fmt.Println("\nUnexpected error on", Prog1)
						fmt.Println("Got output", cipher)
						log.Fatalln(errc)
					}
				}

				recovered, errc := runProg(Prog2, runID,
					[]string{P, Q, e, d, cipher})
				if errc != nil {
					// Errors which are "expected" should be marked with FAIL
					if strings.Contains(recovered, "fail") {
						errs <- fmt.Errorf("FAIL: %v", errc)
						LogToFile.Printf("failed to run Prog2 on job#%s", runID)
						continue
					} else { // other errors are not expected and we stop there
						LogError.Printf("failed to run %s on run %s\nerror: %v",
							Prog2, runID, errc)
						LogInfo.Println("after running:", Prog1, args)
						log.Fatalln(errc)
					}
					fmt.Print("\n")
				}

				// If the message we fed to the Prog1 does not match the
				//  recovered plaintext from Prog2, an error must have occurred:
				if m != recovered {
					errs <- fmt.Errorf("decryption mismatch on length %d", len(m)/2)
					LogToFile.Printf("decryption mismatch on inputs : %s \n"+
						"Got outputs\t1: %s\n\t2: %s",
						m, cipher, recovered)
				}
			}
			wg.Done()
		}()
	}

	// Let us now fill our channel with the messages to be processed:
	for i := Config.MinMsgLen * 2; i <= maxIter; i += incrementMsg {
		TermPrintInline(1, "%d / %d", i/incrementMsg, maxIter/incrementMsg)
		msgs <- msg[:i]
	}

	fmt.Print("\n")
	// We have to close the channel to inform the receiver that there are
	//  no more messages coming.
	close(msgs)
	// let us wait for our workers to finish
	wg.Wait()

	if len(errs) > 0 {
		// Initializing the return value
		var mainErr MultiError
		firstErr := true
		for len(errs) > 0 {
			e := <-errs
			if firstErr {
				firstErr = false
				// This is not guaranteed to be the 1st one, but almost
				LogInfo.Println("First error:", e)
			}
			mainErr = append(mainErr, e)
		}
		TermPrepareFor(1)
		return mainErr
	}
	return nil
}

// testRSAencPubMaxExponentLen will test the maximal size of the exponent
// the tested program support. Typically it would detect when a library is
// using an integer instead of a big integer to store the exponent value.
func testRSAencPubMaxExponentLen(msg string) (mainErr error) {
	TermPrepareFor(1)
	LogInfo.Println("testing max exponent lengths")
	failed := false

	var N, e, d, P, Q string
	N = Config.RsaN
	P = Config.RsaP
	Q = Config.RsaQ

	nTests := 0
	fTests := 0

	var errs MultiError
	maxExp := 0

	TermPrepareFor(3)
	// the range is currently hard-coded, ideally it should be generated using
	// some kind of dichotomic-search like process with an upper limit
	for iter, i := range [...]int{29, 30, 31, 32, 62, 63, 64, 126, 127, 128} {
		e, d = generateExponents(i)
		TermDisplay(3, "trying with public exponent of bit-length %d/%d", i, 128)
		erc := testRSAencConsistency(msg, N, e, d, P, Q, 1)
		if erc != nil {
			failed = true
			if maxExp == 0 {
				maxExp = i
			}
			errs = append(errs, fmt.Errorf("problem with bit-length %d", i))
			fTests++
		}
		nTests = iter + 1
	}
	if failed {
		mainErr = fmt.Errorf("%d / %d exponents' tests failed:\n%v\n"+
			"it seems like the max exponent bit length of one of the programs"+
			" is smaller than %d",
			fTests, nTests, errs,
			maxExp)
	}
	LogInfo.Println("max supported exponent test finished")

	return mainErr
}

// testRSAencLargerMod tests the provided program against messages larger than
// the used modulus, it does so by computing the size of the modulus and
// generating a bigger message, before tring it and expecting an error. If no
// error is thrown, then it'll return an error, otherwise it returns nil.
// (TODO:We may argue later whether the throwned error should be outputed or not.
// It is sowieso logged by the runProg function.)
func testRSAencLargerMod(prog string) error {
	TermPrepareFor(1)
	LogInfo.Println("testing larger than modulus against", prog)
	id := "rsaenc#large_" + prog

	var N, e string
	N = Config.RsaN
	e = Config.RsaE
	msg := randomHex((fromBase16(N).BitLen()+7)/8 + 8)

	argsP := []string{N, e, msg}
	_, err := runProg(prog, id, argsP)
	if err == nil {
		return fmt.Errorf("%s accepted a message larged than the modulus", prog)
	}
	return nil
}

// testRSAsmallD is a side-check against the provided key, so it doesn't mean
// much, unless you are using real keys. Wiener's attack works when d is small,
// so let us check if it may work with the current key. (It may also not.)
func testRSAsmallD() error {
	TermPrepareFor(1)
	LogInfo.Println("testing current key against Wiener's attack precondition")

	N := fromBase16(Config.RsaN)
	D := fromBase16(Config.RsaD)
	temp := big.NewInt(0).Div(bigSqrt(bigSqrt(N)), big.NewInt(3))

	if D.Cmp(temp) == -1 {
		return fmt.Errorf("private exponent too small, may be vulnerable to Wiener's attack")
	}
	return nil
}

// doOneComputationForRsa provides the functions we can pass to the timing tests
// to perform rsa on the desired program.
func doOneComputationForRsa(prog string) func(string) {
	return func(data string) {
		recovered, err := runProg(prog, "dudect-"+prog,
			[]string{Config.RsaP, Config.RsaQ, Config.RsaE, Config.RsaD, data})
		if err == nil { // odds are too odd for the decryption to be successful, yet it avoids any compiler optimisation since we use recovered in it.
			panic(fmt.Errorf("decryption successful: %s", recovered))
		}
	}
}

// prepareInputs generates inputs to test timings leak, it is a bit optimized
// for OAEP but not too much.
func prepareInputsForRsa() (inputData []string, classes []int) {
	inputData = make([]string, numberMeasurements)
	classes = make([]int, numberMeasurements)
	rn := mrand.New(mrand.NewSource(time.Now().UnixNano()))

	// we initialize the key and the big integers we need :
	N := fromBase16(Config.RsaN)
	k := uint((N.BitLen() + 7) / 8)                    // byte len
	lowerB := new(big.Int).Lsh(big.NewInt(1), 8*(k-1)) // one byte less
	upperB := new(big.Int).Sub(N, lowerB)
	ee, err := strconv.ParseInt(Config.RsaE, 16, 8)
	if err != nil {
		log.Fatal(err)
	}
	pubK := &rsa.PublicKey{N: N, E: int(ee)}
	for i := 0; i < numberMeasurements; i++ {
		classes[i] = rn.Intn(2)
		var tmp *big.Int
		if classes[i] == 0 { // we don't want a 00 MSB
			// we generate a big int of 255 bytes
			tmp = new(big.Int).Rand(rn, upperB)
			tmp.Add(tmp, lowerB) // ensure us to be have 256 bytes
		} else { // we want a 00 MSB:
			tmp = new(big.Int).Rand(rn, lowerB)
		}
		// we craft the cipher, since we know the key:
		// we encrypt to be sure of its size and format when decrypted: it'll be ee
		data := encryptRSA(new(big.Int), pubK, tmp)

		inputData[i] = hex.EncodeToString(data)
	}
	return
}

// prepareInputsForSpecialRsa generates inputs to test timings leak, it is a bit optimized
// for OAEP but not too much. It also use known inputs that may cause stange behavior.
// Those special inputs are thought for 1024-bit modulus using 65537 as public exponent.
// Those are coming from the RSA Case Study by Jaffe & al
func prepareInputsForSpecialRsa(special int) func() ([]string, []int) {
	LogInfo.Printf("Testing case %d", special)
	return func() (inputData []string, classes []int) {
		inputData = make([]string, numberMeasurements)
		classes = make([]int, numberMeasurements)
		rn := mrand.New(mrand.NewSource(time.Now().UnixNano()))

		// we initialize the key and the big integers we need :
		N := fromBase16(Config.RsaN)
		ee, err := strconv.ParseInt(Config.RsaE, 16, 8)
		if err != nil {
			log.Fatal(err)
		}
		pubK := &rsa.PublicKey{N: N, E: int(ee)}
		// we craft the cipher, since we know the key:
		// we encrypt to be sure of its size and format when decrypted: it'll be ee
		data0, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubK, []byte("Test"), []byte(""))
		if err != nil {
			log.Fatal(err)
		}
		var data []byte

		one := big.NewInt(1)
		P := fromBase16(Config.RsaP)
		k := (N.BitLen() + 7) / 8 // byte len
		// let us take a few of the special test cases for RSA (1024 bits) from "Efficient side­channel	testing	for	public key algorithms: RSA case study" by J.Jaffe & P.Rohatgi, 2009.
		switch special {
		case 0:
			data = []byte{0}
			// we need to be sure to match the right ciphertext length of k bytes,
			//  otherwise the test is meaningless.
			data = leftPad(data, k)
		case 1:
			data = []byte{1}
			data = leftPad(data, k)
		case 2:
			data = []byte{2}
			data = leftPad(data, k)
		case 3:
			data = []byte{3}
			data = leftPad(data, k)
		case 4:
			data = new(big.Int).Sub(N, big.NewInt(1)).Bytes()
			data = leftPad(data, k)
		case 5:
			data = new(big.Int).Sub(N, big.NewInt(2)).Bytes()
			data = leftPad(data, k)
		case 6:
			data = new(big.Int).Sub(N, big.NewInt(3)).Bytes()
			data = leftPad(data, k)
			// from now on, the tests are though for 1024 bits keys
		case 7: // in barrett reduction, an intermediate is zero
			num := new(big.Int).Div(new(big.Int).Lsh(one, 700), P)
			mult := new(big.Int).Mul(num, new(big.Int).Lsh(one, 528))
			denom := new(big.Int).Div(new(big.Int).Lsh(one, 1024), P)
			num.Mul(num, mult)
			data = new(big.Int).Div(num, denom).Bytes()
			data = leftPad(data, k)
		case 8: // in barrett reduction, an intermediate has high hamming weight
			num := new(big.Int).Lsh(one, 1000)
			denom := new(big.Int).Div(new(big.Int).Lsh(one, 1024), P)
			num.Sub(num, one)
			data = new(big.Int).Div(num, denom).Bytes()
			data = leftPad(data, k)
		case 9: // in barrett reduction, an intermediate is small and low hamming weight
			num := new(big.Int).Lsh(one, 600)
			denom := new(big.Int).Div(new(big.Int).Lsh(one, 1024), P)
			data = new(big.Int).Div(num, denom).Bytes()
			data = leftPad(data, k)
		default:
			log.Fatalln("An unexpected index was provided to the special case RSA input preparation function")
		}
		for i := 0; i < numberMeasurements; i++ {
			classes[i] = rn.Intn(2)
			if classes[i] == 1 { // we want a special case
				inputData[i] = hex.EncodeToString(data)
			} else { // we use the constant ciphertext generated above
				inputData[i] = hex.EncodeToString(data0)
			}
		}
		return
	}
}
