package cdf

import (
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"
)

// TestRSAsign implements the cdf interface for RSA based signature schemes.
// This interface assumes that the Prog1 can sign being given the primes P
// and Q, the public exponent E (since some libs need it to build a private
// key), the private exponent D, all four in hex format and the message:
// ./Prog1 p q e d msg
// It also assumes that Prog2 can verify the signature being given the public
// modulus N and the public exponent E, as well as the signature S
// all given in hex format and the message : ./Prog2 n e s msg
// It does not (for now) assume reflexivity.
func TestRSAsign() error {
	LogInfo.Print("testing rsasign")

	failed := false

	// Generate random hexadecimal data to try and sign those (the tested
	// program are supposed to unhexlify this data to obtain bytes)
	msg := randomHex(Config.MaxMsgLen)
	LogInfo.Println("testing different message's lengths")

	if err := testRsaSignConsistency(msg, Config.RsaN, Config.RsaE, Config.RsaD,
		Config.RsaP, Config.RsaQ, Config.MaxMsgLen); err != nil {
		failed = true
		LogError.Println("while testing messages lengths:", err)
	} else {
		LogSuccess.Println("message's lengths test okay")
	}

	if failed {
		fmt.Print("\n")
		return errors.New("one of more tests failed")
	}

	return nil
}

// testRsaSignConsistency tests the sign/verify process using Prog1
// to sign and Prog2 to verify, for *iter* trials.
func testRsaSignConsistency(msg, N, e, d, P, Q string, iter int) error {
	LogInfo.Println("testing consistency:")

	var errs MultiError

	// Initializing a common, unbuffered channel which gives tasks to
	// the worker goroutines
	msgs := make(chan string)
	// spawn some worker goroutines
	var wg sync.WaitGroup
	for j := uint(0); j < Config.Concurrency; j++ {
		wg.Add(1)
		go func() {
			for m := range msgs { // using range has to be closed later
				runID := fmt.Sprintf("rsasign#%d#%d", iter, len(m))

				args := []string{P, Q, e, d, m}
				// get the message m from channel msgs and sign it
				signature, errc := runProg(Prog1, strconv.Itoa(len(m)), args)
				if errc != nil {
					// Errors which are "expected" should be marked with FAIL
					// in the tested program
					if strings.Contains(signature, "fail") {
						errs = append(errs, fmt.Errorf("FAIL: %v", errc))
						LogToFile.Println("Skipping the rest of job", runID)
						continue
					} else {
						// other errors are not expected by the tested program
						// and we stop there
						fmt.Println("\nUnexpected error on", Prog1)
						fmt.Println("Got output", signature)
						log.Fatalln(errc)
					}
				}

				result, errc := runProg(Prog2, runID,
					[]string{N, e, signature, m})
				if errc != nil {
					// Errors which are "expected" should be marked with FAIL
					if strings.Contains(result, "fail") {
						errs = append(errs, fmt.Errorf("FAIL: %v", errc))
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

				// If the message we fed to the Prog1 is not valid wrt its sign
				//   according to Prog2, an error must have occurred:
				if result != trueStr {
					errs = append(errs,
						fmt.Errorf("verification failed on length %d", len(m)/2))
					LogToFile.Printf("error on inputs : %s \n"+
						"Got outputs\t1: %s\n\t2: %s",
						m, signature, result)
				}
			}
			wg.Done()
		}()
	}

	maxIter := Config.MaxMsgLen * 2         // since the settings are in byte
	incrementMsg := Config.IncrementMsg * 2 // since the settings are in byte
	if maxIter > iter*incrementMsg {
		maxIter = iter * incrementMsg
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
		return errs
	}
	return nil
}
