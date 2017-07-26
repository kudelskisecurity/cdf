package cdf

import (
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"
)

// TestEcdsa implements the cdf interface for ECDSA signature and verification scheme
func TestEcdsa() error {
	LogInfo.Print("testing ecdsa")

	failed := false
	// Testing Message length
	if err := testEcdsaMsgLen(); err != nil {
		failed = true
		LogError.Println("while testing messages lengths:", err)
	} else {
		LogSuccess.Println("message lengths tested without error.")
	}

	// Testing hash length
	if *TestHashes { // test only if the -h flag is supported
		if err := testEcdsaHashLen(); err != nil {
			failed = true
			LogError.Println("while testing hash lengths:", err)
		} else {
			LogSuccess.Println("hash lengths tested without error.")
		}
	}

	// Testing specific point
	if err := testEcdsaPoints(); err != nil {
		failed = true
		//LogError.Println("while testing specific edge cases:", err)
	}

	if failed {
		fmt.Print("\n")
		return errors.New("one of more tests failed")
	}

	return nil
}

// testEcdsaMsgLen is simply calling the testEcdsaConsistency function on
//  the full range from MinMsgLen to MaxMsgLen, on a randomly generated message
//  (relying on the seed set in Config.json)
func testEcdsaMsgLen() (mainErr error) {
	TermPrepareFor(1)
	// generate random chars in the hex range to try and sign those
	msg := randomHex(Config.MaxMsgLen)

	LogInfo.Println("testing different message's lengths, from ", Config.MinMsgLen, "to", Config.MaxMsgLen, "bytes")
	argsP1 := []string{Config.EcdsaX, Config.EcdsaY, Config.EcdsaD}
	argsP2 := []string{Config.EcdsaX, Config.EcdsaY}
	mainErr = testEcdsaConsistency(msg, argsP1, argsP2, 0)
	return
}

// testEcdsaHashLen attempt to test the Ecdsa process using different hash
//  lengths, notably bigger hash than the group size. This test will be more
//  useful in the deterministic Ecdsa case, since we can compare its output against
//  the other one to catch no-same tags cases (i.e hash lengths' handling problems
//  leading to wrong truncation of the hash, typically)
func testEcdsaHashLen() error {
	var first int
	TermPrepareFor(1)
	var mainErr MultiError
	hasSame := false

	msg := randomHex(Config.MaxMsgLen)

	LogInfo.Println("testing different hash's lengths")
	toTest := make(map[string]int)
	TermPrepareFor(3)
	// we should add a setting maybe to have the hash range to test?
	temp := Config.MinMsgLen
	for i := 1; i < Config.MaxMsgLen/2; i++ {
		id := "ecdsa#buf#" + strconv.Itoa(i)
		TermDisplay(3, "%d / %d \n", i+1, Config.MaxMsgLen/2)

		Config.MinMsgLen = i * 2
		argsP2 := []string{"-h", msg[:i*2], Config.EcdsaX, Config.EcdsaY}
		argsP1 := append(argsP2, Config.EcdsaD)
		LogToFile.Println("About to run testEcdsaConsistency for HashLen test")
		if err := testEcdsaConsistency(msg[:i*2], argsP1, argsP2, 1); err != nil {
			mainErr = append(mainErr, err)
			continue
		}
		LogToFile.Println("Finished to run testEcdsaConsistency:", mainErr)

		out, err := runProg(Prog1, id, append(argsP1, msg[:i*2]))
		if err != nil {
			mainErr = append(mainErr, err)
			continue
		}

		// Then we check if the tag is the same as a previous one, since it
		//  should never be the case.
		// Note that this is more useful in the deterministic ECDSA case than
		//  in general.
		if toTest[out] > 0 {
			hasSame = true
			mainErr = append(mainErr, fmt.Errorf("Same tag as with buff %d with len %d on job %s. ",
				toTest[out], i, id))
			if first == 0 {
				first = i
			}
		}
		toTest[out] = i
	}
	Config.MinMsgLen = temp
	if len(mainErr) > 0 {
		if hasSame {
			mainErr = append(mainErr, fmt.Errorf("Note that same tags are expected if you are using ECDSA deterministic as per RFC6979. If you are not, then this is a problem. First problem encountered with size %d", first))
		}
		return mainErr
	}
	return nil
}

// testEcdsaConsistency just tests the ECDSA signature on different message
//  lengths for the given msg, starting from MinMsgLen and for at most maxIter
//  iterations or reaches the value MaxMsgLen set in the Config.json file
func testEcdsaConsistency(msg string, argsP1, argsP2 []string, maxIter int) (mainErr error) {
	LogInfo.Println("testing ecdsa consistency")
	nbIter := maxIter
	if nbIter+Config.MinMsgLen >= Config.MaxMsgLen || maxIter <= 0 {
		nbIter = (Config.MaxMsgLen-Config.MinMsgLen)/2 + 1
	}
	if len(msg)/2 < nbIter || len(msg) < Config.MinMsgLen {
		log.Fatalln("The message provided is not big enough to be processed")
	}

	// Initializing a common, unbuffered, channel which gives tasks to
	//  the worker goroutines.
	msgs := make(chan string)
	errs := make(chan error, nbIter)
	// Spawn some worker goroutines
	var wg sync.WaitGroup
	for j := uint(0); j < Config.Concurrency; j++ {
		wg.Add(1)
		go func() {
			for m := range msgs {
				id := "ecdsa#" + strconv.Itoa(len(m))
				// We cannot use argsP1, we have to create a copy,
				//  to keep argsP1 unchanged
				argsP1T := append(argsP1, m)

				// We run the first program:
				out1 := runOrExitOnErr(Prog1, id, argsP1T...)

				out1Arr := strings.Split(out1, "\n")

				//fmt.Println("\nGot:", out1)
				// it is necessary to trim again after splitting to remove the CR
				rOut := strings.TrimSpace(out1Arr[0])
				sOut := strings.TrimSpace(out1Arr[1])

				argsP2T := append(argsP2, rOut, sOut, m)
				// we run the second program:
				outStr2 := runOrExitOnErr(Prog2, id, argsP2T...)

				if trueStr != outStr2 {
					fmt.Print("\n")
					LogWarning.Printf("verification failed on length %d", len(m))
					fmt.Print("\n")
					LogError.Println(strings.Join(append(
						[]string{"failed to run on length ", strconv.Itoa(len(m)),
							" ", Prog2}, argsP2T...), " "))
					LogError.Println(append([]string{"After running:", Prog1},
						argsP1T...))
					LogWarning.Println(argsP2T[:len(argsP1T)-1])
					TermPrepareFor(4)
					errs <- fmt.Errorf("verification error on job %s and length %d", id, len(m))
				}
			}
			wg.Done()
		}()
	}

	// There we could argue that the MinMsgLen should always be 1 byte.
	// We ignore the Config.MsgIncrement since we are testing each byte-length
	for i := Config.MinMsgLen; i < nbIter*2+Config.MinMsgLen; i += 2 {
		TermPrintInline(1, "%d / %d", (i-Config.MinMsgLen)/2+1, nbIter)
		// we populate our channel:
		msgs <- msg[:i]
	}
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
	TermPrepareFor(1)
	return nil
}

func testEcdsaPoints() error {
	TermPrepareFor(1)
	var mainErr MultiError
	// firstly we'll test both program against the 0,0 coordinate:
	if err := testEcdsaZeroPoint(Prog1); err != nil {
		//LogWarning.Println(err)
		mainErr = append(mainErr,
			fmt.Errorf("%s accepts the (0,0) coordinate and 0 as private integer:\n%v", Prog1, err))
	}

	if err := testEcdsaZeroPoint(Prog2); err != nil {
		//LogWarning.Println(err)
		mainErr = append(mainErr,
			fmt.Errorf("%s accepts the (0,0) coordinate and 0 as private integer:\n%v", Prog2, err))
	}

	TermPrepareFor(1)
	// next, we test the verification against the 0, s and the r, 0 signatures
	if err := testEcdsaZeroSign(Prog1); err != nil {
		mainErr = append(mainErr, err)
	}

	if err := testEcdsaZeroSign(Prog2); err != nil {
		mainErr = append(mainErr, err)
	}

	TermPrepareFor(1)

	if *TestHashes {
		if err := testEcdsaZeroHash(Prog1); err != nil {
			mainErr = append(mainErr, err)
		}

		if err := testEcdsaZeroHash(Prog2); err != nil {
			mainErr = append(mainErr, err)
		}
		TermPrepareFor(1)

		if err := testInfiniteLoop(Prog1); err != nil {
			mainErr = append(mainErr, err)
		}

		if err := testInfiniteLoop(Prog2); err != nil {
			mainErr = append(mainErr, err)
		}
	}

	TermPrepareFor(1)
	if len(mainErr) > 0 {
		return mainErr
	}
	return nil
}

// testEcdsaZeroPoint is a simple trial to sign using the 0,0 coordinate as a key
//  and the 0 integer as a private key. Note that the point (0,0) is never on a curve
//  in short Weierstrass form with a non-zero b parameter.
func testEcdsaZeroPoint(prog string) error {
	LogInfo.Printf("testing %s against the 0,0 coordinate.\n", prog)
	// The point 0,0 shouldn't be accepted as a valid point, so let us try with it:
	id := "ecdsa#pts#0-0_" + prog
	msg := randomHex(Config.MinMsgLen)

	argsP := []string{"00", "00", "00", msg}
	out, err := runProg(prog, id, argsP)
	if err != nil {
		LogToFile.Println("As expected,", id, "failed:", out, "\nGot error:", err)
		LogSuccess.Println(prog, " refused to sign using (0,0) and 0 as private key.")
		return nil
	}
	LogWarning.Println(prog, " signed using (0,0) and 0 as private key without error.")
	return fmt.Errorf("\tit returned:\n%s,\n\ton message %s", out, msg)
}

func testEcdsaZeroSign(prog string) error {
	LogInfo.Printf("testing %s against the null signatures.\n", prog)
	id := "ecdsa#rs#0-0_" + prog
	argsP := []string{Config.EcdsaX, Config.EcdsaY, "00", "00", "434343"}
	list := []string{"00", "01"}

	for _, a := range list {
		for _, b := range list {
			if a == "01" && b == "01" {
				break
			}
			argsP[2] = a
			argsP[3] = b
			out, err := runProg(prog, id, argsP)
			if err != nil {
				LogToFile.Println("As expected, ", id, "failed:", out, "\nGot error:", err)
				LogSuccess.Println(prog, "rejected r=", a, ", s=", b, " with an error.")
				continue
			}
			if out == trueStr {
				return fmt.Errorf("%s validated the invalid signature:\nr=%s,\ns=%s", prog, a, b)
			}
			LogInfo.Println(prog, "rejected r=", a, ", s=", b, " without error.")
		}
	}

	return nil
}

// testEcdsaZeroHash is a simple trial to verify using a wrong 00 hash and
//  using otherwise valid values as x, y, r and s to fool the standard ECDSA
//  verification into validation
func testEcdsaZeroHash(prog string) error {
	LogInfo.Printf("testing %s against the 00 hash.\n", prog)
	// The point 0,0 shouldn't be accepted as a valid point, so let us try with it:
	id := "ecdsa#hash#00_" + prog

	argsP := []string{"-h", "00", Config.EcdsaX, Config.EcdsaY, Config.EcdsaX, Config.EcdsaX, "DEADC0DE"}
	out, err := runProg(prog, id, argsP)
	if err != nil {
		LogToFile.Println("As expected,", id, "failed:", out, "\nGot error:", err)
		LogSuccess.Println(prog, "didn't accept this degenerated case.")
		return nil
	}
	if out == trueStr {
		LogError.Println(prog, "accepted the degenerated -h 00 case.")
		return fmt.Errorf("%s accepted the degenerated -h 00 case", prog)
	}
	return fmt.Errorf("%s refused the degenerated -h 00 case without error", prog)
}

// testInfiniteLoop is a simple trial to verify using a wrong 00 hash and
//  using 00 as secret value that the implementation does not fall into an
//  infinite loop. Note that 00 is not amongst the range of the acceptable
//  secret values.
func testInfiniteLoop(prog string) error {
	LogInfo.Printf("testing %s against the invalid inf loop.\n", prog)
	// The point 0,0 shouldn't be accepted as a valid point, so let us try with it:
	id := "ecdsa#infloop_" + prog

	argsP := []string{"-h", "00", Config.EcdsaX, Config.EcdsaY, "00", "DEADC0DE"}
	out, err := runProg(prog, id, argsP)
	if err != nil && strings.Contains(err.Error(), "STOP") {
		LogError.Println(prog, "failed and run into an infinite loop.")
		return fmt.Errorf("%s runned into a degenerate infinite loop: %v", prog, err)
	} else if err != nil {
		LogToFile.Println("As expected,", id, "failed:", out, "\nGot error:", err)
		LogSuccess.Println(prog, "did not run into an infinite loop.")
		return nil
	}
	LogToFile.Println("Unexpected,", id, "did not fail and output:", out, "\non input:", prog, argsP)
	LogWarning.Println(prog, "didn't run into an infinite loop, but did not fail when running:\n", prog, argsP)
	return nil
}
