package cdf

import (
	"errors"
	"fmt"
	"log"
	"math/rand"
	"strconv"
	"strings"
	"sync"
	"time"
)

// TestDsa implements the tests relying on the cdf interface for DSA signature and verification scheme
func TestDsa() error {
	LogInfo.Print("testing dsa")

	failed := false
	// Testing Message length
	if err := testDsaMsgLen(); err != nil {
		failed = true
		LogError.Println("while testing messages lengths:", err)
	} else {
		LogSuccess.Println("message lengths tested without error.")
	}

	if *TestHashes { // test only if the -h flag is supported
		if err := testDsaHashLen(); err != nil {
			failed = true
			LogError.Println("while testing hash lengths:", err)
		} else {
			LogSuccess.Println("hash lengths tested without error.")
		}
	}

	// Testing special cases
	if err := testDsaCases(); err != nil {
		failed = true
		LogError.Println("while testing special cases:", err)
	} else {
		LogSuccess.Println("special cases tested without error.")
	}

	if limit := *TestTimings; limit > 0 {
		dudectTest(limit, Prog1, doOneComputationForDsa, prepareInputsForDsa)
		dudectTest(limit, Prog2, doOneComputationForDsa, prepareInputsForDsa)
	}

	if failed {
		fmt.Print("\n")
		return errors.New("one of more tests failed")
	}

	return nil
}

// testDsaMsgLen is simply calling the testDsaConsistency function on
//  the full range from MinMsgLen to MaxMsgLen, on a randomly generated message
//  (relying on the seed set in Config.json)
func testDsaMsgLen() (mainErr error) {
	TermPrepareFor(1)
	// generate random chars in the hex range to try and sign those
	msg := randomHex(Config.MaxMsgLen)

	LogInfo.Println("testing different message's lengths, from ", Config.MinMsgLen, "to", Config.MaxMsgLen, "bytes")
	argsP1 := []string{Config.DsaP, Config.DsaQ, Config.DsaG, Config.DsaY, Config.DsaX}
	argsP2 := []string{Config.DsaP, Config.DsaQ, Config.DsaG, Config.DsaY}
	mainErr = testDsaConsistency(msg, argsP1, argsP2, 0)
	return
}

// testDsaHashLen attempt to test the Dsa process using different hash
// lengths, notably bigger hash than the group size. This test will be more
// useful in the deterministic Dsa case, since we can compare its output against
// the other one to catch no-same tags cases (i.e hash lengths' handling problems
// leading to wrong truncation of the hash, typically)
func testDsaHashLen() error {
	TermPrepareFor(1)
	var mainErr MultiError
	hasSame := false

	msg := randomHex(Config.MaxMsgLen)

	LogInfo.Println("testing different hash's lengths over ")
	toTest := make(map[string]int)
	TermPrepareFor(3)
	// we should add a setting maybe to have the hash range to test?
	for i := 1; i < Config.MaxMsgLen; i++ {
		id := "dsa#buf#" + strconv.Itoa(i)
		TermDisplay(3, "%d / %d \n", i+1, Config.MaxMsgLen)

		argsP2 := []string{"-h", msg[:i*2], Config.DsaP, Config.DsaQ, Config.DsaG, Config.DsaY}
		argsP1 := append(argsP2, Config.DsaX)
		if err := testDsaConsistency(msg, argsP1, argsP2, 1); err != nil {
			mainErr = append(mainErr, err)
			continue
		}

		out, err := runProg(Prog1, id, append(argsP1, msg))
		if err != nil {
			mainErr = append(mainErr, err)
			continue
		}

		// Then we check if the tag is the same as a previous one, since it
		// should never be the case.
		// Note that this is more useful in the deterministic DSA case than
		// in general.
		if toTest[out] > 0 {
			hasSame = true
			mainErr = append(mainErr, fmt.Errorf("Same tag as with buff %d with len %d on job %s. ",
				toTest[out], i, id))
		}
		toTest[out] = i
	}
	if len(mainErr) > 0 {
		if hasSame {
			mainErr = append(mainErr, fmt.Errorf("Note that same tags are expected if you are using DSA deterministic as per RFC6979. If you are not, then this is a problem."))
		}
		return mainErr
	}
	return nil
}

// testDsaConsistency just tests the DSA signature on different message
// lengths for the given msg, starting from MinMsgLen and for at most maxIter
// iterations or reaches the value MaxMsgLen set in the Config.json file
func testDsaConsistency(msg string, argsP1, argsP2 []string, maxIter int) error {
	LogInfo.Println("testing dsa consistency")
	nbIter := maxIter + Config.MinMsgLen
	if nbIter >= Config.MaxMsgLen || maxIter <= 0 {
		nbIter = Config.MaxMsgLen + 1
	}
	if len(msg) < nbIter {
		log.Fatalln("The message provided is not big enough to be processed")
	}

	// Initializing a common, unbuffered, channel which gives tasks to
	// the worker goroutines.
	msgs := make(chan string)
	errs := make(chan error, nbIter)
	// Spawn some worker goroutines
	var wg sync.WaitGroup
	for j := uint(0); j < Config.Concurrency; j++ {
		wg.Add(1)
		go func() {
			for m := range msgs {
				id := "dsa#" + strconv.Itoa(len(m))
				// We cannot use argsP1, we have to create a copy,
				// to keep argsP1 unchanged
				argsP1T := append(argsP1, m)

				// We run the first program:
				out1 := runOrExitOnErr(Prog1, id, argsP1T...)

				out1Arr := strings.Split(out1, "\n")
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
					fmt.Print("\n\n")
					errs <- fmt.Errorf("verification error on length %d", len(m))
				}
			}
			wg.Done()
		}()
	}

	// There we could argue that the MinMsgLen should always be 1 byte.
	// We ignore the Config.MsgIncrement since we are testing each byte-length
	for i := Config.MinMsgLen; i < nbIter; i++ {
		TermPrintInline(1, "%d / %d", i-Config.MinMsgLen+1, nbIter-Config.MinMsgLen)
		// we populate our channel:
		msgs <- msg[:i*2]
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

// testDSACases is responsible for running the different tests for edge cases
// for DSA. We currently test against 0 inputs, against 1 inputs and other
// degenerated cases. Note that this function is simply a bundle of functions
// which could have been directly added to the main TestDsa one.
func testDsaCases() error {
	TermPrepareFor(1)
	var mainErr MultiError
	// firstly we'll test both program against the 0 values
	if err := testDsaZeros(Prog1); err != nil {
		//LogWarning.Println(err)
		mainErr = append(mainErr, err)
	}

	if err := testDsaZeros(Prog2); err != nil {
		//LogWarning.Println(err)
		mainErr = append(mainErr, err)
	}

	TermPrepareFor(1)
	if err := testDsaOnes(Prog1); err != nil {
		mainErr = append(mainErr, err)
	}

	if err := testDsaOnes(Prog2); err != nil {
		mainErr = append(mainErr, err)
	}

	TermPrepareFor(1)
	// next, we test the verification against the (0, s) and the (r, 0) signatures
	if err := testDsaZeroSign(Prog1); err != nil {
		mainErr = append(mainErr, err)
	}

	if err := testDsaZeroSign(Prog2); err != nil {
		mainErr = append(mainErr, err)
	}

	TermPrepareFor(1)

	if err := testDsaZeroHash(Prog1); err != nil {
		mainErr = append(mainErr, err)
	}

	if err := testDsaZeroHash(Prog2); err != nil {
		mainErr = append(mainErr, err)
	}

	TermPrepareFor(1)
	if len(mainErr) > 0 {
		return mainErr
	}
	return nil
}

// testDsaOnes is a test to sign using the 01 values as a public parameters
// as well as the 01 integer as a private key. This should not be accepted
// by the tested programs, since it means they do not perform correct domain
// parameters checks on their input. Typically it can lead to signature
// independent of the actual message, with r=01.
func testDsaOnes(prog string) error {
	LogInfo.Printf("testing %s against the 01 parameters.\n", prog)
	var mainErr MultiError

	// we take the MinMsgLen since we don't need a big value, we just need any value
	msg := randomHex(Config.MinMsgLen)

	argsP := []string{Config.DsaP, Config.DsaQ, Config.DsaG, Config.DsaY, Config.DsaX, msg}
	var tmp string
	for i := 0; i < 3; i++ {
		id := "dsa#pts#01-" + fmt.Sprint(i) + "_" + prog
		tmp, argsP[i] = argsP[i], "01"
		out, err := runProg(prog, id, argsP)
		argsP[i] = tmp
		if err != nil {
			if strings.Contains(err.Error(), "STOP") {
				mainErr = append(mainErr, err)
				LogWarning.Println(prog, "timed out using 01 as argument ", i+1, "it may indicate an infinite loop.")
			} else {
				LogToFile.Println("As expected,", id, "failed:", out, "\nGot error:", err)
				LogSuccess.Println(prog, "refused to sign using 01 at arg ", i+1)
			}
			continue
		}
		LogWarning.Println(prog, "signed using 01 without error at ", i+1)
		mainErr = append(mainErr, fmt.Errorf("%s let us sign using 01, without error at %d:\n%s",
			prog, i+1, out))
	}

	if len(mainErr) > 0 {
		return mainErr
	}
	return nil
}

// testDsaZeros is a simple trial to sign using the 0 values as a public key as well
// well as the 00 integer as a private key. This can lead to infinite loops, which
// would then trigger the timeout in runProg. This means that the tested program
// does not perform proper parameters checks on its inputs.
func testDsaZeros(prog string) error {
	LogInfo.Printf("testing %s against the 00 parameters.\n", prog)
	var mainErr MultiError

	// we take the MinMsgLen since we don't need a big value, we just need any value
	msg := randomHex(Config.MinMsgLen)

	argsP := []string{Config.DsaP, Config.DsaQ, Config.DsaG, Config.DsaY, Config.DsaX, msg}
	var tmp string
	for i := 0; i < 5; i++ {
		id := "dsa#pts#0-" + fmt.Sprint(i) + "_" + prog
		if i == 3 { // we don't care about Y when testing the signature process
			i++
		}
		tmp, argsP[i] = argsP[i], "00"
		out, err := runProg(prog, id, argsP)
		argsP[i] = tmp
		if err != nil {
			if strings.Contains(err.Error(), "STOP") {
				mainErr = append(mainErr, err)
				LogWarning.Println(prog, " timed out using 00 as argument ", i+1, "it may indicate an infinite loop.")
			} else {
				LogToFile.Println("As expected,", id, "failed:", out, "\nGot error:", err)
				LogSuccess.Println(prog, " refused to sign using 00 at arg ", i+1)
			}
			continue
		}
		LogWarning.Println(prog, " signed using 00 without error at ", i+1)
		mainErr = append(mainErr, fmt.Errorf("%s let us sign using 00, without error at %d", prog, i+1))
	}

	if len(mainErr) > 0 {
		return mainErr
	}
	return nil
}

// pair is simply a struct to allow to write the following test in a nicer way.
type pair struct {
	a string
	b string
}

// testDsaZeroSign is a test to verify invalid signatures, typically the 00
// 01 and q values should be rejected as not in the proper range for r and s.
// Failure to do so can lead to always true signatures, independently of the
// message, which is a security concern if it is easily triggered.
func testDsaZeroSign(prog string) error {
	LogInfo.Printf("testing %s against the null signatures.\n", prog)
	id := "dsa#rs#0-0_" + prog
	argsP := []string{Config.DsaP, Config.DsaQ, Config.DsaG, Config.DsaY, "00", "00", "434343"}
	list := []pair{pair{"00", "00"}, pair{"01", "00"}, pair{"00", "01"},
		pair{"01", Config.DsaQ}} // This may trigger a faulty true answer

	for _, p := range list {
		argsP[4] = p.a
		argsP[5] = p.b
		out, err := runProg(prog, id, argsP)
		if err != nil {
			LogToFile.Println("As expected, ", id, "failed:", out, "\nGot error:", err)
			LogSuccess.Println(prog, "rejected r=", p.a, ", s=", p.b, " with an error.")
			continue
		}
		if out == "true" {
			return fmt.Errorf("%s validated a 0 signature", prog)
		}
		LogInfo.Println(prog, "rejected r=", p.a, ", s=", p.b, " without error.")
	}

	return nil
}

// testDsaZeroHash is a simple trial to verify using a wrong 00 hash and
//  using 01 as x, r and s to fool the standard DSA verification into validation
//  Note that the point (0,0) note that this should never validate, it's not even
//  on the curve in most possible cases (the y coordinate being free, it may be).
func testDsaZeroHash(prog string) error {
	LogInfo.Printf("testing %s against the 00 hash.\n", prog)
	// The point 0,0 shouldn't be accepted as a valid point, so let us try with it:
	id := "dsa#hash#00_" + prog

	argsP := []string{"-h", "00", "01", "42", "01", "01", "434343"}
	out, err := runProg(prog, id, argsP)
	if err != nil {
		LogToFile.Println("As expected,", id, "failed:", out, "\nGot error:", err)
		LogSuccess.Println(prog, "didn't accept this degenerated case, or you did not implement the -h flag.")
		return nil
	}
	if out == trueStr {
		LogError.Println(prog, "accepted the degenerated -h 00 case.")
		return fmt.Errorf("%s accepted the degenerated -h 00 case", prog)
	}
	return fmt.Errorf("%s refused the degenerated -h 00 case without error", prog)
}

// doOneComputationForDsa allows to use the dudect test with this interface.
func doOneComputationForDsa(prog string) func(string) {
	return func(data string) {
		recovered, err := runProg(prog, "dudect-"+prog,
			[]string{Config.DsaP, Config.DsaQ, Config.DsaG, Config.DsaY, Config.DsaX, data})
		if err != nil {
			panic(fmt.Errorf("Error:%v \n leading to: %s", err, recovered))
		}
	}
}

// prepareInputsForDsa generates inputs to test timings leak, for DSA this test
// simply test two message against each other and could benefit from more interesting.
func prepareInputsForDsa() (inputData []string, classes []int) {
	inputData = make([]string, numberMeasurements)
	classes = make([]int, numberMeasurements)
	rn := rand.New(rand.NewSource(time.Now().UnixNano()))
	// we generate two different message and we simply try with them:
	data := randomHex(20)
	data2 := randomHex(20)
	for i := 0; i < numberMeasurements; i++ {
		classes[i] = rn.Intn(2)
		if classes[i] == 0 {
			inputData[i] = data
		} else {
			inputData[i] = data2
		}
	}
	return
}
