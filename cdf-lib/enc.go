package cdf

import (
	"errors"
	"fmt"
	"log"
	mrand "math/rand"
	"strconv"
	"sync"
	"time"
)

// TestEnc implements the CDF interface for symmetric encryption and decryption
// schemes.
func TestEnc() error {
	LogInfo.Print("testing enc")

	failed := false

	// to warn if the used Config won't cover the whole range
	if (Config.MaxKeyLen-Config.MinKeyLen)%Config.IncrementKey != 0 {
		LogWarning.Println("It seems like the incrementKey and the maxKeyLen values don't fit well together")
	}
	if (Config.MaxMsgLen-Config.MinMsgLen)%Config.IncrementMsg != 0 {
		LogWarning.Println("It seems like the incrementMsg and the maxMsgLen values don't fit well together")
	}

	msg := randomHex(Config.MaxMsgLen)
	key := randomHex(Config.MaxKeyLen)

	// key length to use in msg test
	keyAvgNibbles := 2 * Config.MinKeyLen
	// msg length to use in key test
	msgAvgNibbles := 2 * ((Config.MaxMsgLen + Config.MinMsgLen) / 2)

	// Let us call the message length test
	err := testMessLen(key[:keyAvgNibbles], msg)
	if err != nil {
		failed = true
	}

	// Let us call the key length test
	err = testKeyLen(key, msg[:msgAvgNibbles])
	if err != nil {
		failed = true
	}

	if limit := *TestTimings; limit > 0 {
		dudectTest(limit, Prog1, doOneComputationForEnc, prepareInutsForEnc)
		dudectTest(limit, Prog2, doOneComputationForEnc, prepareInutsForEnc)
	}
	if failed {
		fmt.Print("\n")
		return errors.New("one of more tests failed")
	}

	return nil
}

// testKeyLen tests the programs with different key lengths
func testKeyLen(key string, msg string) (mainErr error) {
	TermPrepareFor(1)
	LogInfo.Println("testing key lengths")

	if len(key) < 2*Config.MaxKeyLen {
		LogError.Println("the provided key and MaxKeyLen setting are not compatible")
		return fmt.Errorf("key length and settings mismatch")
	}
	return testProgs(msg, chooseKeys, loopKeyLen(key))
}

// testMessLen tests the programs with different message lengths
func testMessLen(key string, msg string) (mainErr error) {
	TermPrepareFor(1)
	LogInfo.Println("testing message lengths")
	return testProgs(key, chooseMsg, loopMessLen(msg))
}

// loopMessLen is the loop wich is to be used for the testProgs function in
//  the message length case
func loopMessLen(msg string) func(chan string) {
	return func(msgs chan string) {
		TermPrepareFor(1)
		for i := Config.MinMsgLen; i <= Config.MaxMsgLen; i += Config.IncrementMsg {
			TermPrintInline(1, "%d / %d", i, Config.MaxMsgLen)
			// get the first i bytes, ie first i*2 nibbles
			msgs <- msg[:(i * 2)]
		}
	}
}

// loopKeyLen is the loop wich is to be used for the testProgs function in
//  the key length case
func loopKeyLen(key string) func(chan string) {
	return func(keys chan string) {
		TermPrepareFor(1)
		for i := Config.MinKeyLen; i <= Config.MaxKeyLen; i += Config.IncrementKey {
			TermPrintInline(1, "%d / %d", i, Config.MaxKeyLen)
			// get the first i bytes, ie first i*2 nibbles
			keys <- key[:(i * 2)]
		}
	}
}

// chooseKey fixes the key and the message to the provided arguments
func chooseKeys(fixed, iterated string) (k string, m string) {
	m = fixed
	k = iterated
	return
}

// chooseMsg fixes the key and the message to the provided arguments
func chooseMsg(fixed, iterated string) (k string, m string) {
	m = iterated
	k = fixed
	return
}

// testProgs is the basic test in charge of checking the programs Prog1 and
//  Prog2 are respectively encrypting and decrypting correctly with the key
//  and msg arguments permuted as per chooseArgs, the loop function to provide
//  the jobs must be provided. Concurrency is supported, as setted in config.json.
func testProgs(fixed string, chooseArgs func(string, string) (string, string), loopOver func(chan string)) (mainErr error) {
	nbIter := Config.MaxMsgLen
	if Config.MaxKeyLen > nbIter {
		nbIter = Config.MaxKeyLen
	}

	// Initializing a common, unbuffered, channel which gives tasks to the worker goroutines
	jobs := make(chan string)
	errs := make(chan error, nbIter)

	var wg sync.WaitGroup
	// spawn some worker goroutines according to the Concurrency setting in Config.json
	for j := uint(0); j < Config.Concurrency; j++ {
		wg.Add(1) //to be sure to finish all jobs
		go func() {
			for j := range jobs {
				// here we firstly permute the arguments to match our case
				k, m := chooseArgs(fixed, j)
				// we define a job id for logging purpose
				id := "enc#" + strconv.Itoa(len(m)) + "#" + strconv.Itoa(len(k))
				cipher := runOrExitOnErr(Prog1, id, k, m)
				outStr2 := runOrExitOnErr(Prog2, id, k, cipher)

				if m != outStr2 {
					fmt.Print("\n")
					LogWarning.Printf("decryption mismatch on job %s\nInputs :%s %s\n"+
						"Outputs\t1: %s\n\t2: %s\n",
						id, k, m,
						cipher, outStr2)
					errs <- fmt.Errorf("decryption mismatch on job %s", id)
				}
			}
			wg.Done() // report the job as finished
		}()
	}

	// we call the loop function to iterate over the right objects
	loopOver(jobs)

	//we close our channel since it's unbuffered
	close(jobs)
	// let us wait for our workers to finish their jobs
	wg.Wait()

	if len(errs) > 0 {
		// Initializing the return value
		var mainErr MultiError
		firstErr := true
		for len(errs) > 0 {
			e := <-errs
			if firstErr {
				firstErr = false
				TermPrepareFor(1)
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

func prepareInutsForEnc() (inputData []string, classes []int) {
	inputData = make([]string, numberMeasurements)
	classes = make([]int, numberMeasurements)

	// there we may want to seed it with the seed indicated in the config file
	// for now this is not the case to have better results
	rn := mrand.New(mrand.NewSource(time.Now().UnixNano()))
	data := randomHex(Config.MaxKeyLen + Config.MinMsgLen)
	// we change only the key between the two class:
	//data2 := strings.Repeat("0", Config.MaxKeyLen) + data[Config.MaxKeyLen:]
	// we use the same key and the same message each time
	for i := 0; i < numberMeasurements; i++ {
		classes[i] = rn.Intn(2)
		if classes[i] == 0 {
			inputData[i] = data
		} else {
			inputData[i] = randomHex(Config.MaxKeyLen + Config.MinMsgLen)
		}
	}
	return
}

func doOneComputationForEnc(prog string) func(data string) {
	return func(data string) {
		key := data[:Config.MaxKeyLen]
		msg := data[Config.MaxKeyLen:]
		_, err := runProg(prog, "dudectTest", []string{key, msg})
		if err != nil {
			log.Fatal(err)
		}
	}
}
