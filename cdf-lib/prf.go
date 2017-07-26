package cdf

import (
	"errors"
	"fmt"
)

// TestPrf will test the provided prf function on multiple message length
// ranging from MinMsgLen to MaxMsgLen as set in the Config.json file
func TestPrf() error {
	LogInfo.Print("testing prf")

	failed := false

	// Let us fetch random keys and messages nibbles:
	msg := randomHex(Config.MaxMsgLen)
	key := randomHex(Config.MaxKeyLen)

	// list of tags
	tags := make(map[string]int)

	// key length to use in msg test
	keyAvgNibbles := 2 * ((Config.MaxKeyLen - Config.MinKeyLen) / 2)
	// msg length to use in key test
	msgAvgNibbles := 2 * ((Config.MaxMsgLen - Config.MinMsgLen) / 2)

	LogInfo.Println("testing message lengths")
	TermPrepareFor(1)

	currKey := key[:keyAvgNibbles]
	failedTmp := false
	// note that we ignore the incrementMsg parameter, since the *2 is hardcoded here.
	for i := Config.MinMsgLen; i <= Config.MaxMsgLen; i++ {
		currMsg := msg[:(i * 2)]
		TermPrintInline(1, "%d / %d", i, Config.MaxMsgLen)

		failedTmp = failedTmp || runPrf(currKey, currMsg, tags, i)
	}
	if !failedTmp {
		LogSuccess.Println("message length: okay")
	}
	fmt.Print("\n")
	LogInfo.Println("testing key lengths")
	TermPrepareFor(1)

	// reset tags list
	tags = make(map[string]int)

	currMsg := msg[:msgAvgNibbles]
	for i := Config.MinKeyLen; i <= Config.MaxKeyLen; i++ {
		TermPrintInline(1, "%d / %d", i, Config.MaxKeyLen)

		currKey := key[:(i * 2)]
		failed = failed || runPrf(currKey, currMsg, tags, i)
	}
	if !failedTmp {
		LogSuccess.Println("key length: okay")
	}
	TermPrepareFor(1)

	if nil != prfPaddingTests() {
		failed = true
	}

	if failed {
		fmt.Print("\n")
		return errors.New("one of more tests failed")
	}

	fmt.Print("\n")

	return nil
}

// runPrf is a helper method which perform the actual test of the two provided
// programs. If checks both programs' output for cohension and verify the generated
// tags for duplicates.
func runPrf(currKey, currMsg string, tags map[string]int, index int) bool {
	failed := false
	// get the first i bytes, ie first i*2 nibbles, since the interface is assuming
	// hexadecimal in/outputs
	id := fmt.Sprintf("prf#%d#%d", len(currKey), len(currMsg))
	outStr1 := runOrExitOnErr(Prog1, id, currKey, currMsg)
	outStr2 := runOrExitOnErr(Prog2, id, currKey, currMsg)

	if previous, ok := tags[outStr1]; ok {
		fmt.Print("\n")
		LogWarning.Printf("same tag for %d and %d\n", previous, index)
		failed = true
	} else {
		tags[outStr1] = index
	}

	if outStr1 != outStr2 {
		fmt.Print("\n")
		LogWarning.Printf("mismatch on length %d", index)
		failed = true
		// This is highly unlikely, yet let us cover this case
		if previous, ok := tags[outStr2]; ok {
			LogWarning.Printf("and same tag for %d and %d", previous, index)
			failed = true
		} else {
			tags[outStr2] = index
		}
	}
	return failed
}

func prfPaddingTests() error {
	LogInfo.Println("Testing right 00 padding")

	tags := make(map[string]int)

	currMsg := randomHex(Config.MinMsgLen)
	currKey := randomHex(Config.MinKeyLen)
	failed := runPrf(currKey, currMsg, tags, 0)
	if failed {
		LogError.Fatalln("Something went really wrong")
	}
	currKey = currKey + "00"
	failed = runPrf(currKey, currMsg, tags, 1)
	if failed {
		LogError.Println("Left padding with 00 of the key leads to the same output")
		return fmt.Errorf("left padding error")
	}

	/*
		// TODO: create an additionnal test to test the case with 00 at the end
		// of a previously used key
		if i == Config.MaxKeyLen {
		// this may be an option, but it would be best to refactor the whole
		//  process to have a function testConsistency() which will then
		//  process the different tests, keeping tracks of the previous tags,
		//  and so allowing to add one more easily...
					currKey = key[:(i-1)*2] + "00"
				}
	*/
	return nil
}
