package cdf

import (
	"errors"
	"fmt"
)

// TestXof will generate a random message and test the range from MinMsgLen to
// MaxMsgLen with IncrementMsg bytes increment. It checks for duplicate results
// and compare both implementation against each other. Its return value is
// an error or nil on success.
func TestXof() error {
	LogInfo.Print("testing xof")

	failed := false

	msg := randomHex(Config.MaxMsgLen)

	// list of hashes
	hashes := make(map[string]int)

	LogInfo.Println("testing message lengths")

	for i := Config.MinMsgLen; i <= Config.MaxMsgLen; i += Config.IncrementMsg {

		TermPrintInline(1, "%d / %d", i, Config.MaxMsgLen)
		id := fmt.Sprintf("xof#msglen#%d", i)
		// get the first i bytes, ie first i*2 nibbles
		outStr1 := runOrExitOnErr(Prog1, id, msg[:(i*2)])
		outStr2 := runOrExitOnErr(Prog2, id, msg[:(i*2)])

		if length, ok := hashes[outStr1]; ok {
			fmt.Print("\n")
			LogWarning.Printf("same hash for %d and %d", length, i)
			failed = true
		} else {
			hashes[outStr1] = i
		}

		if outStr1 != outStr2 {
			fmt.Print("\n")
			LogWarning.Printf("mismatch on length %d\nGot:\n\t%s\n\t%s", i, outStr1, outStr2)
			failed = true
			if length, ok := hashes[outStr2]; ok {
				LogWarning.Printf("same hash for %d and %d", length, i)
				failed = true
			} else {
				hashes[outStr2] = i
			}
		}
	}

	if failed {
		fmt.Print("\n")
		return errors.New("one of more tests failed")
	}

	fmt.Print("\n")
	return nil
}
