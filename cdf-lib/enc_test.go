package cdf

import (
	"fmt"
	"os"
	"testing"
)

func TestTestEnc(t *testing.T) {
	initForTesting("ENC")
	err := TestEnc()
	if err != nil {
		t.Error("Expected nil, got ", err)
	}
	if execCounter != 8 {
		t.Error("Expected 8 executions, got ", execCounter)
	}
}

func TestTestEncWithTimings(t *testing.T) {
	initForTesting("ENC")
	*TestTimings = 1 // it will run 1 dudect pass
	enoughMeasurements = float64(200)
	numberMeasurements = 200
	err := TestEnc()
	if err != nil {
		t.Error("Expected nil, got ", err)
	}
	if execCounter != 408 {
		t.Error("Expected 408 executions, got ", execCounter)
	}
}

func testsForEnc(args []string) {
	key := args[1]
	msg := args[2]

	if len(key)%2 != 0 || len(msg)%2 != 0 {
		fmt.Fprintln(os.Stderr, "Not a string of even length!")
		//		os.Exit(2)
	}
	// output for testing:
	fmt.Println(msg)
}
