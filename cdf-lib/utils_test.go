package cdf

import (
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"os"
	"os/exec"
	"testing"
)

var execCounter int

func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") == "" {
		return
	}
	defer os.Exit(0)
	logFile, err := os.OpenFile("/tmp/test_logs.txt", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		t.Fatalf("Failed to open test_logs.txt file:", err)
	}
	defer logFile.Close()
	LogToFile = log.New(logFile, "", log.Ldate|log.Ltime|log.Lshortfile)
	args := os.Args
	for len(args) > 0 {
		if args[0] == "--" {
			args = args[1:]
			break
		}
		args = args[1:]
	}
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "No command\n")
		os.Exit(2)
	}

	switch os.Getenv("GO_WANT_HELPER_PROCESS") {
	case "ENC":
		testsForEnc(args)
	case "ECDSA":
		ExampleECDSA(args)
	case "DSA":
		ExampleDSA(args)
	default:
		return
	}
	LogToFile = log.New(ioutil.Discard, "", log.Ldate|log.Ltime|log.Lshortfile)
}

// fakeExecCommand is a trick from the test of the os/exec package to be able to test it.
func fakeExecCommand(currentTest string) func(command string, args ...string) *exec.Cmd {
	return func(command string, args ...string) *exec.Cmd {
		execCounter++
		cs := []string{"-test.run=TestHelperProcess", "--", command}
		cs = append(cs, args...)
		cmd := exec.Command(os.Args[0], cs...)
		// Let us tell the TestHelperProcess that we are running it from fakeExecCommand:
		cmd.Env = []string{fmt.Sprintf("GO_WANT_HELPER_PROCESS=%s", currentTest)}
		return cmd
	}
}

func initForTesting(currentTest string) {
	// disabling log:
	InitLog(nil)
	// disabling exec:
	execCommand = fakeExecCommand(currentTest)
	execCounter = 0
	// setting some default test parameters:
	Config.MinKeyLen = 1
	Config.MaxKeyLen = 2
	Config.MinMsgLen = 1
	Config.MaxMsgLen = 2
	Config.IncrementKey = 1
	Config.IncrementMsg = 1

	Config.Seed = 0
	// a random RSA key
	Config.RsaP = "D29BB20DAE71CA8EA2988DBC5629CA4C830A7F39D031DC45D064F6F8463ACA73E59F999FA1DC5F01199B2EB949EAA08D8277337027C77317B159B96975A86B57"
	Config.RsaQ = "D09CCF3050C82108220DA39DEBA7446758D0061CC046C52C52370A81C7358571E8F1494F49D82B7CB31293FE0E0F15B8200B1EADD1364A5CE60A97ABF3D41D33"
	Config.RsaN = "AB9F81FF42B280FE2F2F6A9D167C27247A450241D082B955F7F444789687B805D6F06811B6D09B9B661670F1E4B205753E9167A072F0B8442848F291E0D139D2403F2E1C6F23380C03058D99176CF8A6C7AAAAAF5822FA2B82E9A29888A39FDBA9B3B13DEB47DB15A3731F825454636729DCC6A655C4563C6F1B33CFFDC23D55"
	Config.RsaE = "10001"
	Config.RsaD = "60AD8C17754504F12B3774C165072F2D974B04887AA309306A6B499EFC7D1BA6FE7B92C457CD8FBAAC797BCA67DFF8BF212DDBC840B765B5CF53B88180B99BEDEE66F23EA3A03297E138EAC7E2A0DFDB1E07B4E21C27D3AF2996D16A5050897C9FA32DC0C6ABFFBC6919E8B9D80A6478FCBC71E4D70E70C632B82D64995DE309"

	// ECDSA key for P256
	Config.EcdsaX = "3bac7e95a003264cc075a2ba8d4e949862acd755d49094ad8d28bd0d56299dc6"
	Config.EcdsaY = "5c6a5b3810181d82f5eb1be32c9cd8d6c387fcb06fed530d749e3997eb22bd8c"
	Config.EcdsaD = "8964e19c5ae38669db3047f6b460863f5dc6c4510d3427e33545caf9527aafcf"

	// DSA key
	Config.DsaP = "A9B5B793FB4785793D246BAE77E8FF63CA52F442DA763C440259919FE1BC1D6065A9350637A04F75A2F039401D49F08E066C4D275A5A65DA5684BC563C14289D7AB8A67163BFBF79D85972619AD2CFF55AB0EE77A9002B0EF96293BDD0F42685EBB2C66C327079F6C98000FBCB79AACDE1BC6F9D5C7B1A97E3D9D54ED7951FEF"
	Config.DsaQ = "E1D3391245933D68A0714ED34BBCB7A1F422B9C1"
	Config.DsaG = "634364FC25248933D01D1993ECABD0657CC0CB2CEED7ED2E3E8AECDFCDC4A25C3B15E9E3B163ACA2984B5539181F3EFF1A5E8903D71D5B95DA4F27202B77D2C44B430BB53741A8D59A8F86887525C9F2A6A5980A195EAA7F2FF910064301DEF89D3AA213E1FAC7768D89365318E370AF54A112EFBA9246D9158386BA1B4EEFDA"
	Config.DsaY = "32969E5780CFE1C849A1C276D7AEB4F38A23B591739AA2FE197349AEEBD31366AEE5EB7E6C6DDB7C57D02432B30DB5AA66D9884299FAA72568944E4EEDC92EA3FBC6F39F53412FBCC563208F7C15B737AC8910DBC2D9C9B8C001E72FDC40EB694AB1F06A5A2DBD18D9E36C66F31F566742F11EC0A52E9F7B89355C02FB5D32D2"
	Config.DsaX = "5078D4D29795CBE76D3AACFE48C9AF0BCDBEE91A"

	// General settings
	Config.Timeout = 5
	Config.Concurrency = 3
	Config.VerboseLog = false

	// let us set the PRNG using the seed:
	Prng = rand.New(rand.NewSource(Config.Seed))

	// Finally we setup the flags:
	TestTimings = new(int)
	TestHashes = new(bool)
}
