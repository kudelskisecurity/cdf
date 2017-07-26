// All credit goes to Oscar Reparaz, Josep Balasch and Ingrid Verbauwhede for dudect's ideas and design

package cdf

import (
	"fmt"
	"log"
	"math"
	"time"
)

type tCtx struct {
	mean [2]float64
	m2   [2]float64
	n    [2]float64
}

var (
	numberMeasurements = 3000
	enoughMeasurements = float64(3000) // may be handled by the Go benchmark package later
)

const tThresholdBananas = 500 // test failed, with overwhelming probability
const tThresholdModerate = 5  // here we could also take 4.5 e.g.

const numberPercentiles = 100
const numberTests = 1 + numberPercentiles + 1 // we perform 1

var dudectStop bool
var enough int
var percentiles [numberPercentiles]int64
var tests [numberTests]tCtx

// preparePercentiles computes the percentiles to use for the tests later
func preparePercentiles(ticks []int64) {
	for i := 0; i < numberPercentiles; i++ {
		percentiles[i] = percentile(
			ticks, 1-(math.Pow(0.5, float64(10*(i+1))/float64(numberPercentiles))))
	}
}

// measure times the execution of the provided doOneComputation on the
//  provided inputDatas
func measure(inputDatas []string, doOneComputation func(string)) (execTimes []int64) {
	ticks := make([]int64, numberMeasurements+1)
	for i := 0; i < numberMeasurements; i++ {
		ticks[i] = time.Now().UnixNano()
		doOneComputation(inputDatas[i])
	}

	ticks[numberMeasurements] = time.Now().UnixNano()
	execTimes = make([]int64, numberMeasurements)
	for i := 0; i < numberMeasurements; i++ {
		execTimes[i] = ticks[i+1] - ticks[i]
	}
	return
}

// updateStatistics will udpate each t-test we are storing, ie. the test on
//  all data, the tests on each percentiles, and the second order test.
func updateStatistics(execTimes []int64, classes []int) {

	for i := 0; i < numberMeasurements; i++ {
		difference := execTimes[i]
		if difference < 0 {
			continue // the cpu cycle counter overflowed
		}

		// do a t-test on the execution time
		tPush(&tests[0], float64(difference), classes[i])

		// do a t-test on cropped execution times, for several cropping thresholds.
		for cropIndex := 0; cropIndex < numberPercentiles; cropIndex++ {
			if difference < percentiles[cropIndex] {
				tPush(&tests[cropIndex+1], float64(difference), classes[i])
			}
		}

		// do a second-order test (only if we have more than 10000 measurements).
		// Centered product pre-processing.
		if tests[0].n[0] > 10000 {
			centered := float64(difference) - tests[0].mean[classes[i]]
			tPush(&tests[1+numberPercentiles], centered*centered, classes[i])
		}
	}
}

// tPush will add the value x to the t context in the provided class and update
//  its context values
func tPush(ctx *tCtx, x float64, class int) {
	if !(class == 0 || class == 1) {
		log.Fatalln("Error, wrong class in tPush")
	}
	ctx.n[class]++
	// Welford method for computing online variance
	// in a numerically stable way.
	// see Knuth Vol 2
	var delta float64
	delta = x - ctx.mean[class]
	// so we have a/n +(x-a/n)/(n+1) = ((n+1)a + nx-a)/(n(n+1)) = (a+x)/(n+1)
	ctx.mean[class] += delta / ctx.n[class]
	ctx.m2[class] += delta * (x - ctx.mean[class])
	// the algorithm is finalized in tCompute
}

// tCompute performs the computation to give the t-value used by our t-test
func tCompute(ctx *tCtx) float64 {
	vars := [2]float64{0.0, 0.0}
	var den, tValue, num float64

	// we divide by n-1 since to finalize the variance computation.
	vars[0] = ctx.m2[0] / (ctx.n[0] - 1)
	vars[1] = ctx.m2[1] / (ctx.n[1] - 1)
	num = (ctx.mean[0] - ctx.mean[1])
	den = math.Sqrt(vars[0]/ctx.n[0] + vars[1]/ctx.n[1])
	tValue = num / den

	return tValue
}

// maxTest returns the index of the test with the greateast t-value
func maxTest() int {
	ret := 0
	var max float64
	max = 0.0
	for i := 0; i < numberTests; i++ {
		if tests[i].n[0] > enoughMeasurements {
			var x float64
			x = math.Abs(tCompute(&tests[i]))
			if max < x {
				max = x
				ret = i
			}
		}
	}
	return ret
}

// report is in charge of printing the data related to the dudect test.
func report() string {

	var res string

	mt := maxTest()
	maxT := math.Abs(tCompute(&tests[mt]))
	numberTracesMaxT := tests[mt].n[0] + tests[mt].n[1]
	maxTau := maxT / math.Sqrt(numberTracesMaxT)

	if numberTracesMaxT < enoughMeasurements {
		return fmt.Sprintf("not enough measurements (%.0f still to go).\n",
			enoughMeasurements-numberTracesMaxT)
	}

	/*
	* maxT: the t statistic value
	* maxTau: a t value normalized by sqrt(number of measurements).
	*          this way we can compare maxTau taken with different
	*          number of measurements. This is sort of "distance
	*          between distributions", independent of number of
	*          measurements.
	* (5/tau)^2: how many measurements we would need to barely
	*            detect the leak, if present. "barely detect the
	*            leak" = have a t value greater than 5.
	 */
	res = fmt.Sprintf("meas: %7.2f M, max t(%d): %+7.2f, max tau: %.2e, (5/tau)^2: %.2e. m.time (ms):%7.2f",
		(numberTracesMaxT / 1e6),
		mt, maxT,
		maxTau,
		float64(5*5)/(maxTau*maxTau),
		tests[0].mean[0]/float64(1e6))

	if maxT > tThresholdBananas {
		LogWarning.Printf(" Definitely not constant time.\n")
		dudectStop = true
		return res
	}
	if maxT > tThresholdModerate {
		LogWarning.Printf(" Probably not constant time.\n")
		enough++
		if enough > 5 {
			// let us stop before reaching the limit if we have 5 consecutive hints
			LogWarning.Printf(" Stopping for now. You may want to investigate this further.\n")
			dudectStop = true
		}
		return res
	} else {
		LogInfo.Printf(" For the moment, maybe constant time.\n")
		enough = 0
		return res
	}
}

// dudectTest is a function which will allow one to perform a constant time
//  test on the provided doOneComputation function using the data provided
//  by prepare_input and which will tell, using a t-test whether it seems to
//  be timing discrepancies between the two class of inputs or not.
func dudectTest(limit int, progName string, doOneComputation func(string) func(string), prepareInputs func() (inputData []string, classes []int)) {
	LogInfo.Println("dudect constant time test starting for", progName)
	TermView.Println("Preparing input...")
	TermPrepareFor(1)
	var countD int

	// we need to reset our global variables:
	dudectStop = false
	percentiles = [numberPercentiles]int64{}
	tests = [numberTests]tCtx{}
	for !dudectStop {
		countD++
		inputData, classes := prepareInputs()
		execTimes := measure(inputData, doOneComputation(progName))

		// on the very first run, let's compute the rough esitmate of the percentiles:
		if percentiles[numberPercentiles-1] == 0 {
			preparePercentiles(execTimes)
		}
		updateStatistics(execTimes, classes)
		TermPrintInline(2, "%d / %d : %s", countD, limit,
			report())

		if countD >= limit {
			dudectStop = true
		}
	}
	TermPrepareFor(2)

}
