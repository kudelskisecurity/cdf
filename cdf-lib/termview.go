package cdf

import (
	"log"
	"os"
	"strconv"
	"strings"
)

// Escape sequences for terminal rendering.
var (
	esc         = "\033["
	cl          = esc + "2K"
	clearScreen = esc + "2J"
	resetCursor = esc + "0;0H"
	clearLine   = esc + "1G" + cl
	TermView    = log.New(os.Stdout, "", 0)
)

// lineUp will return the escape sequence to move up by n lines in the terminal
//  and clear the line
func lineUp(n int) string {
	return esc + strconv.Itoa(n) + "F" + clearLine
}

// lineDown will return the escape sequence to move down by n lines in the
//  terminal and clear the line
func lineDown(n int) string {
	return esc + strconv.Itoa(n) + "E" + clearLine
}

// TermClear is a function which allow to clear the terminal to prepare
// displaying the data
func TermClear() {
	TermView.Print(clearScreen + resetCursor)
}

// TermPrepareFor is a function which allow to allocate the lines we will be
// using later. Its purpose is to make the terminal display we use compatible
// with the default logging functions.
func TermPrepareFor(size int) {
	TermView.Print(strings.Repeat("\n", size))
}

// TermDisplay moves the cursor up and then displays the specified content as
// well as writing to the log file if it is enabled
func TermDisplay(size int, format string, a ...interface{}) {
	TermView.Printf(lineUp(size)+format, a...)
	LogToFile.Printf(format, a...)
}

// TermPrintInline prints inline the provided string, with string formatting
func TermPrintInline(size int, format string, a ...interface{}) {
	TermView.Printf(lineUp(size)+clearLine+format, a...)
	LogToFile.Printf(format, a...)
}
