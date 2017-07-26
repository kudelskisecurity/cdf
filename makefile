
BIN = cdf

SRC = main.go

.DEFAULT_GOAL = build

.PHONY: clean format examples

build:          $(SRC) 
	        	go build -o $(BIN) $^ 

run:            $(SRC) 
	        	go run $^ 

examples-go:    $(SRC) 
	        	cd examples/; make go

examples-all:   $(SRC)
	        	cd examples/; make

format:         $(SRC) 
	        	$(foreach f, $(SRC), gofmt -w $(f))

test:
				go test -v ./cdf-lib

clean:         
	        	rm -f $(BIN); cd examples/; make clean
