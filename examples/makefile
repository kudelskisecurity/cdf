CC=gcc
CXX=g++
GO=go

GOSRC=$(shell ls *.go)
GOBINS=$(foreach f, $(GOSRC), $(basename $(f)))

CRYPTOPPFSRC=$(wildcard *.cpp)
CRYPTOPPFBINS=$(foreach f, $(CRYPTOPPFSRC), $(basename $(f)))
CRYPTOPPFLAGS=-DNDEBUG -g2 -O2 -lcryptopp

JAVASRC=$(wildcard *.java)
JAVACLASS=$(JAVASRC:.java=.class)
JAVACLASSPATH=".:./libs/bcprov-jdk15on-156.jar"

OPENSSLSRC=$(wildcard *.c)
OPENSSLBINS=$(foreach f, $(OPENSSLSRC), $(basename $(f)))
OPENSSLFLAGS=-lcrypto

MDEBTLSSRC=$(wildcard *.c)
MBEDTLSBINS=$(foreach f, $(OPENSSLSRC), $(basename $(f)))
MBEDTLSFLAGS=-lmbedtls -lmbedcrypto

TRASH=__pycache__ *.dSYM

KERNEL_NAME := $(shell uname -s)
ifeq ($(KERNEL_NAME), Darwin)
	OPENSSLFLAGS += -L/usr/local/opt/openssl/lib -I/usr/local/opt/openssl/include 
endif

all:				cpp go openssl mbedtls java

openssl:					$(OPENSSLBINS)
%openssl:					%openssl.c
					$(CC) -o $@ $< $(OPENSSLFLAGS)

mbedtls:					$(MBEDTLSBINS)
%mbedtls:					%mbedtls.c
					$(CC) -o $@ $< $(MBEDTLSFLAGS)

cpp:						$(CRYPTOPPFBINS)
%cryptopp:					%cryptopp.cpp
					$(CXX) -o $@ $< $(CRYPTOPPFLAGS)

go:						$(GOBINS)
%:						%.go
					go build $<

java:						$(JAVACLASS)
%.class:					%.java
					javac -cp $(JAVACLASSPATH) $<

format:					$(GOSRC)
					$(foreach f, $(GSRC), gofmt -w $(f))

clean:
		rm -rf $(OPENSSLBINS) $(MBEDTLSBINS) $(GOBINS) $(CRYPTOPPFBINS) $(JAVACLASS) $(TRASH)
