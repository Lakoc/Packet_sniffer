SNIFFER = ipk-sniffer.cpp

CC=g++
CFLAGS=-std=c++11 -g -Werror -Wall -pedantic
LIBS= -lm -lpcap

all: sniffer

sniffer: ipk-sniffer.cpp
	$(CC) $(CFLAGS) $(SNIFFER) -o ipk-sniffer $(LIBS)
clean:
	rm ipk-sniffer
