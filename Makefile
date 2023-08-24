# Makefile for nfqnl_test

# Compiler and compiler flags
CC = gcc
CFLAGS = -Wall -Wextra

# Source file and executable name
SRC = nfqnl_test.c
EXEC = nfqnl_test

all: $(EXEC)

$(EXEC): $(SRC)
	$(CC) $(CFLAGS) -o $@ $^ -lnetfilter_queue

clean:
	rm -f $(EXEC)
