# Makefile (Modified)

CC      := gcc
CFLAGS  := -std=c99 -O2 -Wall -Wextra
INCLUDE := -I.. -I../common

PQ_SRC := ../common/*.c ../crypto_kem/ml-kem-768/clean/*.c

.PHONY: all server mitm clean distclean

all: server mitm

server: server_auto.c
	$(CC) $(CFLAGS) -o vuln_server server_auto.c $(PQ_SRC) $(INCLUDE)

mitm: mitm_oracle.c
	$(CC) $(CFLAGS) -o mitm_oracle mitm_oracle.c

# Standard clean: Only removes executables.
# USE THIS during the demo when switching between Secure/Vulnerable modes.
# It preserves 'server_sk.bin' so the key remains constant.
clean:
	rm -f vuln_server mitm_oracle

# Deep clean: Removes executables AND the persistent key.
# Use this ONLY when you want to generate a completely new keypair 
# (e.g., before starting the entire presentation).
distclean: clean
	rm -f server_sk.bin
	rm -rf __pycache__