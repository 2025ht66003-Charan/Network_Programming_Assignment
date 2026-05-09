CC      = gcc
CFLAGS  = -Wall -Wextra -pedantic -std=c11 -O2
LDFLAGS = -lssl -lcrypto

TARGETS = server client tasks

.PHONY: all clean keys run-server run-client

all: $(TARGETS)

server: secure_server.c crypto_common.h
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

client: secure_client.c crypto_common.h
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

keys:
	@bash generate_keys.sh

tasks: crypto_tasks.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGETS) client_private.pem client_public.pem signing_key.pem verify_key.pem signature.bin

run-server: server
	./server

run-client: client
	./client
