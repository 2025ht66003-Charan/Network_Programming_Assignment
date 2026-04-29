CC      = gcc
CFLAGS  = -Wall -Wextra -pedantic -std=c11 -O2
LDFLAGS = -lssl -lcrypto

TARGETS = server client

.PHONY: all clean keys run-server run-client

all: $(TARGETS)

server: secure_server.c crypto_common.h
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

client: secure_client.c crypto_common.h
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

keys:
	@bash generate_keys.sh

clean:
	rm -f $(TARGETS) client_private.pem client_public.pem

run-server: server
	./server

run-client: client
	./client
