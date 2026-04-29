#!/usr/bin/env bash
# generate_keys.sh
# Generates an RSA-2048 key pair for the client.
# client_private.pem – kept by the client (never shared)
# client_public.pem  – distributed to the server for signature verification

set -euo pipefail

echo "[keygen] Generating RSA-2048 private key..."
openssl genpkey -algorithm RSA \
    -pkeyopt rsa_keygen_bits:2048 \
    -out client_private.pem

echo "[keygen] Extracting public key..."
openssl pkey -in client_private.pem -pubout -out client_public.pem

echo "[keygen] Done."
echo "  client_private.pem  (keep secret – client only)"
echo "  client_public.pem   (share with server)"
