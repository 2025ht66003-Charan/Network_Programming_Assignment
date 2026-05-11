# REPORT
## Secure TCP Streaming with Encryption and Digital Signature in C

---

## TITLE PAGE

**Title:** Building Secure and Open TCP Connection for Streaming Real-Time Data

**Subject:** Network Programming

**Language Used:** C (C11 Standard)

**Libraries Used:** POSIX Sockets, OpenSSL (libssl, libcrypto)

**Branch:** claude/secure-tcp-streaming-U3Hnd

**Repository:** 2025ht66003-Charan/Network_Programming_Assignment

---

## ACKNOWLEDGEMENT

I express my sincere gratitude to my faculty and institution for providing the opportunity to work on this network programming assignment. This project has helped deepen my understanding of socket programming, symmetric encryption, and public-key cryptography using the C programming language and the OpenSSL library. I also acknowledge the OpenSSL project and NIST for their publicly available standards and documentation that served as reference material throughout this work.

---

## LIST OF SYMBOLS AND ABBREVIATIONS

| Symbol / Abbreviation | Full Form |
|---|---|
| TCP | Transmission Control Protocol |
| IP | Internet Protocol |
| AES | Advanced Encryption Standard |
| CBC | Cipher Block Chaining |
| RSA | Rivest–Shamir–Adleman |
| SHA | Secure Hash Algorithm |
| IV | Initialization Vector |
| PEM | Privacy Enhanced Mail (key file format) |
| EVP | Envelope (OpenSSL high-level API) |
| API | Application Programming Interface |
| DS | Digital Signature |
| PKCS | Public Key Cryptography Standards |
| NIST | National Institute of Standards and Technology |
| XOR | Exclusive OR |
| B | Bytes |
| KB | Kilobytes |
| fd | File Descriptor |
| MSB | Most Significant Byte |
| LSB | Least Significant Byte |
| POSIX | Portable Operating System Interface |
| BSD | Berkeley Software Distribution |

---

## ABSTRACT

This report presents the design and implementation of a secure, persistent TCP client-server communication system written in the C programming language. The system addresses two fundamental security requirements in network communication: **confidentiality** (preventing eavesdropping) and **authenticity** (verifying the sender and detecting message tampering).

Confidentiality is achieved using **AES-128-CBC** (Advanced Encryption Standard in Cipher Block Chaining mode), a symmetric encryption algorithm. Each plaintext message is encrypted using a pre-shared 128-bit key and a 16-byte Initialization Vector before transmission.

Authenticity is achieved using **RSA-2048 digital signatures** combined with a **SHA-256** hash function. The sender signs each message using its RSA private key; the receiver verifies the signature using the corresponding public key. Any tampering with the message or signature causes verification to fail.

The system is implemented across three primary source files: `secure_server.c`, `secure_client.c`, and `crypto_tasks.c`, supported by a shared header `crypto_common.h`. Testing confirms that encrypted messages are correctly decrypted, valid signatures return `VALID`, and corrupted signatures return `NOTVALID`.

---

## TABLE OF CONTENTS

1. Introduction
2. Requirement Specification
3. Design Methodology
4. Implementation Details / Source Code
5. Testing
6. Conclusion
7. Appendices
8. Bibliography / References

---

## CHAPTER 1: INTRODUCTION

### 1.1 Background

Network communication is the backbone of modern computing. As systems exchange data over shared and potentially untrusted networks, two critical security properties must be ensured:

- **Confidentiality** — data must not be readable by unauthorized parties
- **Integrity and Authenticity** — data must not be altered in transit, and the identity of the sender must be verifiable

Traditional socket programming in C provides only raw, unencrypted TCP streams. This assignment extends basic TCP communication with cryptographic mechanisms to address these security concerns.

### 1.2 Problem Statement

The objective is to build a system where:
- A **client** sends text messages over a persistent TCP connection
- A **server** receives them instantly in real time
- All messages are **encrypted** so that intercepted traffic is unreadable
- All messages carry a **digital signature** so the server can verify they have not been tampered with

### 1.3 Objectives

1. Implement a persistent TCP client-server connection using POSIX sockets in C
2. Implement `encrypt()` and `decrypt()` functions using AES-128-CBC
3. Implement `create_ds()` to generate an RSA-2048 key pair and sign a message
4. Implement `check_signature()` to verify the signature and return `VALID` or `NOTVALID`
5. Demonstrate that corrupting the signature causes the check to return `NOTVALID`

### 1.4 Scope

The system operates over IPv4 TCP on localhost (127.0.0.1) port 8443. It is designed as an educational demonstration of applied cryptography in network programming. The implementation uses OpenSSL 3.x EVP API throughout, avoiding deprecated low-level RSA and AES function calls.

---

## CHAPTER 2: REQUIREMENT SPECIFICATION

### 2.1 Functional Requirements

| ID | Requirement |
|---|---|
| FR-1 | The client shall establish a persistent TCP connection to the server |
| FR-2 | The client shall encrypt every message before transmission |
| FR-3 | The client shall digitally sign every message before transmission |
| FR-4 | The server shall verify the digital signature of every received message |
| FR-5 | The server shall decrypt each verified message and display the plaintext |
| FR-6 | The server shall reject and log any message whose signature is invalid |
| FR-7 | `encrypt(plain_text)` shall return a hex-encoded ciphertext string |
| FR-8 | `decrypt(cipher_text)` shall return the original plaintext string |
| FR-9 | `create_ds(message)` shall generate an RSA-2048 key pair and store `signing_key.pem`, `verify_key.pem`, and `signature.bin` |
| FR-10 | `check_signature(message)` shall return `"VALID"` or `"NOTVALID"` |

### 2.2 Non-Functional Requirements

| ID | Requirement |
|---|---|
| NFR-1 | The system shall use AES-128-CBC for symmetric encryption |
| NFR-2 | The system shall use RSA-2048 with SHA-256 for digital signatures |
| NFR-3 | The system shall handle TCP stream fragmentation using reliable send/receive loops |
| NFR-4 | All OpenSSL resources (contexts, keys) shall be freed after use |
| NFR-5 | The system shall compile with no warnings under `-Wall -Wextra -pedantic -std=c11` |
| NFR-6 | Private key files shall never be committed to version control |

### 2.3 Hardware and Software Requirements

| Component | Specification |
|---|---|
| Operating System | Linux (Ubuntu 22.04 or later) |
| Compiler | GCC with C11 support |
| Cryptography Library | OpenSSL 3.0 (`libssl-dev`, `libcrypto`) |
| Network | IPv4 loopback (127.0.0.1) |
| Port | 8443 |
| Build Tool | GNU Make |

---

## CHAPTER 3: DESIGN METHODOLOGY

### 3.1 System Architecture

The system consists of two subsystems:

**Subsystem 1 — Secure TCP Streaming (Task: Client-Server)**
```
[ Client ]                              [ Server ]
   |                                        |
   |-- TCP connect() ---------------------->|
   |                                        |
   | For each message:                      |
   |  1. AES-128-CBC encrypt               |
   |  2. RSA-2048/SHA-256 sign             |
   |  3. Send: [Header][Signature][Cipher] |
   |---------------------------------------->|
   |                                        | 1. Verify RSA signature
   |                                        | 2. AES decrypt
   |                                        | 3. Display plaintext
```

**Subsystem 2 — Standalone Crypto Tasks**
```
encrypt(plain_text)
  └─ AES-128-CBC → ciphertext bytes → hex string

decrypt(cipher_text)
  └─ hex string → bytes → AES-128-CBC → plain_text

create_ds(message)
  └─ RSA keygen → sign with SHA-256 → save files

check_signature(message)
  └─ load key + signature → verify → "VALID" / "NOTVALID"
```

### 3.2 Wire Packet Format

Each message sent over TCP uses the following packet layout:

```
 0        4        8       24
 +--------+--------+--------+----...----+----...----+
 |sig_len |cip_len |   IV   | Signature | Ciphertext|
 | 4 bytes| 4 bytes|16 bytes| sig_len B | cip_len B |
 +--------+--------+--------+----...----+----...----+
```

- `sig_len` and `cip_len` are sent in **network byte order** (big-endian) using `htonl`/`ntohl`
- `IV` is a fresh 16-byte random value generated per message using `RAND_bytes()`
- Signature covers the **ciphertext** bytes (not plaintext) — server verifies before decrypting

### 3.3 Encryption Design (AES-128-CBC)

AES (Advanced Encryption Standard) is a symmetric block cipher operating on 128-bit (16-byte) blocks.

**CBC Mode Operation:**
```
Plaintext[i] XOR Ciphertext[i-1] → AES_Encrypt(key) → Ciphertext[i]
```

- Block 0 uses the IV as the "previous ciphertext"
- **PKCS#7 padding** fills the final block if plaintext length is not a multiple of 16
- The same key and IV must be used for both encryption and decryption

**Key and IV:**
- Key: 16 bytes (128 bits), pre-shared between client and server
- IV: 16 bytes, randomly generated per message using `RAND_bytes()`

### 3.4 Digital Signature Design (RSA-2048 / SHA-256)

Digital signatures use **asymmetric cryptography** — what the private key locks, only the public key can unlock.

**Signing (create_ds):**
```
message → SHA-256 hash → 32-byte digest
32-byte digest → RSA encrypt with private key → 256-byte signature
```

**Verification (check_signature):**
```
received message → SHA-256 hash → digest A
signature → RSA decrypt with public key → digest B
if (digest A == digest B) → VALID
else → NOTVALID
```

### 3.5 File Structure

```
Network_Programming_Assignment/
├── crypto_common.h       Shared constants and PktHeader struct
├── secure_server.c       TCP server with signature verify + AES decrypt
├── secure_client.c       TCP client with AES encrypt + RSA sign
├── crypto_tasks.c        Standalone encrypt/decrypt/create_ds/check_signature
├── test_corrupt.c        Corruption test demonstrating NOTVALID detection
├── generate_keys.sh      RSA-2048 key pair generation script
└── Makefile              Build targets
```

### 3.6 Function Design Summary

| Function | File | Input | Output |
|---|---|---|---|
| `encrypt()` | crypto_tasks.c | plaintext string | hex ciphertext string |
| `decrypt()` | crypto_tasks.c | hex ciphertext string | plaintext string |
| `create_ds()` | crypto_tasks.c | message string | files: signing_key.pem, verify_key.pem, signature.bin |
| `check_signature()` | crypto_tasks.c | message string | "VALID" or "NOTVALID" |
| `aes_encrypt()` | secure_client.c | plaintext, key, IV | ciphertext bytes |
| `aes_decrypt()` | secure_server.c | ciphertext, key, IV | plaintext bytes |
| `rsa_sign()` | secure_client.c | data, private key | signature bytes |
| `verify_signature()` | secure_server.c | data, signature, public key | 1 (valid) / 0 (invalid) |
| `send_exact()` | secure_client.c | socket, buffer, n | sends exactly n bytes |
| `recv_exact()` | secure_server.c | socket, buffer, n | receives exactly n bytes |

---

## CHAPTER 4: IMPLEMENTATION DETAILS / SOURCE CODE

### 4.1 crypto_common.h — Shared Header

Defines shared constants, the pre-shared AES key, and the `PktHeader` struct used by both client and server.

```c
#ifndef CRYPTO_COMMON_H
#define CRYPTO_COMMON_H

#include <stdint.h>

#define SERVER_PORT   8443
#define SERVER_IP     "127.0.0.1"
#define MAX_MSG_LEN   4096
#define AES_KEY_LEN   32
#define AES_IV_LEN    16
#define MAX_SIG_LEN   512
#define MAX_CIPHER_LEN (MAX_MSG_LEN + AES_IV_LEN)

static const unsigned char SHARED_AES_KEY[AES_KEY_LEN] = {
    0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
    0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
    0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
};

typedef struct {
    uint32_t sig_len;
    uint32_t cipher_len;
    unsigned char iv[AES_IV_LEN];
} __attribute__((packed)) PktHeader;

#endif
```

**Key design points:**
- `PktHeader` is `__attribute__((packed))` — no padding bytes, maps directly onto the wire
- `uint32_t` for lengths ensures consistent 4-byte integers on all platforms
- AES key is `static const` — private to each translation unit

---

### 4.2 crypto_tasks.c — Task 1 and Task 2

#### Task 1 — encrypt() function

Encrypts a plaintext string using AES-128-CBC. Returns a hex-encoded string.

```c
char *encrypt(const char *plain_text)
{
    int plain_len  = (int)strlen(plain_text);
    int buf_size   = plain_len + 16 + 1;
    unsigned char *cipher_bytes = malloc(buf_size);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len = 0, total = 0;

    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, AES_KEY, AES_IV);
    EVP_EncryptUpdate(ctx, cipher_bytes, &len,
                      (const unsigned char *)plain_text, plain_len);
    total = len;
    EVP_EncryptFinal_ex(ctx, cipher_bytes + len, &len);
    total += len;
    EVP_CIPHER_CTX_free(ctx);

    char *hex = bytes_to_hex(cipher_bytes, (size_t)total);
    free(cipher_bytes);
    return hex;
}
```

#### Task 1 — decrypt() function

Reverses `encrypt()`. Takes a hex string and returns the original plaintext.

```c
char *decrypt(const char *cipher_text)
{
    size_t cipher_len;
    unsigned char *cipher_bytes = hex_to_bytes(cipher_text, &cipher_len);

    unsigned char *plain_bytes = malloc(cipher_len + 1);
    int len = 0, total = 0;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, AES_KEY, AES_IV);
    EVP_DecryptUpdate(ctx, plain_bytes, &len, cipher_bytes, (int)cipher_len);
    total = len;
    EVP_DecryptFinal_ex(ctx, plain_bytes + len, &len);
    total += len;
    EVP_CIPHER_CTX_free(ctx);
    free(cipher_bytes);

    plain_bytes[total] = '\0';
    return (char *)plain_bytes;
}
```

#### Task 2.1 — create_ds() function

Generates RSA-2048 key pair, signs the message, saves key files and signature.

```c
void create_ds(const char *message)
{
    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY_keygen_init(kctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, 2048);
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_keygen(kctx, &pkey);
    EVP_PKEY_CTX_free(kctx);

    FILE *fp = fopen("signing_key.pem", "w");
    PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, NULL, NULL);
    fclose(fp);

    fp = fopen("verify_key.pem", "w");
    PEM_write_PUBKEY(fp, pkey);
    fclose(fp);

    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    EVP_DigestSignInit(mctx, NULL, EVP_sha256(), NULL, pkey);
    EVP_DigestSignUpdate(mctx, message, strlen(message));
    size_t sig_len = 0;
    EVP_DigestSignFinal(mctx, NULL, &sig_len);
    unsigned char *sig = malloc(sig_len);
    EVP_DigestSignFinal(mctx, sig, &sig_len);
    EVP_MD_CTX_free(mctx);
    EVP_PKEY_free(pkey);

    fp = fopen("signature.bin", "wb");
    fwrite(sig, 1, sig_len, fp);
    fclose(fp);
    free(sig);
}
```

#### Task 2.2 — check_signature() function

Loads the public key and signature, verifies, and returns `"VALID"` or `"NOTVALID"` using an `if` condition.

```c
const char *check_signature(const char *message)
{
    FILE *fp = fopen("verify_key.pem", "r");
    if (!fp) return "NOTVALID";
    EVP_PKEY *pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!pkey) return "NOTVALID";

    fp = fopen("signature.bin", "rb");
    if (!fp) { EVP_PKEY_free(pkey); return "NOTVALID"; }
    fseek(fp, 0, SEEK_END);
    long sig_len = ftell(fp);
    rewind(fp);
    unsigned char *sig = malloc((size_t)sig_len);
    if (fread(sig, 1, (size_t)sig_len, fp) != (size_t)sig_len) {
        fclose(fp); free(sig); EVP_PKEY_free(pkey); return "NOTVALID";
    }
    fclose(fp);

    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    EVP_DigestVerifyInit(mctx, NULL, EVP_sha256(), NULL, pkey);
    EVP_DigestVerifyUpdate(mctx, message, strlen(message));
    int result = EVP_DigestVerifyFinal(mctx, sig, (size_t)sig_len);
    EVP_MD_CTX_free(mctx);
    EVP_PKEY_free(pkey);
    free(sig);

    if (result == 1) {
        printf("Signature check : VALID\n");
        return "VALID";
    } else {
        printf("Signature check : NOTVALID - message is corrupt or tampered!\n");
        return "NOTVALID";
    }
}
```

---

### 4.3 secure_server.c — TCP Server

The server performs the following on startup:
1. Loads `client_public.pem`
2. Creates a TCP socket, binds to port 8443, and calls `listen()`
3. Calls `accept()` and enters a message receive loop

For each message received:
1. Reads the 24-byte `PktHeader` (sig_len, cipher_len, IV)
2. Reads `sig_len` bytes of RSA signature
3. Reads `cipher_len` bytes of ciphertext
4. Calls `verify_signature()` — rejects if invalid
5. Calls `aes_decrypt()` — displays the plaintext

**recv_exact() — reliable receive:**
```c
static int recv_exact(int fd, void *buf, size_t n)
{
    size_t done = 0;
    while (done < n) {
        ssize_t r = recv(fd, (char *)buf + done, n - done, 0);
        if (r <= 0) return -1;
        done += (size_t)r;
    }
    return 0;
}
```

---

### 4.4 secure_client.c — TCP Client

For each message typed by the user:
1. Generates a random 16-byte IV using `RAND_bytes()`
2. Encrypts using `aes_encrypt()` → ciphertext
3. Signs ciphertext using `rsa_sign()` → signature
4. Sends `PktHeader` + signature + ciphertext using `send_exact()`

**send_exact() — reliable send:**
```c
static int send_exact(int fd, const void *buf, size_t n)
{
    size_t done = 0;
    while (done < n) {
        ssize_t s = send(fd, (const char *)buf + done, n - done, 0);
        if (s <= 0) return -1;
        done += (size_t)s;
    }
    return 0;
}
```

---

### 4.5 test_corrupt.c — Corruption Test

Demonstrates the full signature lifecycle:
1. Generates a valid signature
2. Verifies it → `VALID`
3. Overwrites `signature.bin` with garbage bytes
4. Verifies again → `NOTVALID`

```c
printf("=== STEP 3: Corrupt signature.bin ===\n");
FILE *fp = fopen("signature.bin", "wb");
fprintf(fp, "CORRUPTED_DATA_12345");
fclose(fp);
```

---

### 4.6 Makefile

```makefile
CC      = gcc
CFLAGS  = -Wall -Wextra -pedantic -std=c11 -O2
LDFLAGS = -lssl -lcrypto

all: server client tasks

server: secure_server.c crypto_common.h
    $(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

client: secure_client.c crypto_common.h
    $(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

tasks: crypto_tasks.c
    $(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

keys:
    @bash generate_keys.sh

clean:
    rm -f server client tasks signing_key.pem verify_key.pem signature.bin
```

---

## CHAPTER 5: TESTING

### 5.1 Test 1 — Encryption and Decryption

**Objective:** Verify that `encrypt()` produces ciphertext and `decrypt()` recovers the original plaintext.

**Procedure:**
```bash
make tasks
./tasks
```

**Result:**
```
plain_text  : abcde
cipher_text : 46dad22c2eb638e219fb7106a07ef0be
decrypted   : abcde
```

**Conclusion:** PASS — ciphertext is unreadable hex; decryption restores original text exactly.

---

### 5.2 Test 2 — Valid Digital Signature

**Objective:** Verify that `check_signature()` returns `VALID` when the correct message and signature are used.

**Procedure:**
```bash
./tasks
```

**Result:**
```
[create_ds] Private key saved  : signing_key.pem
[create_ds] Public key saved   : verify_key.pem
[create_ds] Signature saved    : signature.bin (256 bytes)
Signature check : VALID
[main] "This message is signed." => Signature VALID. Message is authentic.
```

**Conclusion:** PASS — RSA signature verification succeeds for the original message.

---

### 5.3 Test 3 — Tampered Message Detection

**Objective:** Verify that `check_signature()` returns `NOTVALID` when a different message is checked against the original signature.

**Procedure:**
```bash
./tasks
```
(The `main()` internally calls `check_signature("tampered message")` after signing a different message.)

**Result:**
```
Signature check : NOTVALID - message is corrupt or tampered!
[main] "tampered message" => NOTVALID. Message is corrupt!
```

**Conclusion:** PASS — signature mismatch is correctly detected.

---

### 5.4 Test 4 — Corrupted Signature File

**Objective:** Verify that overwriting `signature.bin` with garbage data causes `check_signature()` to return `NOTVALID`.

**Procedure:**
```bash
make tasks
gcc -Wall -O2 -o test_corrupt test_corrupt.c -lssl -lcrypto
./test_corrupt
```

**Result:**
```
=== STEP 1: Create valid signature ===
[create_ds] Keys + signature generated.

=== STEP 2: Check BEFORE corruption ===
Signature check : VALID
[test] Result : VALID

=== STEP 3: Corrupt signature.bin ===
[test] signature.bin overwritten with garbage.

=== STEP 4: Check AFTER corruption ===
Signature check : NOTVALID - message is corrupt or tampered!
[test] Result : NOTVALID
```

**Conclusion:** PASS — file corruption is detected immediately.

---

### 5.5 Test 5 — Secure TCP Streaming (Client-Server)

**Objective:** Verify end-to-end encrypted and signed message transmission over TCP.

**Procedure:**
```bash
make keys        # generate RSA key pair
./server &       # start server in background
./client         # start client, type messages
```

**Result:**
```
[Server] Loaded client public key (RSA-2048, SHA-256 signing).
[Server] Listening on port 8443 ...
[Server] Client connected from 127.0.0.1:xxxxx
[Client] Sent (AES-32B cipher, RSA-256B sig): "Hello, secure world!"
[Server] OK (verified)   32         "Hello, secure world!"
```

**Conclusion:** PASS — message encrypted on client, signature verified on server, plaintext displayed correctly.

---

### 5.6 Test Summary

| Test | Description | Expected | Result |
|---|---|---|---|
| T1 | encrypt("abcde") and decrypt back | Ciphertext ≠ plaintext; decrypt = "abcde" | PASS |
| T2 | check_signature with correct message | VALID | PASS |
| T3 | check_signature with different message | NOTVALID | PASS |
| T4 | check_signature after corrupting signature.bin | NOTVALID | PASS |
| T5 | End-to-end secure TCP streaming | Server displays plaintext | PASS |

---

## CONCLUSION

This assignment successfully demonstrates the implementation of a secure TCP streaming system in C with the following outcomes:

1. **Symmetric Encryption (Task 1):** The `encrypt()` and `decrypt()` functions using AES-128-CBC correctly transform plaintext to ciphertext and back. The hex-encoded ciphertext (`46dad22c2eb638e219fb7106a07ef0be`) is completely unreadable, confirming confidentiality.

2. **Digital Signature (Task 2):** The `create_ds()` function generates a fresh RSA-2048 key pair, signs the message using SHA-256, and persists the keys and signature to disk. The `check_signature()` function correctly returns `VALID` for authentic messages and `NOTVALID` for any tampered or corrupted data.

3. **Secure TCP Streaming:** The full client-server system combines both mechanisms — each message is AES-encrypted with a random IV and RSA-signed before sending. The server verifies the signature before decrypting, ensuring no wasted computation on forged packets.

4. **Network Programming Concepts Applied:** POSIX TCP sockets (`socket`, `bind`, `listen`, `accept`, `connect`), reliable framing with `send_exact`/`recv_exact`, and network byte order conversion with `htonl`/`ntohl` were all applied correctly.

The project reinforces the principle that **encryption provides confidentiality** while **digital signatures provide authenticity and integrity** — and that both are required together for truly secure communication.

---

## APPENDICES

### Appendix A — Build and Run Instructions

```bash
# Step 1: Install dependencies
sudo apt install gcc libssl-dev make

# Step 2: Generate RSA key pair
make keys

# Step 3: Build all binaries
make

# Step 4: Run Task 1 + Task 2 demo
./tasks

# Step 5: Run corruption test
gcc -Wall -O2 -o test_corrupt test_corrupt.c -lssl -lcrypto
./test_corrupt

# Step 6: Run TCP server + client (two terminals)
./server          # Terminal 1
./client          # Terminal 2 — type messages
```

### Appendix B — File Descriptions

| File | Description |
|---|---|
| `crypto_common.h` | Shared constants, AES key, PktHeader struct |
| `secure_server.c` | TCP server: signature verification + AES decryption |
| `secure_client.c` | TCP client: AES encryption + RSA signing + TCP send |
| `crypto_tasks.c` | Standalone: encrypt, decrypt, create_ds, check_signature |
| `test_corrupt.c` | Corruption test: VALID → corrupt → NOTVALID |
| `generate_keys.sh` | Shell script to generate RSA-2048 key pair via openssl |
| `Makefile` | Build system with targets: all, keys, clean |

### Appendix C — Key Technical Concepts

**AES-128-CBC:** Symmetric cipher using 128-bit key. CBC mode links each block to the previous ciphertext block using XOR, so identical plaintext blocks produce different ciphertext. PKCS#7 padding fills the final block.

**RSA-2048:** Asymmetric cipher with 2048-bit key pair. Signing = RSA-encrypt the SHA-256 hash with private key. Verification = RSA-decrypt the signature with public key and compare hashes.

**SHA-256:** One-way hash function producing a 32-byte digest. Used as the message digest within the RSA signing operation. Any change to the message produces a completely different digest.

**PKCS#7 Padding:** Padding scheme where N missing bytes are each filled with the value N. Example: 5-byte message in a 16-byte block → 11 bytes of value `0x0B` appended.

**PEM Format:** Base64-encoded key format surrounded by `-----BEGIN ...-----` headers. Used for RSA public and private key storage.

---

## BIBLIOGRAPHY / REFERENCES

1. W. Richard Stevens, Bill Fenner, Andrew M. Rudoff — *Unix Network Programming, Volume 1: The Sockets Networking API*, 3rd Edition, Addison-Wesley, 2003

2. OpenSSL Project — *OpenSSL 3.0 EVP API Documentation*
   https://www.openssl.org/docs/man3.0/man3/EVP_EncryptInit_ex.html

3. NIST FIPS 197 — *Advanced Encryption Standard (AES)*, National Institute of Standards and Technology, 2001

4. NIST FIPS 186-5 — *Digital Signature Standard (DSS)*, National Institute of Standards and Technology, 2023

5. RSA Laboratories — *PKCS#1: RSA Cryptography Standard*, Version 2.2

6. R. Rivest, A. Shamir, L. Adleman — *A Method for Obtaining Digital Signatures and Public-Key Cryptosystems*, Communications of the ACM, 1978

7. D. Eastlake, P. Jones — *RFC 3174: US Secure Hash Algorithm 1 (SHA1)*, IETF, 2001

8. Brian W. Kernighan, Dennis M. Ritchie — *The C Programming Language*, 2nd Edition, Prentice Hall, 1988

---

*End of Report*
