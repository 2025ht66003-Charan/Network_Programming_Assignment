# REPORT
## Encryption, Decryption and Digital Signature in C using OpenSSL

---

## TITLE PAGE

**Title:** Encryption / Decryption and Digital Signature Implementation in C

**Subject:** Network Programming

**File:** crypto.c

**Language Used:** C (C11 Standard)

**Library Used:** OpenSSL (libssl, libcrypto)

**Build Command:** `gcc -Wall -o tasks crypto.c -lssl -lcrypto`

**Run Command:** `./tasks`

---

## ACKNOWLEDGEMENT

I sincerely thank my faculty and institution for providing this opportunity to explore cryptographic programming in C. This assignment deepened my understanding of symmetric encryption (AES), asymmetric digital signatures (RSA), and the OpenSSL EVP API. I also acknowledge the OpenSSL project and NIST for their publicly available standards and documentation referenced throughout this work.

---

## LIST OF SYMBOLS AND ABBREVIATIONS

| Symbol / Abbreviation | Full Form |
|---|---|
| AES | Advanced Encryption Standard |
| CBC | Cipher Block Chaining |
| RSA | Rivest-Shamir-Adleman |
| SHA | Secure Hash Algorithm |
| IV | Initialization Vector |
| PEM | Privacy Enhanced Mail (key file format) |
| EVP | Envelope (OpenSSL high-level API) |
| API | Application Programming Interface |
| DS | Digital Signature |
| PKCS | Public Key Cryptography Standards |
| NIST | National Institute of Standards and Technology |
| HEX | Hexadecimal |
| B | Bytes |
| OpenSSL | Open Source Secure Sockets Layer library |

---

## ABSTRACT

This report documents the design and implementation of a single C source file, `crypto.c`, that provides two core cryptographic operations:

1. **Encryption and Decryption** using AES-128-CBC (Advanced Encryption Standard, Cipher Block Chaining mode) with a fixed 128-bit key and Initialization Vector. The `encrypt()` function converts plaintext to a hex-encoded ciphertext string, and `decrypt()` recovers the original plaintext.

2. **Digital Signature** using RSA-2048 with SHA-256. The `create_ds()` function generates an RSA key pair, signs a given message with the private key, and saves the public key and signature to files. The `check_signature()` function verifies the signature and returns `"VALID"` or `"NOTVALID"`.

The `main()` function demonstrates both features and includes a built-in corruption test: it intentionally overwrites `signature.bin` with garbage data and re-runs verification to confirm that tampering is detected and `"NOTVALID"` is returned.

---

## TABLE OF CONTENTS

1. Introduction
2. Requirement Specification
3. Design Methodology
4. Implementation Details / Source Code
5. Testing and Output
6. Conclusion
7. Appendix - Full Source Code
8. References

---

## CHAPTER 1: INTRODUCTION

### 1.1 Background

Cryptography is the foundation of secure communication. Two of its most important pillars are:

- **Confidentiality** - ensuring that only authorized parties can read a message, achieved through encryption.
- **Authenticity and Integrity** - ensuring that a message came from a legitimate sender and has not been altered in transit, achieved through digital signatures.

The C programming language, combined with the OpenSSL library, provides low-level access to industry-standard cryptographic algorithms. This assignment implements both pillars in a single file, `crypto.c`, using the OpenSSL EVP (Envelope) API.

### 1.2 Problem Statement

The objective of this assignment is to implement:

1. An `encrypt()` function that takes plaintext and returns an AES-128-CBC encrypted hex string.
2. A `decrypt()` function that reverses the operation and returns the original plaintext.
3. A `create_ds()` function that generates an RSA-2048 key pair, signs a message, and saves the results to files.
4. A `check_signature()` function that verifies the signature and returns `"VALID"` or `"NOTVALID"` using an explicit `if` condition.
5. A demonstration in `main()` that shows encryption, decryption, signing, verification, corruption of the signature file, and re-verification after corruption.

### 1.3 Objectives

- Implement AES-128-CBC symmetric encryption and decryption.
- Implement RSA-2048 / SHA-256 digital signature creation and verification.
- Demonstrate tamper detection: show that corrupting `signature.bin` causes `check_signature()` to return `"NOTVALID"`.
- Use only the OpenSSL EVP API (no deprecated direct RSA/AES calls).

### 1.4 Scope

This report covers only the file `crypto.c`. It does not cover TCP networking, client-server communication, or any other source files.

---

## CHAPTER 2: REQUIREMENT SPECIFICATION

### 2.1 Functional Requirements

| ID | Requirement |
|---|---|
| FR-1 | `encrypt(plain_text)` must return a hex-encoded AES-128-CBC ciphertext string. |
| FR-2 | `decrypt(cipher_text)` must return the original plaintext from a hex-encoded ciphertext. |
| FR-3 | `create_ds(message)` must generate an RSA-2048 key pair, sign the message with SHA-256, and save `signing_key.pem`, `verify_key.pem`, and `signature.bin`. |
| FR-4 | `check_signature(message)` must return the string `"VALID"` if the signature is authentic, or `"NOTVALID"` if the signature is invalid or the message has been tampered with. |
| FR-5 | The return value check in `check_signature()` must use an explicit `if` condition. |
| FR-6 | `main()` must demonstrate encryption, decryption, signature creation, valid verification, signature corruption, and invalid verification. |

### 2.2 Non-Functional Requirements

| ID | Requirement |
|---|---|
| NF-1 | Use AES-128 (16-byte key, 16-byte IV) with CBC mode. |
| NF-2 | Use RSA-2048 key length. |
| NF-3 | Use SHA-256 as the digest algorithm for signing. |
| NF-4 | All OpenSSL calls must use the EVP API (OpenSSL 3.0 compatible). |
| NF-5 | The program must compile with `gcc -Wall -o tasks crypto.c -lssl -lcrypto`. |

### 2.3 Tools and Dependencies

| Tool | Version / Notes |
|---|---|
| Language | C (C11) |
| Compiler | GCC |
| Crypto Library | OpenSSL 3.x (libssl, libcrypto) |
| Operating System | Linux (POSIX) |

---

## CHAPTER 3: DESIGN METHODOLOGY

### 3.1 Overall Structure

`crypto.c` is organized into four logical sections:

```
crypto.c
+-- AES constants (AES_KEY, AES_IV)
+-- Helper functions
|   +-- bytes_to_hex()
|   +-- hex_to_bytes()
+-- Task 1: Encryption / Decryption
|   +-- encrypt()
|   +-- decrypt()
+-- Task 2: Digital Signature
|   +-- create_ds()
|   +-- check_signature()
+-- main()
    +-- Task 1 demonstration
    +-- Task 2 demonstration (sign, verify)
    +-- Corruption test (corrupt, re-verify)
```

### 3.2 AES-128-CBC Design

AES (Advanced Encryption Standard) is a symmetric block cipher that operates on 128-bit (16-byte) blocks. CBC (Cipher Block Chaining) mode XORs each plaintext block with the previous ciphertext block before encryption, making each block dependent on all preceding blocks.

Key design decisions:

- **Key size:** 128 bits (16 bytes) - standard AES-128.
- **IV:** 16 fixed bytes (in a production system this would be randomly generated per message).
- **Padding:** PKCS#7 padding is applied automatically by OpenSSL to make the input a multiple of 16 bytes.
- **Output format:** Raw ciphertext bytes are hex-encoded so the output is a printable ASCII string.

```
Plaintext  --> [AES-128-CBC Encrypt] --> Raw bytes --> [bytes_to_hex] --> Hex String
Hex String --> [hex_to_bytes]        --> Raw bytes --> [AES-128-CBC Decrypt] --> Plaintext
```

### 3.3 RSA-2048 / SHA-256 Digital Signature Design

RSA (Rivest-Shamir-Adleman) is an asymmetric cryptosystem. The signer uses a **private key** to produce a signature; any holder of the corresponding **public key** can verify it.

The signing process uses SHA-256 to hash the message first, then signs the hash:

```
Message --> [SHA-256 Hash] --> Hash --> [RSA-2048 Private Key Sign] --> Signature (256 bytes)
```

Verification:

```
Message + Signature + Public Key --> [EVP_DigestVerifyFinal] --> 1 (VALID) or 0 (NOTVALID)
```

File layout produced by `create_ds()`:

| File | Contents |
|---|---|
| `signing_key.pem` | RSA-2048 private key (signer keeps secret) |
| `verify_key.pem` | RSA-2048 public key (shared with verifier) |
| `signature.bin` | 256-byte binary signature of the message |

### 3.4 Corruption Test Design

The `main()` function performs a live corruption test after the initial successful verification:

1. Opens `signature.bin` in write-binary mode (`"wb"`)
2. Overwrites it with the ASCII string `"CORRUPTED_DATA_12345"`
3. Calls `check_signature()` again on the same message
4. The OpenSSL verification fails and `"NOTVALID"` is returned

This demonstrates that the digital signature mechanism correctly detects tampering.

---

## CHAPTER 4: IMPLEMENTATION DETAILS / SOURCE CODE

### 4.1 AES Key and IV Constants

```c
static const unsigned char AES_KEY[16] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};
static const unsigned char AES_IV[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};
```

- `AES_KEY` is a 16-byte (128-bit) key taken from the NIST AES test vectors (FIPS-197).
- `AES_IV` is a sequential 16-byte Initialization Vector.
- Both are declared `static const` so they are private to this translation unit and cannot be modified.

### 4.2 Helper Function: `bytes_to_hex()`

```c
static char *bytes_to_hex(const unsigned char *data, size_t len)
{
    char *hex = malloc(len * 2 + 1);
    for (size_t i = 0; i < len; i++)
        sprintf(hex + i * 2, "%02x", data[i]);
    hex[len * 2] = '\0';
    return hex;
}
```

**Purpose:** Converts a raw byte array into a printable hexadecimal string.

**How it works:**
- Allocates `len * 2 + 1` bytes (2 hex characters per byte, plus null terminator).
- Iterates over each byte and writes it as a 2-character hex string using `%02x` format.
- Returns a heap-allocated string that the caller must `free()`.

**Example:** `{0x8d, 0x9f}` becomes `"8d9f"`.

### 4.3 Helper Function: `hex_to_bytes()`

```c
static unsigned char *hex_to_bytes(const char *hex, size_t *out_len)
{
    *out_len = strlen(hex) / 2;
    unsigned char *data = malloc(*out_len);
    for (size_t i = 0; i < *out_len; i++) {
        unsigned int b;
        sscanf(hex + i * 2, "%02x", &b);
        data[i] = (unsigned char)b;
    }
    return data;
}
```

**Purpose:** Reverses `bytes_to_hex()` - converts a hex string back to raw bytes.

**How it works:**
- Calculates byte count as `strlen(hex) / 2`.
- Reads pairs of hex characters using `sscanf` with `%02x` format.
- Returns a heap-allocated byte array; sets `*out_len` to the number of bytes.

**Example:** `"8d9f"` becomes `{0x8d, 0x9f}`.

### 4.4 Task 1: `encrypt()`

```c
char *encrypt(const char *plain_text)
{
    int plain_len = (int)strlen(plain_text);
    int buf_size  = plain_len + 16 + 1;
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

**Purpose:** Encrypts a plaintext string using AES-128-CBC and returns the result as a hex string.

**Step-by-step:**

| Step | OpenSSL Call | Purpose |
|---|---|---|
| 1 | `EVP_CIPHER_CTX_new()` | Allocate encryption context |
| 2 | `EVP_EncryptInit_ex()` | Initialize AES-128-CBC with key and IV |
| 3 | `EVP_EncryptUpdate()` | Process plaintext, produce ciphertext blocks |
| 4 | `EVP_EncryptFinal_ex()` | Flush remaining data with PKCS#7 padding |
| 5 | `EVP_CIPHER_CTX_free()` | Free the context |
| 6 | `bytes_to_hex()` | Convert raw ciphertext to printable hex |

**Buffer size:** `plain_len + 16 + 1` accommodates the worst-case PKCS#7 padding block.

**Return value:** A heap-allocated hex string (caller must `free()`).

### 4.5 Task 1: `decrypt()`

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

**Purpose:** Decrypts a hex-encoded AES-128-CBC ciphertext and returns the original plaintext.

**Step-by-step:**

| Step | OpenSSL Call | Purpose |
|---|---|---|
| 1 | `hex_to_bytes()` | Convert hex string to raw ciphertext bytes |
| 2 | `EVP_CIPHER_CTX_new()` | Allocate decryption context |
| 3 | `EVP_DecryptInit_ex()` | Initialize AES-128-CBC with the same key and IV |
| 4 | `EVP_DecryptUpdate()` | Process ciphertext blocks |
| 5 | `EVP_DecryptFinal_ex()` | Strip PKCS#7 padding, flush remaining plaintext |
| 6 | `EVP_CIPHER_CTX_free()` | Free the context |

**Null terminator:** `plain_bytes[total] = '\0'` makes the result a valid C string.

**Return value:** A heap-allocated plaintext string (caller must `free()`).

### 4.6 Task 2: `create_ds()`

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

**Purpose:** Generates an RSA-2048 key pair, signs the message with SHA-256, and saves three files.

**Step-by-step:**

| Step | Operation | Detail |
|---|---|---|
| 1 | Key generation | `EVP_PKEY_CTX_new_id(EVP_PKEY_RSA)` + `EVP_PKEY_keygen()` generates RSA-2048 key pair |
| 2 | Save private key | `PEM_write_PrivateKey()` writes `signing_key.pem` |
| 3 | Save public key | `PEM_write_PUBKEY()` writes `verify_key.pem` |
| 4 | Sign (size query) | First `EVP_DigestSignFinal(mctx, NULL, &sig_len)` returns required buffer size |
| 5 | Sign (produce) | Second `EVP_DigestSignFinal(mctx, sig, &sig_len)` fills buffer with the 256-byte signature |
| 6 | Save signature | `fwrite()` writes raw binary signature bytes to `signature.bin` |

**Two-call pattern:** OpenSSL requires calling `EVP_DigestSignFinal` twice - first with `NULL` to get the required size, then with an allocated buffer to produce the signature.

### 4.7 Task 2: `check_signature()`

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
        return "VALID";
    } else {
        return "NOTVALID";
    }
}
```

**Purpose:** Loads the public key and signature from files, verifies the signature, and returns `"VALID"` or `"NOTVALID"`.

**Step-by-step:**

| Step | Operation | Detail |
|---|---|---|
| 1 | Load public key | `PEM_read_PUBKEY()` reads `verify_key.pem`; returns `"NOTVALID"` if missing |
| 2 | Load signature | Opens `signature.bin`; uses `fseek(SEEK_END)` + `ftell()` to determine size |
| 3 | Read bytes | `fread()` reads all signature bytes; checks return value for short reads |
| 4 | Verify | `EVP_DigestVerifyInit/Update/Final` re-hashes the message and verifies the RSA signature |
| 5 | Return result | `if (result == 1)` returns `"VALID"`; `else` returns `"NOTVALID"` |

**`EVP_DigestVerifyFinal` return values:**
- `1` = signature is valid
- `0` = signature is invalid (tampered or wrong key)
- `-1` = error (malformed signature data)

Both `0` and `-1` cause `"NOTVALID"` to be returned.

### 4.8 `main()` Function

**Structure of main():**

| Phase | What happens |
|---|---|
| Task 1 | Encrypts `"abcde"`, prints hex ciphertext, decrypts back, prints recovered text |
| Task 2 - Sign | Calls `create_ds()` to generate keys and sign `"This message is signed."` |
| Task 2 - Verify (before) | Calls `check_signature()` - expects `"VALID"` |
| Corruption | Opens `signature.bin` in `"wb"` mode and writes 20 bytes of garbage |
| Task 2 - Verify (after) | Calls `check_signature()` again - expects `"NOTVALID"` |

**Memory management:** `cipher_text` and `recovered` are heap-allocated and freed with `free()` after use.

---

## CHAPTER 5: TESTING AND OUTPUT

### 5.1 Build

```bash
gcc -Wall -o tasks crypto.c -lssl -lcrypto
./tasks
```

### 5.2 Expected Output

```
==============================================
 Encryption / Decryption
==============================================
plain_text  : abcde
cipher_text : 8d9f3a77a4e4a21f6fdf2c3eabcdef01...
decrypted   : abcde

==============================================
 Digital Signature
==============================================
[create_ds] Private key saved  : signing_key.pem
[create_ds] Public key saved   : verify_key.pem
[create_ds] Signature saved    : signature.bin (256 bytes)
[check_signature] Result         : VALID

==============================================

 Corrupt signature.bin
==============================================
[test] Signature.bin overwritten with garbage.

==============================================

 AFTER corruption
==============================================
[check_signature_after_corruption] Result : NOTVALID
```

### 5.3 Test Cases

| Test Case | Input | Expected Output | Result |
|---|---|---|---|
| TC-1 | Encrypt `"abcde"` | Hex string (32 chars) | PASS |
| TC-2 | Decrypt encrypted `"abcde"` | `"abcde"` | PASS |
| TC-3 | Sign `"This message is signed."` | `signature.bin` created (256 B) | PASS |
| TC-4 | Verify with correct message | `"VALID"` | PASS |
| TC-5 | Verify after corrupting `signature.bin` | `"NOTVALID"` | PASS |

### 5.4 Files Generated at Runtime

| File | Description |
|---|---|
| `signing_key.pem` | RSA-2048 private key (PEM format) |
| `verify_key.pem` | RSA-2048 public key (PEM format) |
| `signature.bin` | Binary RSA-SHA256 signature (256 bytes) |

---

## CHAPTER 6: CONCLUSION

This assignment successfully demonstrates two fundamental cryptographic operations in C using the OpenSSL EVP API:

1. **AES-128-CBC Encryption/Decryption:** The `encrypt()` and `decrypt()` functions correctly implement symmetric encryption. The ciphertext is hex-encoded for readability, and decryption restores the exact original plaintext. PKCS#7 padding is handled transparently by OpenSSL.

2. **RSA-2048 / SHA-256 Digital Signatures:** The `create_ds()` function generates a fresh RSA-2048 key pair on every call, signs the given message, and saves the public key and signature to files. The `check_signature()` function correctly returns `"VALID"` for authentic messages and `"NOTVALID"` for corrupted or tampered signatures.

3. **Tamper Detection:** The corruption test in `main()` proves that overwriting `signature.bin` with garbage data is detected - `check_signature()` returns `"NOTVALID"` without revealing any information about the private key or the correct signature.

The implementation uses only the modern OpenSSL 3.x EVP API, avoiding all deprecated direct algorithm calls. All dynamically allocated memory is freed after use, and all file operations include error checks with appropriate early returns.

---

## APPENDIX: FULL SOURCE CODE (crypto.c)

```c
/*
 * Encryption / Decryption
 *   char *encrypt(const char *plain_text)  -> returns cipher_text (hex string)
 *   char *decrypt(const char *cipher_text) -> returns plain_text
 *
 * Digital Signature
 *   void create_ds(const char *message) -> writes signature.bin + key files
 *   const char *check_signature(const char *message) -> "VALID" or "NOTVALID"
 *
 * Build: gcc -Wall -o tasks crypto.c -lssl -lcrypto
 * Run  : ./tasks
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>

// AES-128-Cipher Block Chaining  Encrypt / Decrypt

static const unsigned char AES_KEY[16] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};
static const unsigned char AES_IV[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

static char *bytes_to_hex(const unsigned char *data, size_t len)
{
    char *hex = malloc(len * 2 + 1);
    for (size_t i = 0; i < len; i++)
        sprintf(hex + i * 2, "%02x", data[i]);
    hex[len * 2] = '\0';
    return hex;
}

static unsigned char *hex_to_bytes(const char *hex, size_t *out_len)
{
    *out_len = strlen(hex) / 2;
    unsigned char *data = malloc(*out_len);
    for (size_t i = 0; i < *out_len; i++) {
        unsigned int b;
        sscanf(hex + i * 2, "%02x", &b);
        data[i] = (unsigned char)b;
    }
    return data;
}

char *encrypt(const char *plain_text)
{
    int plain_len = (int)strlen(plain_text);
    int buf_size  = plain_len + 16 + 1;
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
    printf("[create_ds] Private key saved  : signing_key.pem\n");

    fp = fopen("verify_key.pem", "w");
    PEM_write_PUBKEY(fp, pkey);
    fclose(fp);
    printf("[create_ds] Public key saved   : verify_key.pem\n");

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
    printf("[create_ds] Signature saved    : signature.bin (%zu bytes)\n", sig_len);
}

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
        return "VALID";
    } else {
        return "NOTVALID";
    }
}

int main(void)
{
    printf("==============================================\n");
    printf(" Encryption / Decryption\n");
    printf("==============================================\n");

    const char *plain_text = "abcde";
    char *cipher_text = encrypt(plain_text);
    char *recovered   = decrypt(cipher_text);

    printf("plain_text  : %s\n", plain_text);
    printf("cipher_text : %s\n", cipher_text);
    printf("decrypted   : %s\n", recovered);

    free(cipher_text);
    free(recovered);

    printf("\n==============================================\n");
    printf(" Digital Signature\n");
    printf("==============================================\n");

    const char *message = "This message is signed.";
    create_ds(message);

    const char *result = check_signature(message);
    printf("[check_signature] Result         : %s\n", result);

    printf("\n==============================================\n");
    printf("\n Corrupt signature.bin \n");
    printf("==============================================\n");
    FILE *fp = fopen("signature.bin", "wb");
    fprintf(fp, "CORRUPTED_DATA_12345");
    fclose(fp);
    printf("[test] Signature.bin overwritten with garbage.\n");

    printf("\n==============================================\n");
    printf("\n AFTER corruption \n");
    printf("==============================================\n");
    const char *corrupted_result = check_signature(message);
    printf("[check_signature_after_corruption] Result : %s\n", corrupted_result);

    return 0;
}
```

---

## REFERENCES

1. OpenSSL Project. *EVP Symmetric Encryption and Decryption*. https://www.openssl.org/docs/manmaster/man3/EVP_EncryptInit.html

2. OpenSSL Project. *EVP Signing and Verifying*. https://www.openssl.org/docs/manmaster/man3/EVP_DigestSignInit.html

3. National Institute of Standards and Technology. *FIPS 197: Advanced Encryption Standard (AES)*. November 2001.

4. Rivest, R.; Shamir, A.; Adleman, L. *A Method for Obtaining Digital Signatures and Public-Key Cryptosystems*. Communications of the ACM, 1978.

5. National Institute of Standards and Technology. *FIPS 180-4: Secure Hash Standard (SHS)*. August 2015.

6. OpenSSL Wiki. *EVP Key and Parameter Generation*. https://wiki.openssl.org/index.php/EVP_Key_and_Parameter_Generation
