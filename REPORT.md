# Network Programming Assignment
## Encryption, Decryption and Digital Signature in C

**Name:** Charan
**Subject:** Network Programming
**File:** crypto.c
**Build:** `gcc -Wall -o tasks crypto.c -lssl -lcrypto`

---

## 1. Introduction

This assignment implements two cryptographic tasks in C using the OpenSSL library:

- **Task 1 — Encryption / Decryption** using AES-128-CBC
- **Task 2 — Digital Signature** using RSA-2048 with SHA-256

The program encrypts a message, decrypts it back, signs it with a private key, verifies the signature, and then demonstrates tamper detection by corrupting the signature file.

---

## 2. Functions Implemented

### Task 1: Encryption and Decryption

**`encrypt(plain_text)`**
- Takes a plaintext string as input
- Encrypts it using AES-128-CBC with a fixed 16-byte key and IV
- Returns the ciphertext as a hex-encoded string

**`decrypt(cipher_text)`**
- Takes a hex-encoded ciphertext string as input
- Decrypts it using the same AES-128-CBC key and IV
- Returns the original plaintext string

### Task 2: Digital Signature

**`create_ds(message)`**
- Generates a fresh RSA-2048 key pair
- Signs the message using the private key with SHA-256
- Saves three files:
  - `signing_key.pem` — private key
  - `verify_key.pem` — public key
  - `signature.bin` — the digital signature (256 bytes)

**`check_signature(message)`**
- Loads `verify_key.pem` and `signature.bin`
- Verifies the signature against the message using the public key
- Returns `"VALID"` if the signature is authentic
- Returns `"NOTVALID"` if the signature is invalid or the file has been tampered

```c
if (result == 1) {
    return "VALID";
} else {
    return "NOTVALID";
}
```

---

## 3. Source Code

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>

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

## 4. Output

```
==============================================
 Encryption / Decryption
==============================================
plain_text  : abcde
cipher_text : 8d9f3a77a4e4a21f6fdf2c3e...
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

---

## 5. How It Works

**AES-128-CBC (Task 1)**

AES is a symmetric cipher — the same key is used to encrypt and decrypt. CBC mode chains each block to the previous one so identical plaintext blocks produce different ciphertext. The output is hex-encoded to keep it printable.

**RSA-2048 + SHA-256 (Task 2)**

RSA is asymmetric — a private key signs, the public key verifies. The message is first hashed with SHA-256, then the hash is signed. The signature is 256 bytes and is saved to `signature.bin`. When `check_signature()` is called, it reloads the public key and signature, re-hashes the message, and confirms the signature matches. Overwriting `signature.bin` with garbage breaks this match and returns `NOTVALID`.

---

## 6. Conclusion

The program successfully demonstrates:

- `encrypt("abcde")` produces a hex ciphertext, and `decrypt()` recovers `"abcde"` exactly.
- `create_ds()` signs a message and saves the key files and signature.
- `check_signature()` returns `VALID` for the original message.
- After corrupting `signature.bin`, `check_signature()` correctly returns `NOTVALID`, proving that any tampering is detected.
