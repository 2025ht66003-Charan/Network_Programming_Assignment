/*
 * crypto_tasks.c
 *
 * Task 1 — Encryption / Decryption
 *   char *encrypt(const char *plain_text)  -> returns cipher_text (hex string)
 *   char *decrypt(const char *cipher_text) -> returns plain_text
 *
 * Task 2 — Digital Signature
 *   void        create_ds(const char *message) -> writes signature.bin + key files
 *   const char *check_signature(const char *message) -> "OK" or "NOTVALID"
 *
 * Build: gcc -Wall -o tasks crypto_tasks.c -lssl -lcrypto
 * Run  : ./tasks
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>

/* =========================================================================
 * TASK 1 — AES-128-CBC  Encrypt / Decrypt
 *
 *  - Algorithm : AES  (Advanced Encryption Standard)
 *  - Mode      : CBC  (Cipher Block Chaining)
 *  - Key size  : 128 bits (16 bytes)
 *  - The ciphertext is returned as a HEX string so it is printable.
 * ========================================================================= */

/* Fixed 16-byte key and IV (Initialization Vector).
   In production these would be secret and randomly generated. */
static const unsigned char AES_KEY[16] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};
static const unsigned char AES_IV[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

/* --- helper: raw bytes → hex string (caller must free) --- */
static char *bytes_to_hex(const unsigned char *data, size_t len)
{
    char *hex = malloc(len * 2 + 1);
    for (size_t i = 0; i < len; i++)
        sprintf(hex + i * 2, "%02x", data[i]);
    hex[len * 2] = '\0';
    return hex;
}

/* --- helper: hex string → raw bytes (caller must free, sets *out_len) --- */
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

/*
 * encrypt(plain_text)
 *   Input : any text string   e.g. "abcde"
 *   Output: hex-encoded ciphertext string (caller must free)
 */
char *encrypt(const char *plain_text)
{
    int plain_len  = (int)strlen(plain_text);
    int buf_size   = plain_len + 16 + 1;          /* +16 for PKCS7 padding block */
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
    return hex;                    /* e.g. "8d9f3a..." */
}

/*
 * decrypt(cipher_text)
 *   Input : hex-encoded ciphertext string from encrypt()
 *   Output: original plain text string (caller must free)
 */
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
    return (char *)plain_bytes;    /* e.g. "abcde" */
}


/* =========================================================================
 * TASK 2 — RSA-2048 / SHA-256  Digital Signature
 *
 *  create_ds()      : generates an RSA-2048 key pair, signs the message,
 *                     and saves three files:
 *                       signing_key.pem  — private key  (kept secret by signer)
 *                       verify_key.pem   — public key   (shared with verifier)
 *                       signature.bin    — the digital signature bytes
 *
 *  check_signature(): loads verify_key.pem + signature.bin, re-verifies the
 *                     message, returns "OK" or "NOTVALID".
 * ========================================================================= */

/*
 * create_ds(message)
 *   Generates a fresh RSA-2048 key pair, signs `message` with the
 *   private key (SHA-256 digest), and writes the key files + signature.
 */
void create_ds(const char *message)
{
    /* --- 1. Generate RSA-2048 key pair --- */
    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY_keygen_init(kctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, 2048);

    EVP_PKEY *pkey = NULL;
    EVP_PKEY_keygen(kctx, &pkey);
    EVP_PKEY_CTX_free(kctx);

    /* --- 2. Save private key → signing_key.pem --- */
    FILE *fp = fopen("signing_key.pem", "w");
    PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, NULL, NULL);
    fclose(fp);
    printf("[create_ds] Private key saved  : signing_key.pem\n");

    /* --- 3. Save public key → verify_key.pem --- */
    fp = fopen("verify_key.pem", "w");
    PEM_write_PUBKEY(fp, pkey);
    fclose(fp);
    printf("[create_ds] Public key saved   : verify_key.pem\n");

    /* --- 4. Sign the message with SHA-256 --- */
    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    EVP_DigestSignInit(mctx, NULL, EVP_sha256(), NULL, pkey);
    EVP_DigestSignUpdate(mctx, message, strlen(message));

    size_t sig_len = 0;
    EVP_DigestSignFinal(mctx, NULL, &sig_len);        /* query size first */
    unsigned char *sig = malloc(sig_len);
    EVP_DigestSignFinal(mctx, sig, &sig_len);         /* produce signature */
    EVP_MD_CTX_free(mctx);
    EVP_PKEY_free(pkey);

    /* --- 5. Save signature bytes → signature.bin --- */
    fp = fopen("signature.bin", "wb");
    fwrite(sig, 1, sig_len, fp);
    fclose(fp);
    free(sig);
    printf("[create_ds] Signature saved    : signature.bin (%zu bytes)\n", sig_len);
}

/*
 * check_signature(message)
 *   Loads verify_key.pem and signature.bin, then verifies that the
 *   signature was produced for `message` by the matching private key.
 *   Returns "OK" if valid, "NOTVALID" otherwise.
 */
const char *check_signature(const char *message)
{
    /* --- load public key --- */
    FILE *fp = fopen("verify_key.pem", "r");
    if (!fp) return "NOTVALID";
    EVP_PKEY *pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!pkey) return "NOTVALID";

    /* --- load signature --- */
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

    /* --- verify --- */
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
        printf("Signature check : NOTVALID — message is corrupt or tampered!\n");
        return "NOTVALID";
    }
}


/* =========================================================================
 * main — demonstrates both tasks
 * ========================================================================= */

int main(void)
{
    printf("==============================================\n");
    printf(" TASK 1 — Encryption / Decryption\n");
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
    printf(" TASK 2 — Digital Signature\n");
    printf("==============================================\n");

    const char *message = "This message is signed.";

    /* 2.1 create digital signature and store key files */
    create_ds(message);

    /* 2.2 verify the signature */
    const char *result = check_signature(message);
    printf("[check_signature] Original message : %s\n", result);

    /* tamper test: different message → must say NOTVALID */
    const char *bad_result = check_signature("tampered message");
    printf("[check_signature] Tampered message : %s\n", bad_result);

    return 0;
}
