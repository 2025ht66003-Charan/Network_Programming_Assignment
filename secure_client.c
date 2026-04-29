/*
 * secure_client.c
 *
 * Secure TCP streaming client.
 *
 * For each message typed by the user:
 *   1. Encrypt  – AES-256-CBC with a fresh random IV per message
 *   2. Sign     – RSA-2048 / SHA-256 over the ciphertext (sign-then-send)
 *   3. Send     – PktHeader + signature + ciphertext over TCP
 *
 * Build: see Makefile
 * Run  : ./client
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include "crypto_common.h"

/* ------------------------------------------------------------------ helpers */

static void ssl_die(const char *label)
{
    fprintf(stderr, "[Client] %s: ", label);
    ERR_print_errors_fp(stderr);
    fprintf(stderr, "\n");
}

/* Send exactly n bytes, retrying on partial writes. */
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

/* ----------------------------------------------------------------- crypto */

/*
 * AES-256-CBC encrypt.
 * Returns ciphertext length (>= plain_len due to PKCS#7 padding), -1 on error.
 * Caller must allocate ciphertext with at least (plain_len + AES_IV_LEN) bytes.
 */
static int aes_encrypt(const unsigned char *plaintext, int plain_len,
                       const unsigned char *key,       const unsigned char *iv,
                       unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { ssl_die("EVP_CIPHER_CTX_new"); return -1; }

    int len = 0, total = 0;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        ssl_die("EVP_EncryptInit_ex"); goto fail;
    }
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plain_len) != 1) {
        ssl_die("EVP_EncryptUpdate"); goto fail;
    }
    total = len;
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        ssl_die("EVP_EncryptFinal_ex"); goto fail;
    }
    total += len;
    EVP_CIPHER_CTX_free(ctx);
    return total;

fail:
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}

/*
 * Sign data with RSA private key using SHA-256.
 * Allocates *sig on success; caller must free().
 * Returns 1 on success, 0 on failure.
 */
static int rsa_sign(EVP_PKEY *privkey,
                    const unsigned char *data, size_t data_len,
                    unsigned char **sig, size_t *sig_len)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) { ssl_die("EVP_MD_CTX_new"); return 0; }

    *sig = NULL;

    if (EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, privkey) != 1) {
        ssl_die("EVP_DigestSignInit"); goto fail;
    }
    if (EVP_DigestSignUpdate(ctx, data, data_len) != 1) {
        ssl_die("EVP_DigestSignUpdate"); goto fail;
    }
    /* First call: get required buffer size */
    if (EVP_DigestSignFinal(ctx, NULL, sig_len) != 1) {
        ssl_die("EVP_DigestSignFinal (size query)"); goto fail;
    }
    *sig = malloc(*sig_len);
    if (!*sig) { fprintf(stderr, "[Client] OOM\n"); goto fail; }

    /* Second call: produce the actual signature */
    if (EVP_DigestSignFinal(ctx, *sig, sig_len) != 1) {
        ssl_die("EVP_DigestSignFinal"); free(*sig); *sig = NULL; goto fail;
    }
    EVP_MD_CTX_free(ctx);
    return 1;

fail:
    EVP_MD_CTX_free(ctx);
    return 0;
}

/* ------------------------------------------------------------------- send */

/*
 * Encrypt msg and send a signed packet to the server.
 * Returns 0 on success, -1 on any error.
 */
static int send_secure_message(int sock, EVP_PKEY *privkey, const char *msg)
{
    unsigned char iv[AES_IV_LEN];
    unsigned char ciphertext[MAX_CIPHER_LEN];
    unsigned char *sig     = NULL;
    size_t         sig_len = 0;
    int result = -1;

    /* Fresh random IV for every message (critical for CBC security) */
    if (RAND_bytes(iv, AES_IV_LEN) != 1) {
        ssl_die("RAND_bytes"); return -1;
    }

    /* Step 1 – Encrypt plaintext */
    int cipher_len = aes_encrypt((const unsigned char *)msg, (int)strlen(msg),
                                  SHARED_AES_KEY, iv, ciphertext);
    if (cipher_len < 0) return -1;

    /* Step 2 – Sign the ciphertext (sign-then-encrypt misordering note:
     *           here we sign the ciphertext so the server can verify before
     *           spending cycles decrypting, which is the typical server-side
     *           preference; signing the plaintext is also valid depending on
     *           the threat model). */
    if (!rsa_sign(privkey, ciphertext, (size_t)cipher_len, &sig, &sig_len))
        return -1;

    /* Step 3 – Build and send header + payload */
    PktHeader hdr;
    hdr.sig_len    = htonl((uint32_t)sig_len);
    hdr.cipher_len = htonl((uint32_t)cipher_len);
    memcpy(hdr.iv, iv, AES_IV_LEN);

    if (send_exact(sock, &hdr,        sizeof(hdr))  < 0 ||
        send_exact(sock, sig,         sig_len)       < 0 ||
        send_exact(sock, ciphertext,  (size_t)cipher_len) < 0) {
        perror("[Client] send");
        goto done;
    }

    printf("[Client] Sent (AES-%uB cipher, RSA-%zuB sig): \"%s\"\n",
           (unsigned)cipher_len, sig_len, msg);
    result = 0;

done:
    free(sig);
    return result;
}

/* ------------------------------------------------------------------ main */

int main(void)
{
    /* Load RSA private key for signing */
    FILE *fp = fopen("client_private.pem", "r");
    if (!fp) {
        fprintf(stderr,
                "[Client] Cannot open 'client_private.pem'.\n"
                "         Run './generate_keys.sh' first.\n");
        return EXIT_FAILURE;
    }
    EVP_PKEY *privkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!privkey) { ssl_die("PEM_read_PrivateKey"); return EXIT_FAILURE; }
    printf("[Client] Loaded private key (RSA-2048).\n");

    /* Create TCP socket and connect */
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) { perror("[Client] socket"); return EXIT_FAILURE; }

    struct sockaddr_in saddr = {0};
    saddr.sin_family = AF_INET;
    saddr.sin_port   = htons(SERVER_PORT);
    if (inet_pton(AF_INET, SERVER_IP, &saddr.sin_addr) <= 0) {
        perror("[Client] inet_pton"); return EXIT_FAILURE;
    }

    if (connect(sock, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
        perror("[Client] connect"); return EXIT_FAILURE;
    }
    printf("[Client] Connected to %s:%d\n", SERVER_IP, SERVER_PORT);
    printf("[Client] Type messages (Ctrl+D or empty line to quit):\n> ");
    fflush(stdout);

    /* Interactive send loop */
    char buf[MAX_MSG_LEN];
    while (fgets(buf, sizeof(buf), stdin)) {
        buf[strcspn(buf, "\n")] = '\0';     /* strip trailing newline */
        if (buf[0] == '\0') break;          /* empty line = quit */

        if (send_secure_message(sock, privkey, buf) < 0) {
            fprintf(stderr, "[Client] Send failed – disconnecting.\n");
            break;
        }
        printf("> ");
        fflush(stdout);
    }

    printf("[Client] Closing connection.\n");
    close(sock);
    EVP_PKEY_free(privkey);
    return EXIT_SUCCESS;
}
