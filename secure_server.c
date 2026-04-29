/*
 * secure_server.c
 *
 * Secure TCP streaming server.
 *
 * Each received packet is:
 *   1. Signature-verified  – RSA-2048 / SHA-256 using client's public key
 *   2. Decrypted           – AES-256-CBC with the pre-shared key
 *
 * Build: see Makefile
 * Run  : ./server
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include "crypto_common.h"

/* ------------------------------------------------------------------ helpers */

static void ssl_die(const char *label)
{
    fprintf(stderr, "[Server] %s: ", label);
    ERR_print_errors_fp(stderr);
    fprintf(stderr, "\n");
}

/* Receive exactly n bytes, blocking until done or connection drops. */
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

/* ----------------------------------------------------------------- crypto */

/*
 * AES-256-CBC decrypt.
 * Returns plaintext length on success, -1 on failure.
 */
static int aes_decrypt(const unsigned char *ciphertext, int cipher_len,
                       const unsigned char *key,  const unsigned char *iv,
                       unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { ssl_die("EVP_CIPHER_CTX_new"); return -1; }

    int len = 0, total = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        ssl_die("EVP_DecryptInit_ex"); goto fail;
    }
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, cipher_len) != 1) {
        ssl_die("EVP_DecryptUpdate"); goto fail;
    }
    total = len;
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
        ssl_die("EVP_DecryptFinal_ex (bad key/IV or tampered data)"); goto fail;
    }
    total += len;
    EVP_CIPHER_CTX_free(ctx);
    return total;

fail:
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}

/*
 * Verify RSA-SHA256 digital signature.
 * Returns 1 if valid, 0 if invalid or error.
 */
static int verify_signature(EVP_PKEY *pubkey,
                             const unsigned char *data, size_t data_len,
                             const unsigned char *sig,  size_t sig_len)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) { ssl_die("EVP_MD_CTX_new"); return 0; }

    int ok = 0;
    if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pubkey) != 1) {
        ssl_die("EVP_DigestVerifyInit"); goto done;
    }
    if (EVP_DigestVerifyUpdate(ctx, data, data_len) != 1) {
        ssl_die("EVP_DigestVerifyUpdate"); goto done;
    }
    ok = (EVP_DigestVerifyFinal(ctx, sig, sig_len) == 1);

done:
    EVP_MD_CTX_free(ctx);
    return ok;
}

/* ------------------------------------------------------------------ main */

static void handle_client(int client_fd, EVP_PKEY *pubkey)
{
    printf("[Server] Session started – waiting for messages...\n");
    printf("[Server] %-12s %-10s %s\n", "Status", "Cipher(B)", "Plaintext");
    printf("[Server] %s\n", "----------------------------------------------------");

    for (;;) {
        /* --- read packet header --- */
        PktHeader hdr;
        if (recv_exact(client_fd, &hdr, sizeof(hdr)) < 0) {
            printf("[Server] Client disconnected.\n");
            break;
        }

        uint32_t sig_len    = ntohl(hdr.sig_len);
        uint32_t cipher_len = ntohl(hdr.cipher_len);

        /* sanity bounds */
        if (sig_len == 0 || sig_len > MAX_SIG_LEN ||
            cipher_len == 0 || cipher_len > MAX_CIPHER_LEN) {
            fprintf(stderr, "[Server] Malformed packet (sig=%u cipher=%u) – dropping.\n",
                    sig_len, cipher_len);
            break;
        }

        /* --- allocate and receive payload --- */
        unsigned char *sig        = malloc(sig_len);
        unsigned char *ciphertext = malloc(cipher_len);
        unsigned char *plaintext  = malloc(cipher_len + AES_IV_LEN + 1);

        if (!sig || !ciphertext || !plaintext) {
            fprintf(stderr, "[Server] Out of memory.\n");
            free(sig); free(ciphertext); free(plaintext);
            break;
        }

        if (recv_exact(client_fd, sig,        sig_len)    < 0 ||
            recv_exact(client_fd, ciphertext, cipher_len) < 0) {
            fprintf(stderr, "[Server] Connection lost while reading payload.\n");
            free(sig); free(ciphertext); free(plaintext);
            break;
        }

        /* --- step 1: verify digital signature --- */
        if (!verify_signature(pubkey, ciphertext, cipher_len, sig, sig_len)) {
            fprintf(stderr,
                    "[Server] *** SIGNATURE INVALID – message rejected! "
                    "(possible tampering or wrong sender)\n");
            free(sig); free(ciphertext); free(plaintext);
            continue;   /* keep connection open but reject this message */
        }

        /* --- step 2: decrypt --- */
        int plain_len = aes_decrypt(ciphertext, (int)cipher_len,
                                    SHARED_AES_KEY, hdr.iv, plaintext);
        if (plain_len < 0) {
            fprintf(stderr, "[Server] Decryption failed.\n");
            free(sig); free(ciphertext); free(plaintext);
            continue;
        }
        plaintext[plain_len] = '\0';

        printf("[Server] %-12s %-10u \"%s\"\n",
               "OK (verified)", cipher_len, plaintext);

        free(sig);
        free(ciphertext);
        free(plaintext);
    }
}

int main(void)
{
    /* Load client's RSA public key for signature verification */
    FILE *fp = fopen("client_public.pem", "r");
    if (!fp) {
        fprintf(stderr,
                "[Server] Cannot open 'client_public.pem'.\n"
                "         Run './generate_keys.sh' first.\n");
        return EXIT_FAILURE;
    }
    EVP_PKEY *pubkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!pubkey) { ssl_die("PEM_read_PUBKEY"); return EXIT_FAILURE; }
    printf("[Server] Loaded client public key (RSA-2048, SHA-256 signing).\n");

    /* Create TCP socket */
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) { perror("[Server] socket"); return EXIT_FAILURE; }

    int reuse = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    struct sockaddr_in addr = {0};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(SERVER_PORT);

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("[Server] bind"); close(server_fd); return EXIT_FAILURE;
    }
    if (listen(server_fd, 5) < 0) {
        perror("[Server] listen"); close(server_fd); return EXIT_FAILURE;
    }
    printf("[Server] Listening on port %d (AES-256-CBC + RSA-2048/SHA-256)...\n",
           SERVER_PORT);

    /* Accept one client (extend with fork/threads for multiple clients) */
    struct sockaddr_in client_addr = {0};
    socklen_t clen = sizeof(client_addr);
    int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &clen);
    if (client_fd < 0) {
        perror("[Server] accept"); close(server_fd); return EXIT_FAILURE;
    }
    printf("[Server] Client connected from %s:%d\n",
           inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

    handle_client(client_fd, pubkey);

    close(client_fd);
    close(server_fd);
    EVP_PKEY_free(pubkey);
    printf("[Server] Shutdown.\n");
    return EXIT_SUCCESS;
}
