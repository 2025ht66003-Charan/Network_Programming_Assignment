/*
 * crypto_common.h
 * Shared constants and packet layout for the secure TCP streaming demo.
 *
 * Wire packet (per message):
 *   [4 B]  sig_len    – network byte order
 *   [4 B]  cipher_len – network byte order
 *   [16 B] IV         – random per message
 *   [sig_len B]    RSA-SHA256 signature over ciphertext
 *   [cipher_len B] AES-256-CBC ciphertext
 */

#ifndef CRYPTO_COMMON_H
#define CRYPTO_COMMON_H

#include <stdint.h>

#define SERVER_PORT   8443
#define SERVER_IP     "127.0.0.1"
#define MAX_MSG_LEN   4096
#define AES_KEY_LEN   32   /* AES-256 */
#define AES_IV_LEN    16
#define MAX_SIG_LEN   512  /* RSA-2048 signature */
#define MAX_CIPHER_LEN (MAX_MSG_LEN + AES_IV_LEN)

/*
 * Pre-shared AES-256 key (bytes from NIST FIPS-197 example key schedule).
 * In production this would be established via RSA/ECDH key exchange.
 */
static const unsigned char SHARED_AES_KEY[AES_KEY_LEN] = {
    0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
    0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
    0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
};

/* Packet header sent before each message */
typedef struct {
    uint32_t sig_len;
    uint32_t cipher_len;
    unsigned char iv[AES_IV_LEN];
} __attribute__((packed)) PktHeader;

#endif /* CRYPTO_COMMON_H */
