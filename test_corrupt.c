#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

static void create_ds(const char *message)
{
    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY_keygen_init(kctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, 2048);
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_keygen(kctx, &pkey);
    EVP_PKEY_CTX_free(kctx);

    FILE *fp = fopen("verify_key.pem", "w");
    PEM_write_PUBKEY(fp, pkey); fclose(fp);

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
    fwrite(sig, 1, sig_len, fp); fclose(fp);
    free(sig);
    printf("[create_ds] Keys + signature generated.\n");
}

static const char *check_signature(const char *message)
{
    FILE *fp = fopen("verify_key.pem", "r");
    if (!fp) return "NOTVALID";
    EVP_PKEY *pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!pkey) return "NOTVALID";

    fp = fopen("signature.bin", "rb");
    if (!fp) { EVP_PKEY_free(pkey); return "NOTVALID"; }
    fseek(fp, 0, SEEK_END);
    long sig_len = ftell(fp); rewind(fp);
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
        printf("Signature check : NOTVALID — message is corrupt or tampered!\n");
        return "NOTVALID";
    }
}

int main(void)
{
    const char *msg = "This message is signed.";

    printf("=== STEP 1: Create valid signature ===\n");
    create_ds(msg);

    printf("\n=== STEP 2: Check BEFORE corruption ===\n");
    const char *r1 = check_signature(msg);
    printf("[test] Result : %s\n", r1);

    printf("\n=== STEP 3: Corrupt signature.bin ===\n");
    FILE *fp = fopen("signature.bin", "wb");
    fprintf(fp, "CORRUPTED_DATA_12345");
    fclose(fp);
    printf("[test] signature.bin overwritten with garbage.\n");

    printf("\n=== STEP 4: Check AFTER corruption ===\n");
    const char *r2 = check_signature(msg);
    printf("[test] Result : %s\n", r2);

    return 0;
}
