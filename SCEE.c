#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define SCEE_ALGORITHM EVP_aes_128_gcm
#define SCEE_TAG_LENGTH 16
#define SCEE_NONCE_LENGTH 12

#define SCEE_OK 0
#define SCEE_ERROR_RAND 1
#define SCEE_ERROR_CTX_NEW 2
#define SCEE_ERROR_CTX_ALGORITHM 3
#define SCEE_ERROR_CTX_KEY_NONCE 4
#define SCEE_ERROR_CRYPT 5
#define SCEE_ERROR_CRYPT_FINAL 6
#define SCEE_ERROR_CRYPT_TAG 7
#define SCEE_ERROR_CRYPT_TAG_INVALID 8

int encrypt(const uint8_t* plaintext, size_t plaintext_length, const uint8_t* key, uint8_t* ciphertext_and_nonce, size_t* ciphertext_and_nonce_length_out) {
    // Generate a 96-bit nonce using a CSPRNG.
    uint8_t nonce[SCEE_NONCE_LENGTH];
    if (!RAND_bytes(nonce, SCEE_NONCE_LENGTH)) { return SCEE_ERROR_RAND; }

    // Create the cipher context and initialize.
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { return SCEE_ERROR_CTX_NEW; }

    if (!EVP_EncryptInit_ex(ctx, SCEE_ALGORITHM(), NULL, NULL, NULL)) {
        EVP_CIPHER_CTX_free(ctx);
        return SCEE_ERROR_CTX_ALGORITHM;
    }
    if (!EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce)) {
        EVP_CIPHER_CTX_free(ctx);
        return SCEE_ERROR_CTX_KEY_NONCE;
    }

    // Encrypt and prepend nonce.
    int temp_length;
    uint8_t ciphertext[plaintext_length];

    if (!EVP_EncryptUpdate(ctx, ciphertext, &temp_length, plaintext, plaintext_length)) {
        EVP_CIPHER_CTX_free(ctx);
        return SCEE_ERROR_CRYPT;
    }
    *ciphertext_and_nonce_length_out = temp_length;

    if (!EVP_EncryptFinal_ex(ctx, ciphertext + temp_length, &temp_length)) {
        EVP_CIPHER_CTX_free(ctx);
        return SCEE_ERROR_CRYPT_FINAL;
    }
    *ciphertext_and_nonce_length_out += temp_length;

    uint8_t tag[SCEE_TAG_LENGTH];
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, SCEE_TAG_LENGTH, tag)) {
        EVP_CIPHER_CTX_free(ctx);
        return SCEE_ERROR_CRYPT_TAG;
    }

    memcpy(ciphertext_and_nonce, nonce, SCEE_NONCE_LENGTH);
    memcpy(ciphertext_and_nonce + SCEE_NONCE_LENGTH, ciphertext, plaintext_length);
    memcpy(ciphertext_and_nonce + SCEE_NONCE_LENGTH + plaintext_length, tag, SCEE_TAG_LENGTH);
    *ciphertext_and_nonce_length_out += SCEE_NONCE_LENGTH + SCEE_TAG_LENGTH;

    return SCEE_OK;
}

int decrypt(const uint8_t* ciphertext_and_nonce, size_t ciphertext_and_nonce_length, const uint8_t* key, uint8_t* plaintext, size_t* plaintext_length_out) {
    // Retrieve the nonce and ciphertext.
    size_t ciphertext_length = ciphertext_and_nonce_length - SCEE_NONCE_LENGTH - SCEE_TAG_LENGTH;
    uint8_t ciphertext[ciphertext_length];
    uint8_t nonce[SCEE_NONCE_LENGTH];
    uint8_t tag[SCEE_NONCE_LENGTH];

    memcpy(nonce, ciphertext_and_nonce, SCEE_NONCE_LENGTH);
    memcpy(ciphertext, ciphertext_and_nonce + SCEE_NONCE_LENGTH, ciphertext_length);
    memcpy(tag, ciphertext_and_nonce + SCEE_NONCE_LENGTH + ciphertext_length, SCEE_TAG_LENGTH);

    // Create the cipher context and initialize.
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { return SCEE_ERROR_CTX_NEW; }

    if (!EVP_DecryptInit_ex(ctx, SCEE_ALGORITHM(), NULL, NULL, NULL)) {
        EVP_CIPHER_CTX_free(ctx);
        return SCEE_ERROR_CTX_ALGORITHM;
    }
    if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce)) {
        EVP_CIPHER_CTX_free(ctx);
        return SCEE_ERROR_CTX_KEY_NONCE;
    }

    // Decrypt and return result.
    int temp_length;

    if (!EVP_DecryptUpdate(ctx, plaintext, &temp_length, ciphertext, ciphertext_length)) {
        EVP_CIPHER_CTX_free(ctx);
        return SCEE_ERROR_CRYPT;
    }
    *plaintext_length_out = temp_length;

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, SCEE_TAG_LENGTH, tag)) {
        return SCEE_ERROR_CRYPT_TAG;
    }

    if (EVP_DecryptFinal_ex(ctx, plaintext + temp_length, &temp_length) < 1) {
        EVP_CIPHER_CTX_free(ctx);
        return SCEE_ERROR_CRYPT_TAG_INVALID;
    }
    *plaintext_length_out += temp_length;

    return SCEE_OK;
}
