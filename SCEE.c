#include "scee.h"

// Base64.
size_t b64_get_length(size_t current_size, int operation) {
    if (operation == SCEE_B64_ENCODE) {
        return ((current_size + 2) / 3) * 4 + 1;
    } else {
        return (current_size * 3) / 4;
    }
}
int b64_encode(const uint8_t* bytes, size_t length, char* str) {
    if (!EVP_EncodeBlock(str, bytes, length)) {
        return SCEE_ERROR_B64;
    }

    return SCEE_OK;
}
int b64_decode(const char* str, size_t length, uint8_t* bytes, size_t* decode_size_out) {
    int pad_count = 0;
    if (str[length - 1] == '=') { pad_count++; }
    if (str[length - 2] == '=') { pad_count++; }

    int decode_size = EVP_DecodeBlock(bytes, str, length);
    if (decode_size == -1) {
        return SCEE_ERROR_B64;
    }

    *decode_size_out = (size_t)decode_size - pad_count;

    return SCEE_OK;
}

// PBKDF2.
int pbkdf2(const char* password, size_t password_length, const uint8_t* salt, size_t salt_length, int iterations, const EVP_MD* digest, uint8_t* key_out, size_t key_length) {
    if (!PKCS5_PBKDF2_HMAC(password, password_length, salt, salt_length, iterations, digest, key_length, key_out)) {
        return SCEE_ERROR_PBKDF2;
    }

    return SCEE_OK;
}

// Encrypt/Decrypt String.
size_t crypt_string_get_length(size_t current_size, int operation) {
    if (operation == SCEE_CRYPT_ENCRYPT) {
        return b64_get_length(current_size + SCEE_SALT_LENGTH + SCEE_NONCE_LENGTH + SCEE_TAG_LENGTH, SCEE_B64_ENCODE);
    } else {
        size_t temp_length = b64_get_length(current_size, SCEE_B64_DECODE);
        return temp_length - SCEE_SALT_LENGTH - SCEE_NONCE_LENGTH - SCEE_TAG_LENGTH + 1;
    }
}
int encrypt_string(const char* plaintext, size_t plaintext_length, const char* password, size_t password_length, char* ciphertext_out) {
    // Generate a 128-bit salt using a CSPRNG.
    uint8_t salt[SCEE_SALT_LENGTH];
    if (!RAND_bytes(salt, SCEE_SALT_LENGTH)) { return SCEE_ERROR_RAND; }

    // Use PBKDF2 to derive a key.
    uint8_t key[SCEE_KEY_LENGTH];
    int r = pbkdf2(password, password_length, salt, SCEE_SALT_LENGTH, SCEE_PBKDF2_ITERATIONS, SCEE_PBKDF2_HASH(), key, SCEE_KEY_LENGTH);
    if (r != SCEE_OK) { return r; }

    // Encrypt and prepend salt.
    size_t ciphertext_and_nonce_length = plaintext_length + SCEE_NONCE_LENGTH + SCEE_TAG_LENGTH;
    uint8_t ciphertext_and_nonce[ciphertext_and_nonce_length];
    r = encrypt(plaintext, plaintext_length, key, ciphertext_and_nonce);
    if (r != SCEE_OK) { return r; }

    size_t ciphertext_and_nonce_and_salt_length = ciphertext_and_nonce_length + SCEE_SALT_LENGTH;
    uint8_t ciphertext_and_nonce_and_salt[ciphertext_and_nonce_and_salt_length];
    memcpy(ciphertext_and_nonce_and_salt, salt, SCEE_SALT_LENGTH);
    memcpy(ciphertext_and_nonce_and_salt + SCEE_SALT_LENGTH, ciphertext_and_nonce, ciphertext_and_nonce_length);

    return b64_encode(ciphertext_and_nonce_and_salt, ciphertext_and_nonce_and_salt_length, ciphertext_out);
}
int decrypt_string(const char* base64_ciphertext_and_nonce_and_salt, size_t base64_length, const char* password, size_t password_length, char* plaintext_out, size_t* plaintext_length_out) {
    // Decode the base64.
    size_t actual_size;
    size_t max_size = b64_get_length(base64_length, SCEE_B64_DECODE);
    uint8_t ciphertext_and_nonce_and_salt[max_size];
    int r = b64_decode(base64_ciphertext_and_nonce_and_salt, base64_length, ciphertext_and_nonce_and_salt, &actual_size);
    if (r != SCEE_OK) { return r; }

    // Retrieve the salt and ciphertext.
    size_t ciphertext_and_nonce_length = actual_size - SCEE_SALT_LENGTH;
    uint8_t salt[SCEE_SALT_LENGTH];
    uint8_t ciphertext_and_nonce[ciphertext_and_nonce_length];
    memcpy(salt, ciphertext_and_nonce_and_salt, SCEE_SALT_LENGTH);
    memcpy(ciphertext_and_nonce, ciphertext_and_nonce_and_salt + SCEE_SALT_LENGTH, ciphertext_and_nonce_length);

    // Use PBKDF2 to derive the key.
    uint8_t key[SCEE_KEY_LENGTH];
    r = pbkdf2(password, password_length, salt, SCEE_SALT_LENGTH, SCEE_PBKDF2_ITERATIONS, SCEE_PBKDF2_HASH(), key, SCEE_KEY_LENGTH);
    if (r != SCEE_OK) { return r; }

    *plaintext_length_out = ciphertext_and_nonce_length - SCEE_NONCE_LENGTH - SCEE_TAG_LENGTH;
    plaintext_out[*plaintext_length_out] = '\0';

    // Decrypt and return result.
    return decrypt(ciphertext_and_nonce, ciphertext_and_nonce_length, key, plaintext_out);
}

// Encrypt/Decrypt.
int encrypt(const uint8_t* plaintext, size_t plaintext_length, const uint8_t* key, uint8_t* ciphertext_and_nonce) {
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

    if (!EVP_EncryptFinal_ex(ctx, ciphertext + temp_length, &temp_length)) {
        EVP_CIPHER_CTX_free(ctx);
        return SCEE_ERROR_CRYPT_FINAL;
    }

    uint8_t tag[SCEE_TAG_LENGTH];
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, SCEE_TAG_LENGTH, tag)) {
        EVP_CIPHER_CTX_free(ctx);
        return SCEE_ERROR_CRYPT_TAG;
    }

    EVP_CIPHER_CTX_free(ctx);

    memcpy(ciphertext_and_nonce, nonce, SCEE_NONCE_LENGTH);
    memcpy(ciphertext_and_nonce + SCEE_NONCE_LENGTH, ciphertext, plaintext_length);
    memcpy(ciphertext_and_nonce + SCEE_NONCE_LENGTH + plaintext_length, tag, SCEE_TAG_LENGTH);

    return SCEE_OK;
}

int decrypt(const uint8_t* ciphertext_and_nonce, size_t ciphertext_and_nonce_length, const uint8_t* key, uint8_t* plaintext) {
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

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, SCEE_TAG_LENGTH, tag)) {
        EVP_CIPHER_CTX_free(ctx);
        return SCEE_ERROR_CRYPT_TAG;
    }

    if (EVP_DecryptFinal_ex(ctx, plaintext + temp_length, &temp_length) < 1) {
        EVP_CIPHER_CTX_free(ctx);
        return SCEE_ERROR_CRYPT_TAG_INVALID;
    }

    EVP_CIPHER_CTX_free(ctx);

    return SCEE_OK;
}
