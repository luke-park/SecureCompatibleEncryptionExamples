#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define SCEE_ALGORITHM EVP_aes_128_gcm
#define SCEE_KEY_LENGTH 16
#define SCEE_TAG_LENGTH 16
#define SCEE_NONCE_LENGTH 12
#define SCEE_SALT_LENGTH 16
#define SCEE_PBKDF2_ITERATIONS 32767
#define SCEE_PBKDF2_HASH EVP_sha256

#define SCEE_OK 1
#define SCEE_ERROR_RAND 0
#define SCEE_ERROR_CTX_NEW 2
#define SCEE_ERROR_CTX_ALGORITHM 3
#define SCEE_ERROR_CTX_KEY_NONCE 4
#define SCEE_ERROR_CRYPT 5
#define SCEE_ERROR_CRYPT_FINAL 6
#define SCEE_ERROR_CRYPT_TAG 7
#define SCEE_ERROR_CRYPT_TAG_INVALID 8
#define SCEE_ERROR_B64 9
#define SCEE_ERROR_PBKDF2 10

#define SCEE_B64_ENCODE 0
#define SCEE_B64_DECODE 1

#define SCEE_CRYPT_ENCRYPT 0
#define SCEE_CRYPT_DECRYPT 1

// Base64.
size_t b64_get_length(size_t current_size, int operation);
int b64_encode(const uint8_t* bytes, size_t length, char* str);
int b64_decode(const char* str, size_t length, uint8_t* bytes, size_t* decode_size_out);

// PBKDF2.
int pbkdf2(const char* password, size_t password_length, const uint8_t* salt, size_t salt_length, int iterations, const EVP_MD* digest, uint8_t* key_out, size_t key_length);

// Encrypt/Decrypt String.
size_t crypt_string_get_length(size_t current_size, int operation);
int encrypt_string(const char* plaintext, size_t plaintext_length, const char* password, size_t password_length, char* ciphertext_out);
int decrypt_string(const char* base64_ciphertext_and_nonce_and_salt, size_t base64_length, const char* password, size_t password_length, char* plaintext_out, size_t* plaintext_length_out);

// Encrypt/Decrypt.
int encrypt(const uint8_t* plaintext, size_t plaintext_length, const uint8_t* key, uint8_t* ciphertext_and_nonce);
int decrypt(const uint8_t* ciphertext_and_nonce, size_t ciphertext_and_nonce_length, const uint8_t* key, uint8_t* plaintext);
