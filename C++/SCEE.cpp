#include "SCEE_cpp.h"

using namespace std;

int SCEE::encrypt_string(string plaintext, string password, string& ciphertext) {
    const char* pt = plaintext.c_str();
    const char* pass = password.c_str();

    size_t ct_length = scee_crypt_string_get_length(strlen(pt), SCEE_CRYPT_ENCRYPT);
    unsigned char ct[ct_length];

    int r = scee_encrypt_string((unsigned char*)pt, strlen(pt), (unsigned char*)pass, strlen(pass), ct);
    if (r != SCEE_OK) { return r; }

    ciphertext = string((char*)ct);
    return SCEE_OK;
}
int SCEE::decrypt_string(string ciphertext, string password, string& plaintext) {
    const char* ct = ciphertext.c_str();
    const char* pass = password.c_str();

    size_t t_length;
    size_t pt_length = scee_crypt_string_get_length(strlen(ct), SCEE_CRYPT_DECRYPT);
    unsigned char pt[pt_length];

    int r = scee_decrypt_string((unsigned char*)ct, strlen(ct), (unsigned char*)pass, strlen(pass), pt, &t_length);
    if (r != SCEE_OK) { return r; }

    plaintext = string((char*)pt);
    return SCEE_OK;
}
int SCEE::encrypt(vector<uint8_t> plaintext, vector<uint8_t> key, std::vector<uint8_t>& ciphertext) {
    uint8_t* pt = plaintext.data();
    uint8_t* k = key.data();
    size_t pt_length = plaintext.size();

    size_t ct_length = pt_length + SCEE_NONCE_LENGTH + SCEE_TAG_LENGTH;
    uint8_t ct[ct_length];
    int r = scee_encrypt(pt, pt_length, k, ct);
    if (r != SCEE_OK) { return r; }

    ciphertext = vector<uint8_t>(ct_length);
    ciphertext.assign(ct, ct + ct_length);
    return SCEE_OK;
}
int SCEE::decrypt(vector<uint8_t> ciphertext, vector<uint8_t> key, std::vector<uint8_t>& plaintext) {
    uint8_t* ct = ciphertext.data();
    uint8_t* k = key.data();
    size_t ct_length = ciphertext.size();

    size_t pt_length = ct_length - SCEE_NONCE_LENGTH - SCEE_TAG_LENGTH;
    uint8_t pt[pt_length];
    int r = scee_decrypt(ct, ct_length, k, pt);
    if (r != SCEE_OK) { return r; }

    plaintext = vector<uint8_t>(pt_length);
    plaintext.assign(pt, pt + pt_length);
    return SCEE_OK;
}
