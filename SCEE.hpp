#ifndef __SCEE_HPP
#define __SCEE_HPP

#include <string>
#include <vector>
#include "SCEE.h"

class SCEE {
public:
    static int encrypt_string(std::string plaintext, std::string password, std::string& ciphertext);
    static int decrypt_string(std::string ciphertext, std::string password, std::string& plaintext);
    static int encrypt(std::vector<uint8_t> plaintext, std::vector<uint8_t> key, std::vector<uint8_t>& ciphertext);
    static int decrypt(std::vector<uint8_t> ciphertext, std::vector<uint8_t> key, std::vector<uint8_t>& plaintext);

private:
    SCEE() {}
};

#endif
