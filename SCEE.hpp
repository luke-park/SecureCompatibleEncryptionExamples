#ifndef __SCEE_HPP
#define __SCEE_HPP

#include <string>
#include <vector>
#include "SCEE.h"

class SCEE {
public:
    static int encrypt_str(std::string plaintext, std::string password, std::string& ciphertext);
    static int decrypt_str(std::string ciphertext, std::string password, std::string& plaintext);
    static int encrypt_vec(std::vector<uint8_t> plaintext, std::vector<uint8_t> key, std::vector<uint8_t>& ciphertext);
    static int decrypt_vec(std::vector<uint8_t> ciphertext, std::vector<uint8_t> key, std::vector<uint8_t>& plaintext);

private:
    SCEE() {}
};

#endif
