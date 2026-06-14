#include "xor_cipher.h"

#include <stdexcept>

std::vector<uint8_t> xorEncrypt(const std::vector<uint8_t>& data, const std::string& key) {
    if (key.empty()) {
        throw std::invalid_argument("XOR key must not be empty");
    }
    std::vector<uint8_t> result(data.size());
    for (size_t i = 0; i < data.size(); ++i) {
        result[i] = data[i] ^ static_cast<uint8_t>(key[i % key.size()]);
    }
    return result;
}

std::vector<uint8_t> xorDecrypt(const std::vector<uint8_t>& data, const std::string& key) {
    return xorEncrypt(data, key);
}
