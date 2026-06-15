#pragma once

#include <string>

struct RsaKeyPair {
    std::string publicKey;
    std::string privateKey;
};

RsaKeyPair generateRsaKeyPair(int bits = 2048);
std::string generateXorKey(int length = 32);
