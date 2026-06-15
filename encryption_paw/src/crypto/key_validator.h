#pragma once

#include <string>

struct KeyValidationResult {
    bool valid;
    std::string message;
    int bits;
};

KeyValidationResult validatePrivateKey(const std::string& privKeyPath);
