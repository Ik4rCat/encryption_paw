#pragma once

#include <cstdint>
#include <string>
#include <vector>

std::vector<uint8_t> rsaEncrypt(const std::vector<uint8_t>& data, const std::string& pubKeyPath);
std::vector<uint8_t> rsaDecrypt(const std::vector<uint8_t>& data, const std::string& privKeyPath);
