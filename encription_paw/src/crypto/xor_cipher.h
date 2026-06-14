#pragma once

#include <cstdint>
#include <string>
#include <vector>

std::vector<uint8_t> xorEncrypt(const std::vector<uint8_t>& data, const std::string& key);
std::vector<uint8_t> xorDecrypt(const std::vector<uint8_t>& data, const std::string& key);
