#include "crypto/key_generator.h"
#include "crypto/key_validator.h"
#include "crypto/rsa_cipher.h"
#include "crypto/xor_cipher.h"

#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

#include <openssl/evp.h>

static std::string toBase64(const std::vector<uint8_t>& data) {
    std::vector<unsigned char> out(((data.size() + 2) / 3) * 4 + 1);
    int len = EVP_EncodeBlock(out.data(), data.data(), static_cast<int>(data.size()));
    return std::string(reinterpret_cast<char*>(out.data()), static_cast<size_t>(len));
}

static void printHex(const std::vector<uint8_t>& data, size_t cols = 18) {
    const std::string indent(19, ' ');
    for (size_t i = 0; i < data.size(); ++i) {
        if (i > 0 && i % cols == 0) std::cout << "\n" << indent;
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(data[i]);
        if (i + 1 < data.size()) std::cout << " ";
    }
    std::cout << std::dec << "\n";
}

static void writePem(const std::string& path, const std::string& pem) {
    FILE* f = fopen(path.c_str(), "w");
    if (!f) throw std::runtime_error("Cannot write " + path);
    fwrite(pem.c_str(), 1, pem.size(), f);
    fclose(f);
}

int main() {
    // 5.2 XOR
    {
        std::cout << "---- XOR-шифр ----\n";
        const std::string plainStr = "Privet, mir! Eto test shifrovaniya XOR.";
        std::vector<uint8_t> plain(plainStr.begin(), plainStr.end());

        std::string key = generateXorKey(8);
        std::cout << "Исходный текст : " << plainStr << "\n";
        std::cout << "Сгенерированный ключ (8 символов): " << key << "\n";

        auto enc = xorEncrypt(plain, key);
        std::cout << "Зашифровано (hex): ";
        printHex(enc);

        std::cout << "Зашифровано (Base64): " << toBase64(enc) << "\n";

        auto dec = xorDecrypt(enc, key);
        std::string decStr(dec.begin(), dec.end());
        std::cout << "Расшифровано    : " << decStr << "\n";
        std::cout << "Совпадает с исходным: " << (dec == plain ? "ДА" : "НЕТ") << "\n";
        std::cout << "Длина зашифрованных данных (" << enc.size()
                  << " байт) совпадает с длиной исходного текста: "
                  << (enc.size() == plain.size() ? "ДА" : "НЕТ") << "\n\n";
    }

    // 5.3 RSA
    {
        std::cout << "---- RSA-шифр ----\n";
        std::cout << "Генерация пары ключей RSA-2048...\n";

        auto kp = generateRsaKeyPair(2048);

        const std::string tmpDir = std::filesystem::temp_directory_path().string();
        const std::string pubPath  = tmpDir + "/demo_public.pem";
        const std::string privPath = tmpDir + "/demo_private.pem";

        writePem(pubPath,  kp.publicKey);
        writePem(privPath, kp.privateKey);
        std::cout << "Ключи сохранены: demo_public.pem, demo_private.pem\n";

        auto val = validatePrivateKey(privPath);
        std::cout << "Проверка приватного ключа: " << val.message << "\n";

        const std::string plainStr = "Secret message 12345";
        std::vector<uint8_t> plain(plainStr.begin(), plainStr.end());
        std::cout << "Исходный текст : " << plainStr << "\n";

        auto enc = rsaEncrypt(plain, pubPath);
        std::cout << "Размер шифротекста: " << enc.size() << " байт\n";

        const size_t show = std::min<size_t>(32, enc.size());
        std::cout << "Зашифровано (hex, первые 32 байта из " << enc.size() << "):\n  ";
        for (size_t i = 0; i < show; ++i) {
            if (i == 16) std::cout << "\n  ";
            std::cout << std::hex << std::setw(2) << std::setfill('0')
                      << static_cast<int>(enc[i]);
            if (i + 1 < show) std::cout << " ";
        }
        std::cout << std::dec << " ...\n";

        auto dec = rsaDecrypt(enc, privPath);
        std::string decStr(dec.begin(), dec.end());
        std::cout << "Расшифровано    : " << decStr << "\n";
        std::cout << "Совпадает с исходным: " << (dec == plain ? "ДА" : "НЕТ") << "\n\n";

        std::remove(pubPath.c_str());
        std::remove(privPath.c_str());
    }

    // 5.4 Некорректный ключ
    {
        std::cout << "---- Проверка некорректного ключа ----\n";
        auto res = validatePrivateKey("/nonexistent/path/private.pem");
        std::cout << "Результат: " << res.message
                  << " (valid=" << (res.valid ? 1 : 0) << ")\n";
    }

    return 0;
}
