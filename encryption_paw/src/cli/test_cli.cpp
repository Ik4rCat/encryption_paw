#include "crypto/key_validator.h"
#include "crypto/rsa_cipher.h"
#include "crypto/xor_cipher.h"
#include "io/buffer_sink.h"
#include "io/buffer_source.h"
#include "io/file_sink.h"
#include "io/file_source.h"

#include <cstdio>
#include <filesystem>
#include <iostream>
#include <string>

#ifndef LEGACY_PAW_DIR
#define LEGACY_PAW_DIR "../../legacy_paw"
#endif

static int passed = 0;
static int failed = 0;

static void check(const std::string& name, bool ok) {
    if (ok) {
        std::cout << "[OK]   " << name << "\n";
        ++passed;
    } else {
        std::cout << "[FAIL] " << name << "\n";
        ++failed;
    }
}

int main() {
    std::cout << "=== test_cli ===\n\n";

    {
        std::cout << "-- XOR --\n";
        std::vector<uint8_t> plain = {'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd'};
        std::string key = "secret";
        auto enc = xorEncrypt(plain, key);
        auto dec = xorDecrypt(enc, key);
        check("XOR round-trip", dec == plain);

        auto enc2 = xorEncrypt(plain, key);
        check("XOR encrypt is deterministic", enc == enc2);
    }

    {
        std::cout << "\n-- RSA --\n";
        std::string pubKey = std::string(LEGACY_PAW_DIR) + "/public.pem";
        std::string privKey = std::string(LEGACY_PAW_DIR) + "/private.pem";

        std::vector<uint8_t> plain = {'R', 'S', 'A', ' ', 't', 'e', 's', 't', ' ', '1', '2', '3'};
        try {
            auto enc = rsaEncrypt(plain, pubKey);
            check("RSA encrypt produced output", enc.size() > 8);
            auto dec = rsaDecrypt(enc, privKey);
            check("RSA round-trip", dec == plain);
        } catch (const std::exception& ex) {
            std::cerr << "RSA exception: " << ex.what() << "\n";
            check("RSA round-trip", false);
        }
    }

    {
        std::cout << "\n-- Key validation --\n";
        std::string privKey = std::string(LEGACY_PAW_DIR) + "/private.pem";
        auto res = validatePrivateKey(privKey);
        check("Valid private key", res.valid && res.bits > 0);

        auto bad = validatePrivateKey("/nonexistent/path/private.pem");
        check("Invalid path returns !valid", !bad.valid);
    }

    {
        std::cout << "\n-- FileSource / FileSink --\n";
        std::string tmpPath = std::filesystem::temp_directory_path().string() + "/test_cli_tmp.bin";
        std::vector<uint8_t> data = {0x01, 0x02, 0x03, 0xAA, 0xBB, 0xFF};

        try {
            FileSink sink(tmpPath);
            sink.write(data);

            FileSource src(tmpPath);
            auto readBack = src.readAll();
            check("FileSource/FileSink round-trip", readBack == data);

            std::remove(tmpPath.c_str());
        } catch (const std::exception& ex) {
            std::cerr << "IO exception: " << ex.what() << "\n";
            check("FileSource/FileSink round-trip", false);
        }
    }

    {
        std::cout << "\n-- BufferSource / BufferSink --\n";
        std::string text = "hello buffer";
        BufferSource src(text);
        auto data = src.readAll();
        BufferSink sink;
        sink.write(data);
        auto got = sink.getData();
        check("BufferSource/BufferSink round-trip",
              std::string(got.begin(), got.end()) == text);
    }

    std::cout << "\n=== " << passed << " passed, " << failed << " failed ===\n";
    return failed == 0 ? 0 : 1;
}
