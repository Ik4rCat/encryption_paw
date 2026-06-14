#include "rsa_cipher.h"

#include <algorithm>
#include <stdexcept>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

static int rsaMaxPlaintext(EVP_PKEY* pkey) {
    int rsa_size = EVP_PKEY_get_size(pkey);
    if (rsa_size <= 0) {
        return -1;
    }
    return rsa_size - 2 * static_cast<int>(SHA256_DIGEST_LENGTH) - 2;
}

static void writeU64Be(std::vector<uint8_t>& out, uint64_t v) {
    for (int i = 7; i >= 0; --i) {
        out.push_back(static_cast<uint8_t>((v >> (i * 8)) & 0xff));
    }
}

static uint64_t readU64Be(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v = (v << 8) | p[i];
    }
    return v;
}

std::vector<uint8_t> rsaEncrypt(const std::vector<uint8_t>& data, const std::string& pubKeyPath) {
    FILE* fp = fopen(pubKeyPath.c_str(), "r");
    if (!fp) {
        throw std::runtime_error("Cannot open public key: " + pubKeyPath);
    }
    EVP_PKEY* pkey = PEM_read_PUBKEY(fp, nullptr, nullptr, nullptr);
    fclose(fp);

    if (!pkey) {
        throw std::runtime_error("Invalid or corrupted public key PEM");
    }

    const int rsa_size = EVP_PKEY_get_size(pkey);
    const int max_plain = rsaMaxPlaintext(pkey);
    if (max_plain <= 0) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Invalid RSA key size");
    }

    std::vector<uint8_t> result;
    writeU64Be(result, static_cast<uint64_t>(data.size()));

    std::vector<uint8_t> outbuf(static_cast<size_t>(rsa_size));
    size_t offset = 0;

    while (offset < data.size()) {
        size_t chunk = std::min<size_t>(static_cast<size_t>(max_plain), data.size() - offset);

        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
        if (!ctx || EVP_PKEY_encrypt_init(ctx) <= 0 ||
            EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0 ||
            EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()) <= 0 ||
            EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) <= 0) {
            if (ctx) { EVP_PKEY_CTX_free(ctx); }
            EVP_PKEY_free(pkey);
            throw std::runtime_error("RSA encrypt init failed");
        }

        size_t outlen = outbuf.size();
        if (EVP_PKEY_encrypt(ctx, outbuf.data(), &outlen, data.data() + offset, chunk) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(pkey);
            throw std::runtime_error("RSA encrypt failed");
        }
        EVP_PKEY_CTX_free(ctx);

        result.insert(result.end(), outbuf.begin(), outbuf.begin() + static_cast<ptrdiff_t>(outlen));
        offset += chunk;
    }

    EVP_PKEY_free(pkey);
    return result;
}

std::vector<uint8_t> rsaDecrypt(const std::vector<uint8_t>& data, const std::string& privKeyPath) {
    FILE* fp = fopen(privKeyPath.c_str(), "r");
    if (!fp) {
        throw std::runtime_error("Cannot open private key: " + privKeyPath);
    }
    EVP_PKEY* pkey = PEM_read_PrivateKey(fp, nullptr, nullptr, nullptr);
    fclose(fp);

    if (!pkey) {
        throw std::runtime_error("Invalid or corrupted private key PEM");
    }

    const int rsa_size = EVP_PKEY_get_size(pkey);
    if (rsa_size <= 0) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Invalid RSA key size");
    }

    if (data.size() < 8) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Input too short (missing header)");
    }

    const uint64_t plain_len = readU64Be(data.data());
    std::vector<uint8_t> result;
    result.reserve(static_cast<size_t>(plain_len));

    size_t offset = 8;
    while (result.size() < static_cast<size_t>(plain_len)) {
        if (offset + static_cast<size_t>(rsa_size) > data.size()) {
            EVP_PKEY_free(pkey);
            throw std::runtime_error("Incomplete ciphertext block");
        }

        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
        if (!ctx || EVP_PKEY_decrypt_init(ctx) <= 0 ||
            EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0 ||
            EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()) <= 0 ||
            EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) <= 0) {
            if (ctx) { EVP_PKEY_CTX_free(ctx); }
            EVP_PKEY_free(pkey);
            throw std::runtime_error("RSA decrypt init failed");
        }

        const uint8_t* block = data.data() + offset;

        size_t pt_len = 0;
        if (EVP_PKEY_decrypt(ctx, nullptr, &pt_len, block, static_cast<size_t>(rsa_size)) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(pkey);
            throw std::runtime_error("RSA decrypt size query failed");
        }

        std::vector<uint8_t> pt(pt_len);
        if (EVP_PKEY_decrypt(ctx, pt.data(), &pt_len, block, static_cast<size_t>(rsa_size)) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(pkey);
            throw std::runtime_error("RSA decrypt failed");
        }
        EVP_PKEY_CTX_free(ctx);

        size_t need = static_cast<size_t>(plain_len) - result.size();
        size_t to_write = std::min(need, pt_len);
        result.insert(result.end(), pt.begin(), pt.begin() + static_cast<ptrdiff_t>(to_write));
        offset += static_cast<size_t>(rsa_size);
    }

    EVP_PKEY_free(pkey);
    return result;
}
