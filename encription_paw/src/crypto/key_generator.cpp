#include "key_generator.h"

#include <stdexcept>
#include <vector>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

RsaKeyPair generateRsaKeyPair(int bits) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx) {
        throw std::runtime_error("Ошибка создания контекста генерации ключа");
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Ошибка инициализации генерации RSA ключа");
    }

    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Ошибка генерации RSA ключа");
    }
    EVP_PKEY_CTX_free(ctx);

    auto bioToString = [](BIO* bio) -> std::string {
        BUF_MEM* mem = nullptr;
        BIO_get_mem_ptr(bio, &mem);
        std::string s(mem->data, mem->length);
        BIO_free(bio);
        return s;
    };

    BIO* pubBio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(pubBio, pkey);
    std::string publicKey = bioToString(pubBio);

    BIO* privBio = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(privBio, pkey, nullptr, nullptr, 0, nullptr, nullptr);
    std::string privateKey = bioToString(privBio);

    EVP_PKEY_free(pkey);
    return {publicKey, privateKey};
}

std::string generateXorKey(int length) {
    static const char charset[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+";
    constexpr int charsetLen = static_cast<int>(sizeof(charset)) - 1;

    std::vector<uint8_t> rand(static_cast<size_t>(length));
    RAND_bytes(rand.data(), length);

    std::string result(static_cast<size_t>(length), '\0');
    for (int i = 0; i < length; ++i) {
        result[static_cast<size_t>(i)] = charset[rand[static_cast<size_t>(i)] % charsetLen];
    }
    return result;
}
