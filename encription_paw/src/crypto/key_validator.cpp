#include "key_validator.h"

#include <openssl/evp.h>
#include <openssl/pem.h>

KeyValidationResult validatePrivateKey(const std::string& privKeyPath) {
    FILE* fp = fopen(privKeyPath.c_str(), "r");
    if (!fp) {
        return {false, "Ошибка: не удалось открыть файл", 0};
    }

    EVP_PKEY* pkey = PEM_read_PrivateKey(fp, nullptr, nullptr, nullptr);
    fclose(fp);

    if (!pkey) {
        return {false, "Ошибка: некорректный или повреждённый PEM файл", 0};
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    int check = -1;
    if (ctx) {
        check = EVP_PKEY_check(ctx);
        EVP_PKEY_CTX_free(ctx);
    }

    if (check <= 0) {
        EVP_PKEY_free(pkey);
        return {false, "Ошибка: ключ не прошёл проверку", 0};
    }

    int bits = EVP_PKEY_get_bits(pkey);
    EVP_PKEY_free(pkey);

    return {true, "RSA-" + std::to_string(bits) + ", ключ корректен", bits};
}
