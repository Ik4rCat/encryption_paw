#include <algorithm>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <vector>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

using namespace std;

void xorEncryptDecrypt(const string &inputFile, const string &outputFile, const string &key)
{
    ifstream in(inputFile, ios::binary);
    ofstream out(outputFile, ios::binary);

    if (!in || !out)
    {
        cout << "Failed to open file.\n";
        return;
    }

    char ch;

    for (int i = 0; in.get(ch); i++)
    {
        char encrypted = ch ^ key[i % key.size()];
        out.put(encrypted);
    }

    in.close();
    out.close();
}

static void write_u64_be(ostream &out, uint64_t v)
{
    for (int i = 7; i >= 0; --i)
        out.put(static_cast<char>((v >> (i * 8)) & 0xff));
}

static bool read_u64_be(istream &in, uint64_t &v)
{
    v = 0;
    for (int i = 0; i < 8; ++i)
    {
        char c;
        if (!in.get(c))
            return false;
        v = (v << 8) | static_cast<unsigned char>(c);
    }
    return true;
}

static int rsa_oaep_sha256_max_plaintext(EVP_PKEY *pkey)
{
    int rsa_size = EVP_PKEY_get_size(pkey);
    if (rsa_size <= 0)
        return -1;
    return rsa_size - 2 * static_cast<int>(SHA256_DIGEST_LENGTH) - 2;
}

bool rsaEncryptDecryptFile(const string &inputFile, const string &outputFile,
                           const string &keyPath, bool encrypt)
{
    FILE *key_fp = fopen(keyPath.c_str(), "r");
    if (!key_fp)
    {
        cerr << "Failed to open key file.\n";
        return false;
    }

    EVP_PKEY *pkey = encrypt ? PEM_read_PUBKEY(key_fp, nullptr, nullptr, nullptr)
                               : PEM_read_PrivateKey(key_fp, nullptr, nullptr, nullptr);
    fclose(key_fp);

    if (!pkey)
    {
        cerr << "Invalid or corrupted PEM key.\n";
        return false;
    }

    const int rsa_size = EVP_PKEY_get_size(pkey);
    const int max_plain = rsa_oaep_sha256_max_plaintext(pkey);
    if (max_plain <= 0)
    {
        cerr << "Invalid RSA key size.\n";
        EVP_PKEY_free(pkey);
        return false;
    }

    ifstream fin(inputFile, ios::binary);
    ofstream fout(outputFile, ios::binary);
    if (!fin || !fout)
    {
        cerr << "Failed to open input/output file.\n";
        EVP_PKEY_free(pkey);
        return false;
    }

    if (encrypt)
    {
        fin.seekg(0, ios::end);
        const streampos end_pos = fin.tellg();
        if (end_pos < 0)
        {
            cerr << "Could not determine file size.\n";
            EVP_PKEY_free(pkey);
            return false;
        }
        const uint64_t plain_len = static_cast<uint64_t>(end_pos);
        fin.seekg(0, ios::beg);

        write_u64_be(fout, plain_len);

        vector<unsigned char> inbuf(static_cast<size_t>(max_plain));
        vector<unsigned char> outbuf(static_cast<size_t>(rsa_size));

        uint64_t total_read = 0;
        while (total_read < plain_len)
        {
            const size_t chunk =
                static_cast<size_t>(min<uint64_t>(max_plain, plain_len - total_read));
            fin.read(reinterpret_cast<char *>(inbuf.data()), static_cast<streamsize>(chunk));
            const streamsize got = fin.gcount();
            if (got <= 0)
                break;

            EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, nullptr);
            if (!ctx || EVP_PKEY_encrypt_init(ctx) <= 0 ||
                EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0 ||
                EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()) <= 0 ||
                EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) <= 0)
            {
                cerr << "RSA encryption initialization failed.\n";
                EVP_PKEY_CTX_free(ctx);
                EVP_PKEY_free(pkey);
                return false;
            }

            size_t outlen = outbuf.size();
            if (EVP_PKEY_encrypt(ctx, outbuf.data(), &outlen, inbuf.data(),
                                 static_cast<size_t>(got)) <= 0)
            {
                cerr << "RSA encryption failed.\n";
                EVP_PKEY_CTX_free(ctx);
                EVP_PKEY_free(pkey);
                return false;
            }
            EVP_PKEY_CTX_free(ctx);

            fout.write(reinterpret_cast<const char *>(outbuf.data()),
                       static_cast<streamsize>(outlen));
            total_read += static_cast<uint64_t>(got);
        }

        if (total_read != plain_len)
        {
            cerr << "Read less data than expected.\n";
            EVP_PKEY_free(pkey);
            return false;
        }
    }
    else
    {
        uint64_t plain_len = 0;
        if (!read_u64_be(fin, plain_len))
        {
            cerr << "File too short or corrupted (header).\n";
            EVP_PKEY_free(pkey);
            return false;
        }

        uint64_t total_written = 0;
        vector<unsigned char> inbuf(static_cast<size_t>(rsa_size));

        while (total_written < plain_len)
        {
            fin.read(reinterpret_cast<char *>(inbuf.data()), rsa_size);
            if (fin.gcount() != rsa_size)
            {
                cerr << "Incomplete ciphertext block.\n";
                EVP_PKEY_free(pkey);
                return false;
            }

            EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, nullptr);
            if (!ctx || EVP_PKEY_decrypt_init(ctx) <= 0 ||
                EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0 ||
                EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()) <= 0 ||
                EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) <= 0)
            {
                cerr << "RSA decryption initialization failed.\n";
                EVP_PKEY_CTX_free(ctx);
                EVP_PKEY_free(pkey);
                return false;
            }

            size_t pt_len = 0;
            if (EVP_PKEY_decrypt(ctx, nullptr, &pt_len, inbuf.data(), inbuf.size()) <= 0)
            {
                cerr << "RSA decryption failed (size query).\n";
                EVP_PKEY_CTX_free(ctx);
                EVP_PKEY_free(pkey);
                return false;
            }

            vector<unsigned char> pt(pt_len);
            if (EVP_PKEY_decrypt(ctx, pt.data(), &pt_len, inbuf.data(), inbuf.size()) <= 0)
            {
                cerr << "RSA decryption failed.\n";
                EVP_PKEY_CTX_free(ctx);
                EVP_PKEY_free(pkey);
                return false;
            }
            EVP_PKEY_CTX_free(ctx);

            const uint64_t need = plain_len - total_written;
            const size_t to_write = static_cast<size_t>(min<uint64_t>(need, pt_len));
            fout.write(reinterpret_cast<const char *>(pt.data()),
                       static_cast<streamsize>(to_write));
            total_written += to_write;
        }
    }

    EVP_PKEY_free(pkey);
    return true;
}

void XOR(string inF, string outF)
{
    string key;

    cout << "Input file: ";
    cin >> inF;

    cout << "Output file: ";
    cin >> outF;

    cout << "Key: ";
    cin >> key;

    xorEncryptDecrypt(inF, outF, key);
}

void rsaMenu(bool encrypt)
{
    string inF, outF, keyPath;

    cout << "Input file: ";
    cin >> inF;
    cout << "Output file: ";
    cin >> outF;
    cout << (encrypt ? "Public key file (PEM): " : "Private key file (PEM): ");
    cin >> keyPath;

    if (rsaEncryptDecryptFile(inF, outF, keyPath, encrypt))
        cout << "Done.\n";
    else
        cout << "Operation failed.\n";
}

int main()
{
    while (true)
    {
        int choice;

        cout << "\n1 - XOR Encryption\n";
        cout << "2 - XOR Decryption\n";
        cout << "3 - RSA Encryption\n";
        cout << "4 - RSA Decryption\n";
        cout << "---------------------\n";
        cout << "0 - exit\n";
        cout << "choice: ";
        cin >> choice;

        string inFile, outFile;

        switch (choice)
        {
        case 0:
            return 0;
        case 1:
        case 2:
            XOR(inFile, outFile);
            break;
        case 3:
            rsaMenu(true);
            break;
        case 4:
            rsaMenu(false);
            break;
        default:
            cout << "[!] Invalid choice, try again\n";
            break;
        }
    }
}
