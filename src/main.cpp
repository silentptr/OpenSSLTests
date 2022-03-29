#include "openssltests/aestest.h"

#include <memory>
#include <cstdio>
#include <sstream>
#include <openssl/err.h>
#include <openssl/rand.h>

int main()
{
    ERR_print_errors_fp(stderr);
    std::unique_ptr<std::uint8_t[]> key = std::make_unique<std::uint8_t[]>(32);
    std::unique_ptr<std::uint8_t[]> iv = std::make_unique<std::uint8_t[]>(16);
    RAND_bytes(key.get(), 32);
    RAND_bytes(iv.get(), 16);
    OSSLTests::AES256Cipher cipher(OSSLTests::CipherType::AES_256_GCM, key.get());

    std::string plainTextString = "The lazy fox jumped over the whatever.";
    std::unique_ptr<std::uint8_t[]> cipherBuffer = std::make_unique<std::uint8_t[]>(plainTextString.length() * 2);
    std::unique_ptr<std::uint8_t[]> plainBuffer = std::make_unique<std::uint8_t[]>(plainTextString.length() * 2);
    std::uint32_t cipherLength, plainLength;

    std::printf("Plain text: %s\n", plainTextString.c_str());

    try
    {
        cipherLength = cipher.Encrypt(cipherBuffer.get(), plainTextString.length() * 2,
                                    (const std::uint8_t*)plainTextString.c_str(), plainTextString.length(),
                                    iv.get());
    }
    catch (const std::string& err)
    {
        std::printf("Error encrypting: %s\n", err.c_str());
        return 1;
    }

    std::string cipherText;

    for (std::size_t i = 0; i < cipherLength; ++i)
    {
        cipherText += cipherBuffer.get()[i];
    }

    std::printf("Cipher text: ");

    for (std::size_t i = 0; i < cipherLength; ++i)
    {
        std::printf("%02x ", cipherBuffer.get()[i]);
    }

    std::printf("\n");

    try
    {
        plainLength = cipher.Decrypt(plainBuffer.get(), plainTextString.length() * 2,
                                    cipherBuffer.get(), cipherLength,
                                    iv.get());
    }
    catch (const std::string& err)
    {
        std::printf("Error decrypting: %s\n", err.c_str());
        return 1;
    }

    std::string plainText;

    for (std::size_t i = 0; i < plainLength; ++i)
    {
        plainText += plainBuffer.get()[i];
    }

    std::printf("Plain text: %s\n", plainText.c_str());
    return 0;
}