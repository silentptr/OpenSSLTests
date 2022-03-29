#ifndef OPENSSLTESTS_AESTEST_H_
#define OPENSSLTESTS_AESTEST_H_

#include <cstdint>
#include <array>
#include <vector>
#include <cstring>
#include <string>
#include <openssl/evp.h>

namespace OSSLTests
{
    enum CipherType : std::uint8_t
    {
        None = 0,
        AES_256_CBC = 1,
        AES_256_GCM = 2
    };

    class AES256Cipher
    {
    private:
        CipherType type;
        std::uint8_t* key;
    public:
        AES256Cipher(const CipherType, const std::array<std::uint8_t, 32>&);
        AES256Cipher(const CipherType, const std::uint8_t*);
        ~AES256Cipher();

        std::uint32_t Encrypt(std::uint8_t*, const std::uint32_t, const std::uint8_t*, const std::uint32_t, const std::uint8_t*);

        std::uint32_t Decrypt(std::uint8_t*, const std::uint32_t, const std::uint8_t*, const std::uint32_t, const std::uint8_t*);
    };
}

#endif