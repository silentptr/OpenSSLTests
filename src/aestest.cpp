#include "openssltests/aestest.h"

namespace OSSLTests
{
    AES256Cipher::AES256Cipher(const CipherType t, const std::array<std::uint8_t, 32>& arr)
    {
        switch (t)
        {
            case CipherType::AES_256_CBC:
            case CipherType::AES_256_GCM:
                break;
            default:
                throw std::string("invalid cipher type");
        }
        type = t;
        key = new std::uint8_t[32];
        std::memcpy(key, arr.data(), 32);
    }

    AES256Cipher::AES256Cipher(const CipherType t, const std::uint8_t* ptr)
    {
        switch (t)
        {
            case CipherType::AES_256_CBC:
            case CipherType::AES_256_GCM:
                break;
            default:
                throw std::string("invalid cipher type");
        }
        type = t;
        key = new std::uint8_t[32];
        std::memcpy(key, ptr, 32);
    }

    AES256Cipher::~AES256Cipher()
    {
        std::memset(key, 0, 32);
        delete[] key;
    }

    std::uint32_t AES256Cipher::Encrypt(std::uint8_t* destBuffer, const std::uint32_t destBufferLength, const std::uint8_t* plainBuffer, const std::uint32_t plainLength, const std::uint8_t* iv)
    {
        EVP_CIPHER_CTX* evpCtx = EVP_CIPHER_CTX_new();
        int opensslError;

        if (!evpCtx)
        {
            throw std::string("EVP_CIPHER_CTX_new failed");
        }

        if ((opensslError = EVP_EncryptInit_ex(evpCtx, type == CipherType::AES_256_CBC ? EVP_aes_256_cbc() : EVP_aes_256_gcm(), nullptr, key, iv)) != 1)
        {
            EVP_CIPHER_CTX_free(evpCtx);
            throw std::string("EVP_EncryptInit_ex failed: " + opensslError);
        }

        bool isGCM = type == CipherType::AES_256_GCM;

        if (isGCM && !EVP_CIPHER_CTX_ctrl(evpCtx, EVP_CTRL_GCM_SET_IVLEN, 16, NULL))
        {
            EVP_CIPHER_CTX_free(evpCtx);
            throw std::string("EVP_CIPHER_CTX_ctrl failed");
        }

        std::uint32_t cipherLength, outLength;
        std::uint8_t* temp = new std::uint8_t[plainLength * 2];

        if (EVP_EncryptUpdate(evpCtx, temp, (int*)&outLength, plainBuffer, plainLength) != 1)
        {
            EVP_CIPHER_CTX_free(evpCtx);
            delete[] temp;
            throw std::string("EVP_EncryptUpdate failed");
        }

        cipherLength = outLength;
        
        if (EVP_EncryptFinal_ex(evpCtx, temp + cipherLength, (int*)&outLength) != 1)
        {
            EVP_CIPHER_CTX_free(evpCtx);
            delete[] temp;
            throw std::string("EVP_EncryptFinal_ex");
        }

        cipherLength += outLength;
        std::uint8_t* gcmTag;

        if (isGCM)
        {
            gcmTag = new std::uint8_t[16];

            if (!EVP_CIPHER_CTX_ctrl(evpCtx, EVP_CTRL_GCM_GET_TAG, 16, gcmTag))
            {
                EVP_CIPHER_CTX_free(evpCtx);
                delete[] temp;
                delete[] gcmTag;
                throw std::string("EVP_CIPHER_CTX_ctrl failed");
            }
        }

        EVP_CIPHER_CTX_free(evpCtx);

        if (cipherLength > destBufferLength)
        {
            delete[] temp;

            if (isGCM)
            {
                delete[] gcmTag;
            }

            throw std::string("not enough room in destBuffer");
        }

        if (isGCM)
        {
            std::uint8_t* temp2 = new std::uint8_t[(plainLength * 2) + 16];
            std::memcpy(temp2, gcmTag, 16);
            std::memcpy(temp2 + 16, temp, cipherLength);
            std::memset(temp, 0, plainLength * 2);
            std::memcpy(destBuffer, temp2, cipherLength + 16);
            std::memset(temp2, 0, (plainLength * 2) + 16);
            delete[] temp2;
            delete[] gcmTag;
        }
        else
        {
            std::memcpy(destBuffer, temp, cipherLength);
            std::memset(temp, 0, plainLength * 2);
        }
        
        delete[] temp;
        return cipherLength + (isGCM ? 16 : 0);
    }

    std::uint32_t AES256Cipher::Decrypt(std::uint8_t* destBuffer, const std::uint32_t destBufferLength, const std::uint8_t* cipherBuffer, const std::uint32_t cipherLength, const std::uint8_t* iv)
    {
        EVP_CIPHER_CTX* evpCtx = EVP_CIPHER_CTX_new();
        int opensslError;

        if (!evpCtx)
        {
            throw std::string("EVP_CIPHER_CTX_new failed");
        }

        bool isGCM = type == CipherType::AES_256_GCM;

        if (EVP_DecryptInit_ex(evpCtx, isGCM ? EVP_aes_256_gcm() : EVP_aes_256_cbc(), NULL, key, iv) != 1)
        {
            EVP_CIPHER_CTX_free(evpCtx);
            throw std::string("EVP_DecryptInit_ex failed");
        }

        if (isGCM && !EVP_CIPHER_CTX_ctrl(evpCtx, EVP_CTRL_GCM_SET_IVLEN, 16, NULL))
        {
            EVP_CIPHER_CTX_free(evpCtx);
            throw std::string("EVP_CIPHER_CTX_ctrl failed");
        }
        
        std::uint32_t plainLength, outLength;
        std::uint8_t* temp = new std::uint8_t[cipherLength * 2];

        if (EVP_DecryptUpdate(evpCtx, temp, (int*)&outLength, cipherBuffer + (isGCM ? 16 : 0), cipherLength - (isGCM ? 16 : 0)) != 1)
        {
            EVP_CIPHER_CTX_free(evpCtx);
            delete[] temp;
            throw std::string("EVP_DecryptUpdate failed");
        }

        plainLength = outLength;

        if (isGCM && !EVP_CIPHER_CTX_ctrl(evpCtx, EVP_CTRL_GCM_SET_TAG, 16, (void*)cipherBuffer))
        {
            EVP_CIPHER_CTX_free(evpCtx);
            delete[] temp;
            throw std::string("EVP_CIPHER_CTX_ctrl failed");
        }

        if ((opensslError = EVP_DecryptFinal_ex(evpCtx, temp + plainLength, (int*)&outLength)) != 1)
        {
            EVP_CIPHER_CTX_free(evpCtx);
            delete[] temp;
            throw std::string("EVP_DecryptFinal_ex failed: " + std::to_string(opensslError));
        }

        plainLength += outLength;
        EVP_CIPHER_CTX_free(evpCtx);

        if (plainLength > destBufferLength)
        {
            delete[] temp;
            throw std::string("not enough room in destBuffer");
        }

        std::memcpy(destBuffer, temp, plainLength);
        std::memset(temp, 0, cipherLength * 2);
        delete[] temp;
        return plainLength;
    }
}