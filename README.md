# OpenSSL Tests

Some tests of OpenSSL in C++17. OpenSSL is pretty annoying to get a hang of on account of the really bad documentation it provides so when I figure out how to do something I push it here. This is mainly for a reference I can use for future OpenSSL code as well as just learning how to use it.

Feel free to use this code as a reference or to copy it completely.

# Features

- AES 256-bit CBC encryption
- AES 256-bit GCM encryption (without AAD)

# References

References I used when writing this code that may be useful to you if you're writing your own OpenSSL code:

- [EVP Symmetric Encryption and Decryption - OpenSSLWiki](https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption)
- [EVP Authenticated Encryption and Decryption - OpenSSLWiki](https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption)