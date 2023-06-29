#include <string>
#include <iostream>
#include <fstream>

#include <openssl/rand.h>

#include "./types.h"

// @todo configure everything with defines before includes in a config.h

#include "./kdf.hpp"
#include "./integrity.hpp"
#include "./pcbc.hpp"

#define SALT_SIZE (128 / 8)

int main(void)
{

#pragma region File digest

    // size_t file_size = 500;
    // byte *file = new byte[file_size];
    // RAND_bytes(file, file_size);

    byte *file = (byte *)"some test file content";
    size_t file_size = strlen((char *)file);

    byte *digest;

    hash(file, file_size, digest);

    // printf("Digest = %s\n", OPENSSL_buf2hexstr(digest_buffer, DIGEST_SIZE));

#pragma endregion

#pragma region Password input and key derivation
    printf("Input password:\n");

    std::string password;
    getline(std::cin, password);

    system("clear");

    byte salt[SALT_SIZE];
    RAND_bytes(salt, SALT_SIZE);

    // printf("Password (%zu) = %s\n", password.length(), password.c_str());
    // printf("Salt = %s\n", OPENSSL_buf2hexstr(salt, SALT_SIZE));

    byte *key;

    kdf((byte *)password.c_str(), password.length(), salt, SALT_SIZE, key);

    // printf("Key = %s\n", OPENSSL_buf2hexstr(key, KEY_SIZE));

#pragma endregion

#pragma region File encryption

    byte *iv = new byte[IV_SIZE];
    RAND_bytes(iv, IV_SIZE);

    byte *ciphertext;
    size_t ciphertext_size;

    encrypt_aes256_pcbc(file, file_size, key, iv, ciphertext, ciphertext_size);

    // erase key
    memset(key, 0, KEY_SIZE);

#pragma endregion

#pragma region Writing to disk

    std::ofstream encrypted_tar;
    encrypted_tar.open("encrypted.mars", std::ios::binary | std::ios::trunc);

    // << can't be used
    encrypted_tar.write((char *)salt, SALT_SIZE);
    encrypted_tar.write((char *)digest, DIGEST_SIZE);
    encrypted_tar.write((char *)iv, IV_SIZE);
    encrypted_tar.write((char *)ciphertext, ciphertext_size);

    // vs code doesn't immediately update files in side bar, so it may appear ofstream didn't create the file
    encrypted_tar.close();

    printf("File written! %zu bytes\n", SALT_SIZE + DIGEST_SIZE + IV_SIZE + ciphertext_size);

#pragma endregion

    return 0;
}