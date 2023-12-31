#include <string>
#include <iostream>
#include <fstream>

#include <openssl/rand.h>

#include <filesystem>

#include "./types.h"

// @todo configure everything with defines before includes in a config.h

#include "./kdf.hpp"
#include "./integrity.hpp"
#include "./pcbc.hpp"

#define ENCRYPTED_EXT std::string(".mars")

void encrypt(const std::string filename, const std::string password)
{

#pragma region Create brotli compressed archive

    std::string tar_path = filename + ".tar.br";
    std::string command = "tar -cO " + filename + " | brotli --best -f - -o " + tar_path;

    system(command.c_str());

#pragma endregion

#pragma region Read tar.br
    std::ifstream fs(tar_path, std::ios::binary);

    // extra parens are required????
    std::string file((std::istreambuf_iterator<char>(fs)),
                     (std::istreambuf_iterator<char>()));

    fs.close();

    size_t file_size = file.length();
#pragma endregion

#pragma region Overwrite file and delete it

    std::ofstream of(tar_path, std::ios::binary);
    for (size_t f = 0; f < file_size; f += 1)
    {
        of.put(0);
    }
    of.close();

    // remove file
    std::remove(tar_path.c_str());
#pragma endregion

#pragma region File digest

    byte digest[DIGEST_SIZE];

    hash((byte *)file.data(), file_size, digest);

    // prepend digest to file
    file = std::string((char *)digest, DIGEST_SIZE) + file;
    file_size = file.length();

    // printf("Digest = %s\n", OPENSSL_buf2hexstr(digest_buffer, DIGEST_SIZE));

#pragma endregion

#pragma region Key derivation

    byte salt[SALT_SIZE];
    RAND_bytes(salt, SALT_SIZE);

    // printf("Password (%zu) = %s\n", password.length(), password.c_str());
    // printf("Salt = %s\n", OPENSSL_buf2hexstr(salt, SALT_SIZE));

    byte key[KEY_SIZE];

    kdf((byte *)password.c_str(), password.length(), salt, SALT_SIZE, key);

    // printf("Key = %s\n", OPENSSL_buf2hexstr(key, KEY_SIZE));

#pragma endregion

#pragma region File encryption

    byte iv[IV_SIZE];
    RAND_bytes(iv, IV_SIZE);

    byte *ciphertext;
    size_t ciphertext_size;

    encrypt_aes256_pcbc((byte *)file.data(), file_size, key, iv, ciphertext, ciphertext_size);

    OPENSSL_cleanse(key, KEY_SIZE);
    OPENSSL_cleanse(file.data(), file_size);

#pragma endregion

#pragma region Writing to disk

    std::ofstream encrypted(filename + ".mars", std::ios::binary | std::ios::trunc);

    // << can't be used
    encrypted.write((char *)salt, SALT_SIZE);
    // encrypted.write((char *)digest, DIGEST_SIZE);
    encrypted.write((char *)iv, IV_SIZE);
    encrypted.write((char *)ciphertext, ciphertext_size);

    // vs code doesn't immediately update files in side bar, so it may appear ofstream didn't create the file
    encrypted.close();

    printf(
        "\e[33m\e[3m"
        "Final size = %zu bytes"
        "\e[0m\n"
        "\e[92m"
        "Data encrypted successfully!\n",
        SALT_SIZE + IV_SIZE + ciphertext_size);

#pragma endregion
}

void decrypt(const std::string filename, const std::string password)
{
#pragma region Read data

    byte salt[SALT_SIZE];
    byte iv[IV_SIZE];

    std::ifstream encrypted(filename, std::ios::binary);
    encrypted.read((char *)salt, SALT_SIZE);
    // encrypted.read((char *)digest, DIGEST_SIZE);
    encrypted.read((char *)iv, IV_SIZE);

    std::string ciphertext((std::istreambuf_iterator<char>(encrypted)),
                           (std::istreambuf_iterator<char>()));

    size_t ciphertext_size = ciphertext.length();

#pragma endregion

#pragma region Key derivation

    byte key[KEY_SIZE];

    kdf((byte *)password.c_str(), password.length(), salt, SALT_SIZE, key);

#pragma endregion

#pragma region Decryption

    byte *plaintext;
    size_t plaintext_size;

    decrypt_aes256_pcbc((byte *)ciphertext.data(), ciphertext_size, key, iv, plaintext, plaintext_size);

    OPENSSL_cleanse(key, KEY_SIZE);

    // extract digest
    byte *digest = plaintext;
    plaintext += DIGEST_SIZE;
    plaintext_size -= DIGEST_SIZE;

#pragma endregion

#pragma Integrity check

    if (!verify(plaintext, plaintext_size, digest))
    {
        printf("\e[91m"
               "Integrity is broken or password is incorrect!\n");
        abort();
    }

#pragma endregion

#pragma region Decompress and untar

    std::string path = filename.substr(0, filename.length() - ENCRYPTED_EXT.length()) + ".tar.br";

    std::ofstream fs;

    fs.open(path, std::ios::binary);
    fs.write((char *)plaintext, plaintext_size);
    fs.close();

    OPENSSL_cleanse(plaintext, plaintext_size);

    std::string command = "brotli -d " + path + " --stdout | tar -x";

    system(command.c_str());

    // overwrite with 0s
    fs.open(path, std::ios::binary);
    for (size_t f = 0; f < plaintext_size; f += 1)
    {
        fs.put(0);
    }
    fs.close();

    std::remove((path).c_str());

    printf("\e[92m"
           "Data decrypted successfully!\n");

#pragma endregion
}

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        // 4 - underline
        printf(
            "\e[43m\e[3m\e[1m"
            "Usage:"
            "\e[0m\n\n"

            "  \e[3m"
            "Encrypt:"
            "\e[0m\n"

            "    \e[41m"
            "mars"
            "\e[0m"
            " "
            "\e[33m"
            "path/to/folder"
            "\e[0m\n"

            "\n"

            "  \e[3m"
            "Decrypt:"
            "\e[0m\n"

            "    \e[41m"
            "mars"
            "\e[49m \e[36m"
            "encrypted.mars\n"

            "\e[39m\e[3m");
        return 0;
    }

    std::string filename(argv[1]);

    if (!std::filesystem::exists(filename))
    {
        print_error(("Path \"" + filename + "\" does not exist!").c_str());
        abort();
    }

#pragma region Password input
    printf("\e[33m\e[3m\e[1m"
           "Input password:\n"
           "\e[0m");

    std::string password;
    getline(std::cin, password);

    system("clear");

#pragma endregion

    if (filename.ends_with(ENCRYPTED_EXT))
    {
        decrypt(filename, password);
    }
    else
    {
        encrypt(filename, password);
    }
}