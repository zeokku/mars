#include <openssl/evp.h>
#include <string.h>

#include "./types.h"

// define in parens, so it doesn't cause @bugs with operations order
// (256 / 8)
// all aes ciphers have block size 16
const auto ECB_CIPHER = EVP_aes_256_ecb();
const auto BLOCK_SIZE = EVP_CIPHER_get_block_size(ECB_CIPHER);
const auto XOR_OP_SIZE = BLOCK_SIZE / sizeof(size_t);

#define IV_SIZE BLOCK_SIZE

// faster xor with size_t?
// compiler should optimize it to use 128/256 bit operations doe
// dest = b0 ^ b1
void xor_block(size_t *b0, size_t *b1, size_t *dest)
{
    for (size_t i = 0; i < XOR_OP_SIZE; i += 1)
    {
        dest[i] = b0[i] ^ b1[i];
    }
}

void pcbc_encrypt_round(EVP_CIPHER_CTX *ctx, const byte *in, byte *out, byte *op)
{
    int encrypted_size;

    // plaintext ^ operation (= iv OR prev_plaintext & prev_ciphertext)
    xor_block(
        (size_t *)in,
        (size_t *)op,
        (size_t *)op);

    // encrypt
    EVP_EncryptUpdate(
        ctx,
        out,
        &encrypted_size,
        op,
        BLOCK_SIZE);

    // prepare next operation = plaintext ^ ciphertext
    xor_block(
        (size_t *)in,
        (size_t *)out,
        (size_t *)op);

    // printf("[PCBC] Encrypted len = %d\n", encrypted_size);
}

void encrypt_aes256_pcbc(const byte *plaintext, const size_t plaintext_size, const byte *key, byte *iv, byte *&ciphertext, size_t &ciphertext_size)
{
    // iv OR ciphertext ^ plaintext
    byte operation_buffer[BLOCK_SIZE];

    // clear iv to 0
    // memset(operation_buffer, 0, BLOCK_SIZE);
    memcpy(operation_buffer, iv, BLOCK_SIZE);

    size_t padding_size = BLOCK_SIZE - plaintext_size % BLOCK_SIZE;
    ciphertext_size = plaintext_size + padding_size;

    ciphertext = new byte[ciphertext_size];

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    EVP_EncryptInit(ctx, ECB_CIPHER, key, NULL);

    // @note !!! it's required to disable padding
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    // encrypt full blocks
    for (size_t b = 0; b + BLOCK_SIZE <= plaintext_size; b += BLOCK_SIZE)
    {
        pcbc_encrypt_round(
            ctx,
            plaintext + b,
            ciphertext + b,
            operation_buffer);
    }

    /// encrypt last block

    // copy remaining bytes
    // use end of ciphertext to store padded plaintext

    // temp store for padded final plaintext block
    byte *last_ciphertext_block = ciphertext + ciphertext_size - BLOCK_SIZE;

    memcpy(
        last_ciphertext_block,
        plaintext + ciphertext_size - BLOCK_SIZE,
        BLOCK_SIZE - padding_size);

    // set padding
    memset(
        last_ciphertext_block + BLOCK_SIZE - padding_size,
        padding_size,
        padding_size);

    pcbc_encrypt_round(
        ctx,
        last_ciphertext_block,
        last_ciphertext_block,
        operation_buffer);

    EVP_CIPHER_CTX_free(ctx);
}

void pcbc_decrypt_round(EVP_CIPHER_CTX *ctx, const byte *in, byte *out, byte *op)
{
    int decrypted_size;

    EVP_DecryptUpdate(ctx, out, &decrypted_size, in, BLOCK_SIZE);

    // plaintext = decrypted ^ op (= iv OR prev_ciphertext ^ prev_plaintext)
    xor_block(
        (size_t *)out,
        (size_t *)op,
        (size_t *)out);

    // update op = ciphertext ^ plaintext
    xor_block(
        (size_t *)in,
        (size_t *)out,
        (size_t *)op);

    // printf("[PCBC] Decrypted len = %d\n", decrypted_size);
}

void decrypt_aes256_pcbc(const byte *ciphertext, const size_t ciphertext_size, const byte *key, byte *iv, byte *&plaintext, size_t &plaintext_size)
{
    byte operation_buffer[BLOCK_SIZE];
    // memset(operation_buffer, 0, BLOCK_SIZE);
    memcpy(operation_buffer, iv, BLOCK_SIZE);

    plaintext = new byte[ciphertext_size];

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    EVP_DecryptInit(ctx, ECB_CIPHER, key, NULL);

    EVP_CIPHER_CTX_set_padding(ctx, 0);

    for (size_t b = 0; b < ciphertext_size; b += BLOCK_SIZE)
    {
        pcbc_decrypt_round(
            ctx,
            ciphertext + b,
            plaintext + b,
            operation_buffer);
    }

    size_t padding_size = plaintext[ciphertext_size - 1];

    // @note sometimes incorrect password may lead to incorrect decryption and thus
    // extremely big plaintext_size values, when padding_size turns out to be bigger
    // than ciphertext size (overflow)
    if (padding_size > BLOCK_SIZE)
    {
        printf("\e[91m"
               "Integrity is broken or password is incorrect!\n");
        abort();
    }

    plaintext_size = ciphertext_size - padding_size;

    EVP_CIPHER_CTX_free(ctx);
}