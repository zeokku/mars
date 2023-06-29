#include <openssl/evp.h>
#include <string.h>

#include "./types.h"

// define in parens, so it doesn't cause @bugs with operations order
// (256 / 8)
// all aes ciphers have block size 16
const auto ECB_CIPHER = EVP_aes_256_ecb();
const auto BLOCKSIZE = EVP_CIPHER_get_block_size(ECB_CIPHER);
const auto XOR_OP_SIZE = BLOCKSIZE / sizeof(size_t);

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
        BLOCKSIZE);

    // prepare next operation = plaintext ^ ciphertext
    xor_block(
        (size_t *)in,
        (size_t *)out,
        (size_t *)op);

    // printf("[PCBC] Encrypted len = %d\n", encrypted_size);
}

/*
    Use ECB mode to encrypt and pad the blocks by default with PKCS
*/
void encrypt_aes256_pcbc(const byte *plaintext, const size_t plaintext_size, const byte *key, byte *iv, byte *&ciphertext, size_t &ciphertext_size)
{
    // iv OR ciphertext ^ plaintext
    byte operation_buffer[BLOCKSIZE];

    // clear iv to 0
    // memset(operation_buffer, 0, BLOCKSIZE);
    memcpy(operation_buffer, iv, BLOCKSIZE);

    size_t padding_size = BLOCKSIZE - plaintext_size % BLOCKSIZE;
    ciphertext_size = plaintext_size + padding_size;

    ciphertext = new byte[ciphertext_size];

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    EVP_EncryptInit(ctx, ECB_CIPHER, key, NULL);

    // @note !!! it's required to disable padding
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    // encrypt full blocks
    for (size_t b = 0; b + BLOCKSIZE <= plaintext_size; b += BLOCKSIZE)
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
    byte *last_ciphertext_block = ciphertext + ciphertext_size - BLOCKSIZE;

    memcpy(
        last_ciphertext_block,
        plaintext + ciphertext_size - BLOCKSIZE,
        BLOCKSIZE - padding_size);

    // set padding
    memset(
        last_ciphertext_block + BLOCKSIZE - padding_size,
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

    EVP_DecryptUpdate(ctx, out, &decrypted_size, in, BLOCKSIZE);

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
    byte operation_buffer[BLOCKSIZE];
    // memset(operation_buffer, 0, BLOCKSIZE);
    memcpy(operation_buffer, iv, BLOCKSIZE);

    plaintext = new byte[ciphertext_size];

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    EVP_DecryptInit(ctx, ECB_CIPHER, key, NULL);

    EVP_CIPHER_CTX_set_padding(ctx, 0);

    for (size_t b = 0; b < ciphertext_size; b += BLOCKSIZE)
    {
        pcbc_decrypt_round(
            ctx,
            ciphertext + b,
            plaintext + b,
            operation_buffer);
    }

    size_t padding_size = plaintext[ciphertext_size - 1];
    plaintext_size = ciphertext_size - padding_size;

    EVP_CIPHER_CTX_free(ctx);
}