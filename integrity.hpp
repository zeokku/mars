#include <openssl/evp.h>

#include "./types.h"

const auto DIGEST_ALG = EVP_sha3_512();
const auto DIGEST_SIZE = EVP_MD_get_size(DIGEST_ALG);

void hash(const byte *data, const size_t data_size, byte *digest_buffer)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();

    if (ctx == NULL)
        handle_ossl_error();

    if (!EVP_DigestInit(ctx, DIGEST_ALG))
        handle_ossl_error();

    if (!EVP_DigestUpdate(ctx, data, data_size))
        handle_ossl_error();

    unsigned int digest_size;

    if (!EVP_DigestFinal(ctx, digest_buffer, &digest_size))
        handle_ossl_error();

    EVP_MD_CTX_free(ctx);
}

bool verify(const byte *data, const size_t data_size, const byte *digest_buffer)
{
    byte data_digest_buffer[DIGEST_SIZE];

    hash(data, data_size, data_digest_buffer);

    for (size_t b = 0; b < DIGEST_SIZE; b += 1)
    {
        if (digest_buffer[b] != data_digest_buffer[b])
            return false;
    }

    return true;
}