#include <openssl/evp.h>

#include "./types.h"

const auto DIGEST_ALG = EVP_sha3_512();
const auto DIGEST_SIZE = EVP_MD_get_size(DIGEST_ALG);

void hash(byte *data, size_t data_size, byte *&digest_buffer)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();

    EVP_DigestInit(ctx, DIGEST_ALG);

    EVP_DigestUpdate(ctx, data, data_size);

    digest_buffer = new byte[DIGEST_SIZE];

    unsigned int digest_size;

    EVP_DigestFinal(ctx, digest_buffer, &digest_size);

    EVP_MD_CTX_free(ctx);
}

bool verify(byte *data, size_t data_size, byte *digest_buffer)
{
    byte *current_digest_buffer;

    hash(data, data_size, current_digest_buffer);

    for (size_t b = 0; b < DIGEST_SIZE; b += 1)
    {
        if (digest_buffer[b] != current_digest_buffer[b])
            return false;
    }

    return true;
}