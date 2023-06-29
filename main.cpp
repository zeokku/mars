#include <string.h> /* strlen               */

#include <openssl/core_names.h> /* OSSL_KDF_*           */
#include <openssl/params.h>     /* OSSL_PARAM_*         */
#include <openssl/thread.h>     /* OSSL_set_max_threads */

#include <openssl/kdf.h> /* EVP_KDF_*            */
#include <openssl/evp.h>

#include <openssl/rand.h>

#include <openssl/err.h>

#include "./types.h"

#include "./pcbc.hpp"

#include <chrono>
using namespace std::chrono;

#define MB(x) 1024ull * x
#define GB(x) MB(1024ull) * x

void handle_error()
{
    printf("End: %s", ERR_error_string(ERR_get_error(), NULL));
    abort();
}

int main(void)
{
    int retval = 1;

    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;
    OSSL_PARAM params[6];

    // https://www.rfc-editor.org/rfc/rfc9106.html#name-parameter-choice
    uint32_t
        threads = 1,
        lanes = 2,
        iterations = 1; // 4

    // https://www.openssl.org/docs/manmaster/man7/EVP_KDF-ARGON2.html#:~:text=%22memcost%22%20(-,OSSL_KDF_PARAM_ARGON2_MEMCOST,-)%20%3Cunsigned%20integer%3E
    // mem cost is 1k blocks
    // first increase memory to max affordable
    // then increase number of iterations
    const uint64_t
        memcost = GB(1);
    // 1gb 1466ms
    // 2gb 2769ms
    // 3gb 3926ms
    // 4gb 6242ms

    printf("[Config] Iterations: %d, memcost: %ld, lanes: %d\n", iterations, memcost, lanes);

    char pwd[] = "test password with spaces btw", salt[] = "saltsalt";

    size_t outlen = 256;
    unsigned char result[outlen];

    // @todo error, undefined
    /* required if threads > 1 */
    // if (OSSL_set_max_threads(NULL, threads) != 1)
    //     handle_error();

    OSSL_PARAM *p = params;

    *p++ = OSSL_PARAM_construct_uint32(
        OSSL_KDF_PARAM_THREADS,
        &threads);

    *p++ = OSSL_PARAM_construct_uint32(
        OSSL_KDF_PARAM_ARGON2_LANES,
        &lanes);

    *p++ = OSSL_PARAM_construct_uint32(
        OSSL_KDF_PARAM_ITER,
        &iterations);

    *p++ = OSSL_PARAM_construct_uint64(
        OSSL_KDF_PARAM_ARGON2_MEMCOST,
        (uint64_t *)&memcost);

    *p++ = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_SALT,
        salt,
        strlen((const char *)salt));

    *p++ = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_PASSWORD,
        pwd,
        strlen((const char *)pwd));

    *p++ = OSSL_PARAM_construct_end();

    if ((kdf = EVP_KDF_fetch(NULL, "ARGON2D", NULL)) == NULL)
        handle_error();

    if ((kctx = EVP_KDF_CTX_new(kdf)) == NULL)
        handle_error();

    auto start = high_resolution_clock::now();

    if (EVP_KDF_derive(kctx, &result[0], outlen, params) != 1)
        handle_error();

    printf("Duration = %ldms\n", duration_cast<milliseconds>(high_resolution_clock::now() - start).count());

    printf("Output = %s\n", OPENSSL_buf2hexstr(result, outlen));

    char testtext[] = "some plain test "
                      "text";
    byte iv[BLOCKSIZE];
    RAND_bytes(iv, BLOCKSIZE);

    printf("Block size = %d\n", BLOCKSIZE);

    byte *ciphertext;
    size_t ciphertext_size;
    encrypt_aes256_pcbc((byte *)testtext, strlen(testtext), result, (byte *)iv, ciphertext, ciphertext_size);

    printf("Encrypted (%ld -> %ld) = %s\n", strlen(testtext), ciphertext_size, OPENSSL_buf2hexstr(ciphertext, ciphertext_size));

    byte *plaintext;
    size_t plaintext_size;
    decrypt_aes256_pcbc(ciphertext, ciphertext_size, result, iv, plaintext, plaintext_size);

    // since padding is guaranteed to be at least one byte, we write null terminator within ciphertext_size allocated range inside plaintext
    plaintext[plaintext_size] = 0;
    printf("Decrypted (%ld -> %ld) = %s\n", ciphertext_size, plaintext_size, plaintext);
    // fail:
    //     printf("End: %s", ERR_error_string(ERR_get_error(), NULL));
    //     EVP_KDF_CTX_free(kctx);
    //     EVP_KDF_free(kdf);

    // OSSL_set_max_threads(NULL, 0);

    return 0;
}