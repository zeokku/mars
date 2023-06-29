#include <openssl/core_names.h> /* OSSL_KDF_*           */
#include <openssl/params.h>     /* OSSL_PARAM_*         */
#include <openssl/thread.h>     /* OSSL_set_max_threads */

#include <openssl/kdf.h> /* EVP_KDF_*            */
#include <openssl/evp.h>

#include "./types.h"
#include "./error.hpp"

// aes256
#define KEY_SIZE (256 / 8)

#define SALT_SIZE (128 / 8)

#include <chrono>
using namespace std::chrono;

#define MB(x) 1024ull * x
#define GB(x) MB(1024ull) * x

void kdf(byte *password, byte password_size, byte *salt, byte salt_size, byte *key)
{
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "ARGON2D", NULL);

    if (kdf == NULL)
        handle_error();

    EVP_KDF_CTX *ctx = EVP_KDF_CTX_new(kdf);

    if (ctx == NULL)
        handle_error();

    // https://www.rfc-editor.org/rfc/rfc9106.html#name-parameter-choice
    // @todo 4 lanes, 2 threads
    size_t
        threads = 1,
        lanes = 2,
        iterations = 1;

    // https://www.openssl.org/docs/manmaster/man7/EVP_KDF-ARGON2.html#:~:text=%22memcost%22%20(-,OSSL_KDF_PARAM_ARGON2_MEMCOST,-)%20%3Cunsigned%20integer%3E
    // mem cost is 1k blocks
    // first increase memory to max affordable
    // then increase number of iterations
    size_t
        memcost = GB(3);
    // 1gb 1466ms
    // 2gb 2769ms
    // 3gb 3926ms
    // 4gb 6242ms

    // printf("[KDF] Iterations: %zu, memcost: %zu, lanes: %zu\n", iterations, memcost, lanes);

    // key = new byte[KEY_SIZE];

    // @todo waiting for bugfix to be merged into master
    // https://github.com/openssl/openssl/issues/21305
    /* required if threads > 1 */
    // if (OSSL_set_max_threads(NULL, threads) != 1)
    //     handle_error();

    // @note @bug this caused stack smashing error!!!
    // i had 6 params instaed of 7
    OSSL_PARAM params[7];
    OSSL_PARAM *p = params;

    *p++ = OSSL_PARAM_construct_size_t(
        OSSL_KDF_PARAM_THREADS,
        &threads);

    *p++ = OSSL_PARAM_construct_size_t(
        OSSL_KDF_PARAM_ARGON2_LANES,
        &lanes);

    *p++ = OSSL_PARAM_construct_size_t(
        OSSL_KDF_PARAM_ITER,
        &iterations);

    *p++ = OSSL_PARAM_construct_size_t(
        OSSL_KDF_PARAM_ARGON2_MEMCOST,
        &memcost);

    *p++ = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_PASSWORD,
        password,
        password_size);

    *p++ = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_SALT,
        salt,
        salt_size);

    *p++ = OSSL_PARAM_construct_end();

    auto start = high_resolution_clock::now();

    printf("\e[3m"
           "KDF running"
           "\e[0m");
    // force output before starting kdf
    fflush(stdout);

    if (EVP_KDF_derive(ctx, key, KEY_SIZE, params) != 1)
        handle_error();

    auto finish = high_resolution_clock::now();

    // @note use \r to overwrite current line
    printf("\r\e[3m"
           "KDF duration = %ldms"
           "\e[0m\n",
           duration_cast<milliseconds>(finish - start).count());

    EVP_KDF_free(kdf);
    EVP_KDF_CTX_free(ctx);
}