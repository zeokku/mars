#include <openssl/core_names.h> /* OSSL_KDF_*           */
#include <openssl/params.h>     /* OSSL_PARAM_*         */
#include <openssl/thread.h>     /* OSSL_set_max_threads */

#include <openssl/kdf.h> /* EVP_KDF_*            */
#include <openssl/evp.h>

#include <cmath>

#include "./types.h"
#include "./error.hpp"

// aes256
#define KEY_SIZE (256 / 8)

#define SALT_SIZE (128 / 8)

#include <chrono>
using namespace std::chrono;

// @note multiply by double to allow fractional units
#define MiB(x) 1024. * x
#define GiB(x) MiB(1024) * x

void kdf(byte *password, byte password_size, byte *salt, byte salt_size, byte *key)
{
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "ARGON2D", NULL);

    if (kdf == NULL)
        handle_ossl_error();

    EVP_KDF_CTX *ctx = EVP_KDF_CTX_new(kdf);

    if (ctx == NULL)
        handle_ossl_error();

    // https://www.rfc-editor.org/rfc/rfc9106.html#name-parameter-choice
    size_t
        lanes = 4,
        threads = 2,
        iterations = 3;

    // https://www.openssl.org/docs/manmaster/man7/EVP_KDF-ARGON2.html#:~:text=%22memcost%22%20(-,OSSL_KDF_PARAM_ARGON2_MEMCOST,-)%20%3Cunsigned%20integer%3E
    // mem cost is 1k blocks
    // first increase memory to max affordable
    // then increase number of iterations
    size_t
        memcost = GiB(4);

    // 1gb 1466ms
    // 2gb 2769ms
    // 3gb 3926ms
    // 4gb 6242ms

#pragma region @todo config tweak
    // @todo store values in .mars file
    // utilize struct

    // printf("\e[33m\e[3m\e[1m"
    //        "Do you want to tweak KDF parameters? "
    //        "(y/"
    //        "\e[4m"
    //        "N"
    //        "\e[0m"
    //        "\e[33m\e[3m\e[1m"
    //        "):\e[0m ");

    // std::string input;
    // getline(std::cin, input);

    // if (input == "y" || input == "yes")
    // {
    //     printf("\e[96m"
    //            "Mem cost (GiB):"
    //            "\e[0m ");
    //     getline(std::cin, input);

    //     memcost = GiB(std::stod(input));

    //     ///

    //     printf("\e[96m"
    //            "Lanes:"
    //            "\e[0m ");
    //     getline(std::cin, input);

    //     lanes = std::stoul(input);

    //     threads = std::ceil(lanes / 2.);

    //     ///

    //     printf("\e[96m"
    //            "Iterations:"
    //            "\e[0m ");
    //     getline(std::cin, input);

    //     iterations = std::stoul(input);
    // }
#pragma endregion

    printf(
        "\e[95m[KDF config]\e[0m\n"
        "\e[3m"
        "Iterations: %zu, memcost: %zu, lanes: %zu, threads: %zu"
        "\e[0m\n",
        iterations, memcost, lanes, threads);

    // https://github.com/openssl/openssl/issues/21305
    /* required if threads > 1 */
    if (!OSSL_set_max_threads(NULL, threads))
        handle_ossl_error();

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
           "KDF is running..."
           "\e[0m");
    // force output before starting kdf
    fflush(stdout);

    if (!EVP_KDF_derive(ctx, key, KEY_SIZE, params))
        handle_ossl_error();

    auto finish = high_resolution_clock::now();

    // @note use \r to overwrite current line
    printf("\r\e[3m"
           "KDF duration = %ld ms"
           "\e[0m\n",
           duration_cast<milliseconds>(finish - start).count());

    EVP_KDF_free(kdf);
    EVP_KDF_CTX_free(ctx);

    // OSSL_set_max_threads(NULL, 0);
}