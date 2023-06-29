#include <openssl/rand.h>
#include "./pcbc.hpp"

void test(size_t test_payload_size)
{
    byte key[BLOCKSIZE];
    RAND_bytes(key, BLOCKSIZE);

    byte iv[BLOCKSIZE];
    RAND_bytes(iv, BLOCKSIZE);

    byte *test_payload = new byte[test_payload_size];
    RAND_bytes(test_payload, test_payload_size);

    byte *encrypted;
    size_t encrypted_size;
    encrypt_aes256_pcbc(test_payload, test_payload_size, key, iv, encrypted, encrypted_size);

    // printf("[%ld] Encrypted: %ld -> %ld\n", test_payload_size, test_payload_size, encrypted_size);

    byte *decrypted;
    size_t decrypted_size;
    decrypt_aes256_pcbc(encrypted, encrypted_size, key, iv, decrypted, decrypted_size);

    // printf("[%ld] Decrypted: %ld -> %ld\n", test_payload_size, encrypted_size, decrypted_size);

    if (test_payload_size != decrypted_size)
    {
        printf("! Different sizes !\n");
        abort();
    }

    for (size_t i = 0; i < test_payload_size; i += 1)
    {
        if (test_payload[i] != decrypted[i])
        {
            printf("! Different bytes [%ld] !\n", i);
            abort();
        }
    }

    printf("[%3ld] Pass! (%3ld -> %3ld -> %3ld)\n", test_payload_size, test_payload_size, encrypted_size, decrypted_size);

    delete[] test_payload;
}

int main()
{
    // test(1);

    // test(BLOCKSIZE - 1);

    // test(BLOCKSIZE);

    // test(BLOCKSIZE + 1);

    // test(BLOCKSIZE * 5);

    // test(BLOCKSIZE * 5 + 2);

    // printf("--- Random tests ---\n");
    // for (size_t r = 0; r < 50; r += 1)
    // {
    //     byte rs;
    //     RAND_bytes(&rs, 1);

    //     test(rs);
    // }

    ///////

    for (size_t s = 0; s < 256; s += 1)
    {
        test(s);
    }

    return 0;
}