#include <openssl/err.h>

void print_error(const char *message)
{
    printf("\e[91m\e[1m"
           "Error:\n"
           "%s\n",
           message);
}

void handle_ossl_error()
{
    print_error(ERR_error_string(ERR_get_error(), NULL));
    abort();
}
