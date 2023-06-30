#include <openssl/err.h>

void print_error(const char *message)
{
    printf("\e[41m\e[1m"
           "Error:"
           "\e[49m\n"
           "\e[91m"
           "%s\n",
           message);
}

void handle_ossl_error()
{
    print_error(ERR_error_string(ERR_get_error(), NULL));
    abort();
}
