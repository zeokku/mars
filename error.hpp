#include <openssl/err.h>

void handle_error()
{
    printf("Error: %s", ERR_error_string(ERR_get_error(), NULL));
    abort();
}