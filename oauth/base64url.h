#include <stdlib.h>
#include <stdio.h>
#include <time.h>

unsigned char* hawkc_base64url_encode(const unsigned char* data, size_t data_len, unsigned char *result, size_t *result_len);
int hawkc_base64url_decode(const unsigned char* data, size_t data_len, unsigned char *result, size_t *result_len);
