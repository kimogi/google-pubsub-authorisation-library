#include <openssl/sha.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/pkcs12.h>

#include <errno.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

int sign_with_rsa_sha256(const char *input, const char *private_key, unsigned char *buffer_out, int *buffer_out_len);
