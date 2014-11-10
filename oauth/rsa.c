#include "rsa.h"

int sign_with_rsa_sha256(const char *input, const char *private_key, unsigned char *buffer_out, int *buffer_out_len) {

  FILE *fp;
  EVP_PKEY *pkey = 0;
  EVP_MD_CTX *ctx = 0;
  const EVP_MD *sha256_md = 0;
  unsigned int s = 0;
  PKCS12 *p12 = 0;
  X509 *cert = 0;

  OpenSSL_add_all_ciphers();
  OpenSSL_add_all_digests();
  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();

  ctx = EVP_MD_CTX_create();
  EVP_MD_CTX_init(ctx);
  sha256_md = EVP_sha256(); 

  EVP_SignInit(ctx, sha256_md);
  EVP_SignUpdate(ctx, input, strlen(input));

  ERR_load_crypto_strings();
  if (!(fp = fopen(private_key, "rb"))) {
    perror("Error opening file with private key");
    return -1;
  }
  
  p12 = d2i_PKCS12_fp(fp, NULL);
  fclose (fp);
  if (!p12) {
    perror("Error reading PKCS#12 file");
    return -1;
  }

  if (!PKCS12_parse(p12, "notasecret", &pkey, &cert, NULL)) {
    perror("Error parsing PKCS#12 file");
    return -1;
  }

  s = EVP_PKEY_size(pkey);
  EVP_SignFinal(ctx, buffer_out, &s, pkey);
  
  *buffer_out_len = s;

  PKCS12_free(p12);
  EVP_MD_CTX_destroy(ctx);
  X509_free(cert);
  EVP_cleanup();

  return 0;
}
