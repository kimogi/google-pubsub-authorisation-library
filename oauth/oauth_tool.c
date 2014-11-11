#include "oauth_tool.h"

const char *HEADER_ALG = "RS256";
const char *HEADER_TYP = "JWT";
const char *TOKEN_AUD = "https://accounts.google.com/o/oauth2/token";
const char *REQUEST_TOKEN_URL = "https://accounts.google.com/o/oauth2/token";
const char *REQUEST_TOKEN_JWT_PREFIX = "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=";

int get_unix_time_now();
int make_token_request(unsigned char *jwt, long connection_timeout, long timeout, size_t (*callback)(char *, size_t, size_t, void *), void *user_pointer);
unsigned char *base64url_encode(unsigned char *src, int src_len);

void request_auth_token(struct google_pubsub_props *props, const char *scope, const char *private_key_path, size_t (*callback)(char *, size_t, size_t, void *), void *user_pointer) {
  unsigned char *jwt_header = (unsigned char *)calloc(strlen("{\"alg\":\"\",\"typ\":\"\"}") + strlen(HEADER_ALG) + strlen(HEADER_TYP) + 1, sizeof(char));
  sprintf(jwt_header, "{\"alg\":\"%s\",\"typ\":\"%s\"}", HEADER_ALG, HEADER_TYP);

  int issue_time_secs = get_unix_time_now();
  int exp_time_secs = issue_time_secs + 3000;
 
  unsigned char *jwt_claim_set = (unsigned char *)calloc(
    strlen("{\"iss\":\"\",\"scope\":\"\",\"aud\":\"\",\"exp\":,\"iat\":}") + strlen(props->email_address) + strlen(scope) + strlen(TOKEN_AUD) + 10 + 10 + 1, 
    sizeof(char));
  sprintf(jwt_claim_set, "{\"iss\":\"%s\",\"scope\":\"%s\",\"aud\":\"%s\",\"exp\":%d,\"iat\":%d}", props->email_address, scope, TOKEN_AUD, exp_time_secs, issue_time_secs);

  unsigned char *encoded_jwt_header = base64url_encode(jwt_header, strlen(jwt_header));   
  unsigned char *encoded_jwt_claim_set = base64url_encode(jwt_claim_set, strlen(jwt_claim_set));

  free(jwt_header);
  free(jwt_claim_set);
  
  unsigned char *signature_input_str = (unsigned char *)calloc(strlen(".") + strlen(encoded_jwt_header) + strlen(encoded_jwt_claim_set) + 1, sizeof(char));  
  sprintf(signature_input_str, "%s.%s", encoded_jwt_header, encoded_jwt_claim_set);

  int signature_len = 257;
  unsigned char *signature = (unsigned char *)calloc(signature_len, sizeof(char));
  
  if (0 == sign_with_rsa_sha256(signature_input_str, private_key_path, signature, &signature_len)) {
    unsigned char *encoded_signature = base64url_encode(signature, signature_len);
    unsigned char *assertion = (unsigned char *)calloc(strlen(".") + strlen(signature_input_str) + strlen(encoded_signature) + 1, sizeof(char));    
    sprintf(assertion, "%s.%s", signature_input_str, encoded_signature);
    
    long connection_timeout = props->connection_timeout != NULL ? (long)atoi(props->connection_timeout) : 0;
    long timeout = props->timeout != NULL ? (long)atoi(props->timeout) : 0;   
    
    make_token_request(assertion, connection_timeout, timeout, callback, user_pointer);
    
    free(encoded_signature);
    free(assertion);
  } else {
    perror("Failed to encrypt signature");
  }

  free(encoded_jwt_claim_set);
  free(encoded_jwt_header); 
  free(signature_input_str);
}

int make_token_request(unsigned char *assertion, long connection_timeout, long timeout, size_t (*callback)(char *, size_t, size_t, void *), void *user_pointer) {
  CURL *curl =  NULL;
  CURLcode response;

  curl = curl_easy_init();

  if(!curl) {
    perror("Failed to get curl handle");
    return -1;
  }

  unsigned char *post_data = (unsigned char *)calloc(strlen(REQUEST_TOKEN_JWT_PREFIX) + strlen(assertion) + 1, sizeof(char));
  sprintf(post_data, "%s%s", REQUEST_TOKEN_JWT_PREFIX, assertion);

  curl_easy_setopt(curl, CURLOPT_URL, REQUEST_TOKEN_URL);
  curl_easy_setopt(curl, CURLOPT_POST, 1);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, callback);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, user_pointer);
  curl_easy_setopt(curl, CURLOPT_TCP_NODELAY, 1);
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0);
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
  curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
  curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, connection_timeout);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout);  

  response = curl_easy_perform(curl);

  free(post_data);
  curl_easy_cleanup(curl);
  curl_global_cleanup();

  if(response != CURLE_OK) {
    fprintf(stderr, "curl_easy_perform() failed with code %d : %s\n", response, curl_easy_strerror(response));
    return -1;
  }
  return 0;
}

unsigned char *base64url_encode(unsigned char *src, int src_len) {
  size_t result_buffer_len = 4*src_len/3 + 1;
  unsigned char *result_buffer = (unsigned char *)calloc(result_buffer_len, sizeof(char));

  hawkc_base64url_encode(src, src_len, result_buffer, &result_buffer_len);

  unsigned char *encoded_str = (unsigned char *)calloc(result_buffer_len + 1, sizeof(char));
  strncpy(encoded_str, result_buffer, result_buffer_len);
  free(result_buffer);
  return encoded_str;
}

int get_unix_time_now() {
  return (int)time(NULL);
}
