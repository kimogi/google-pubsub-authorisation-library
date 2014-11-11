#include "google_pubsub_tool.h"

const char *SCOPE = "https://www.googleapis.com/auth/pubsub";
const char *AUTH_TOKEN_NEEDLE = "\"access_token\" : \"";
const char *TOPICS_URL = "https://www.googleapis.com/pubsub/v1beta1/topics";
const char *TOPIC_REQUEST_FORMAT = "{\"name\": \"/topics/%s/%s\"}";
const char *PUBLISH_MESSAGE_URL = "https://www.googleapis.com/pubsub/v1beta1/topics/publish";
const char *PUBLISH_MESSAGE_REQUEST_FORMAT = "{\"topic\": \"/topics/%s/%s\",\"message\": {\"data\": \"%s\"}}";

struct google_pubsub_props *props;

size_t parse_auth_response_callback(char *contents, size_t length, size_t nmemb, void *userp);
int authorized_publish_message(char *file_path, char *auth_token, long connection_timeout, long timeout);
int authorized_create_topic(char *project_id, char *topic, char *auth_token, long connection_timeout, long timeout);
void mine_file_name(char *file_path, char *file_name);
unsigned char *allocate_base64url_encoded(unsigned char *src, int src_len);

void upload_file(char *file_path, struct google_pubsub_props *google_props) { 
  props = google_props;
  request_auth_token(props, SCOPE, props->private_key_path, &parse_auth_response_callback, (void *)file_path);
}

size_t parse_auth_response_callback(char *contents, size_t length, size_t nmemb, void *userp) {  
  size_t real_size = length * nmemb;
  
  char *content_from_auth_token_needle = strstr(contents, AUTH_TOKEN_NEEDLE);
  char *content_from_auth_token = (char *)calloc(strlen(content_from_auth_token_needle) - strlen(AUTH_TOKEN_NEEDLE) + 1, sizeof(char));
  memmove(content_from_auth_token, content_from_auth_token_needle + strlen(AUTH_TOKEN_NEEDLE), strlen(content_from_auth_token_needle) - strlen(AUTH_TOKEN_NEEDLE));
  
  char *auth_token_termination_pos = strchr(content_from_auth_token, '"');   
  int auth_token_len = (int)(auth_token_termination_pos - content_from_auth_token);
  
  char *auth_token = (char *)calloc(auth_token_len + 1, sizeof(char));
  memcpy(auth_token, content_from_auth_token, auth_token_len);

  long connection_timeout = props->connection_timeout != NULL ? (long)atoi(props->connection_timeout) : 0;
  long timeout = props->timeout != NULL ? (long)atoi(props->timeout) : 0;

  if(-1 == authorized_create_topic(props->project_id, props->topic, auth_token, connection_timeout, timeout)) {
    perror("Failed to create topic");
  }
  if (-1 == authorized_publish_message((char *)userp, auth_token, connection_timeout, timeout)) {
    perror("Failed to publish massage");
  }
  
  free(content_from_auth_token);
  return real_size;
}

int authorized_create_topic(char *project_id, char *topic, char *auth_token, long connection_timeout, long timeout) {
  CURL *curl;
  CURLcode response;

  curl = curl_easy_init();
  if(!curl) {
    perror("Failed to get curl handle");
    return -1;
  }

  char *topic_request = (char *)calloc(strlen(TOPIC_REQUEST_FORMAT) + strlen(props->project_id) + strlen(props->topic) + 1, sizeof(char));
  sprintf(topic_request, TOPIC_REQUEST_FORMAT, props->project_id, props->topic);

  curl_easy_setopt(curl, CURLOPT_URL, TOPICS_URL);
  curl_easy_setopt(curl, CURLOPT_POST, 1L);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, topic_request);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, strlen(topic_request));
  curl_easy_setopt(curl, CURLOPT_TCP_NODELAY, 1L);
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0);
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
  curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
  curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, connection_timeout);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout); 

  char *auth_header = (char *)calloc(strlen(auth_token) + strlen("Authorization: Bearer ") + 1, sizeof(char));
  sprintf(auth_header, "Authorization: Bearer %s", auth_token);

  char *content_length_header = (char *)calloc(strlen("Content-Length: ") + 10 + 1, sizeof(char));
  sprintf(content_length_header, "Content-Length: %d", strlen(topic_request));

  struct curl_slist *curl_headers = NULL;
  curl_headers = curl_slist_append(curl_headers, "Content-Type: application/json");
  curl_headers = curl_slist_append(curl_headers, content_length_header);  
  curl_headers = curl_slist_append(curl_headers, auth_header);
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, curl_headers); 

  response = curl_easy_perform(curl);

  free(topic_request);
  free(content_length_header);
  free(auth_header);
  curl_slist_free_all(curl_headers);
  curl_easy_cleanup(curl);
  curl_global_cleanup();

  if(response != CURLE_OK) {
    fprintf(stderr, "curl_easy_perform() failed with code %d : %s\n", response, curl_easy_strerror(response));
    return -1;
  }
  return 0;
}

int authorized_publish_message(char *file_path, char *auth_token, long connection_timeout, long timeout) {
  CURL *curl;
  CURLcode response;

  curl = curl_easy_init();
  if(!curl) {
    perror("Failed to get curl handle");
    return -1;
  }

  FILE *file = fopen(file_path,"rb");
  if(file == NULL) {
    perror("Error while opening the file");
    return -1;
  }

  struct stat file_info;
  if(fstat(fileno(file), &file_info) != 0) {
    perror("Invalid file to load");
    return -1;
  }  

  char *file_content = (char *)calloc(file_info.st_size + 1, sizeof(char));
  fread(file_content, 1, file_info.st_size, file);
  char *message = allocate_base64url_encoded(file_content, file_info.st_size);
  char *publish_message_request = (char *)calloc(strlen(PUBLISH_MESSAGE_REQUEST_FORMAT) + strlen(props->project_id) + strlen(props->topic) + strlen(message) + 1, sizeof(char));
  sprintf(publish_message_request, PUBLISH_MESSAGE_REQUEST_FORMAT, props->project_id, props->topic, message);

  printf("REQUEST :\n%s\n", publish_message_request);

  curl_easy_setopt(curl, CURLOPT_URL, PUBLISH_MESSAGE_URL);
  curl_easy_setopt(curl, CURLOPT_POST, 1L);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, publish_message_request);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, strlen(publish_message_request));
  curl_easy_setopt(curl, CURLOPT_TCP_NODELAY, 1L);
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0);
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
  curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
  curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, connection_timeout);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout);

  char *auth_header = (char *)calloc(strlen(auth_token) + strlen("Authorization: Bearer ") + 1, sizeof(char));
  sprintf(auth_header, "Authorization: Bearer %s", auth_token);

  char *content_length_header = (char *)calloc(strlen("Content-Length: ") + 10 + 1, sizeof(char));
  sprintf(content_length_header, "Content-Length: %d", strlen(publish_message_request));

  struct curl_slist *curl_headers = NULL;
  curl_headers = curl_slist_append(curl_headers, content_length_header);
  curl_headers = curl_slist_append(curl_headers, "Content-Type: application/json");  
  curl_headers = curl_slist_append(curl_headers, auth_header);
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, curl_headers); 

  response = curl_easy_perform(curl);

  fclose(file);
  free(file_content);
  free(message);
  free(publish_message_request);
  free(content_length_header);
  free(auth_header);
  curl_slist_free_all(curl_headers);
  curl_easy_cleanup(curl);
  curl_global_cleanup();

  if(response != CURLE_OK) {
    fprintf(stderr, "curl_easy_perform() failed with code %d : %s\n", response, curl_easy_strerror(response));
    return -1;
  }
  return 0;
}

void mine_file_name(char *file_path, char *file_name) {
  char *token_pointer = strtok(file_path, "/");
  char *last_token = token_pointer;
  while (token_pointer != NULL) {
    last_token = token_pointer;
    token_pointer = strtok(NULL, "/");
  }
  memcpy(file_name, last_token, strlen(last_token));
  memset(file_name + strlen(last_token), '\0', 1);
}

unsigned char *allocate_base64url_encoded(unsigned char *src, int src_len) {
  size_t result_buffer_len = 4*src_len/3;
  unsigned char *result_buffer = (unsigned char *)calloc(result_buffer_len, sizeof(char));

  hawkc_base64url_encode(src, src_len, result_buffer, &result_buffer_len);

  unsigned char *encoded_str = (unsigned char *)calloc(result_buffer_len + 1, sizeof(char));
  strncpy(encoded_str, result_buffer, result_buffer_len);
  free(result_buffer);
  return encoded_str;
}
