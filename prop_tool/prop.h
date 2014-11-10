#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define GOOGLE_PUBSUB_CLIENT_ID_PROP "C_GOOGLE_PUBSUB_CLIENT_ID"
#define GOOGLE_PUBSUB_EMAIL_ADDRESS_PROP "C_GOOGLE_PUBSUB_EMAIL_ADDRESS"
#define GOOGLE_PUBSUB_PRIVATE_KEY_PATH_PROP "C_GOOGLE_PUBSUB_PRIVATE_KEY_PATH"
#define GOOGLE_PUBSUB_TOPIC_PROP "C_GOOGLE_PUBSUB_TOPIC"
#define GOOGLE_PUBSUB_PROJECT_ID_PROP "C_GOOGLE_PUBSUB_PROJECT_ID"
#define GOOGLE_PUBSUB_CONNECTION_TIMEOUT_PROP "C_GOOGLE_PUBSUB_CONNECTION_TIMEOUT"
#define GOOGLE_PUBSUB_TIMEOUT_PROP "C_GOOGLE_PUBSUB_TIMEOUT"

#define GOOGLE_PUBSUB_CLIENT_ID_LEN 256
#define GOOGLE_PUBSUB_EMAIL_ADDRESS_LEN 256
#define GOOGLE_PUBSUB_PRIVATE_KEY_PATH_LEN 256
#define GOOGLE_PUBSUB_TOPIC_LEN 256
#define GOOGLE_PUBSUB_PROJECT_ID_LEN 256
#define GOOGLE_PUBSUB_CONNECTION_TIMESTAMP_LEN 10
#define GOOGLE_PUBSUB_TIMEOUT_LEN 10

struct google_pubsub_props {
  char *client_id;
  char *email_address;
  char *private_key_path;
  char *topic;
  char *project_id;
  char *connection_timeout;
  char *timeout;
};

int get_prop(char *file_path, char *prop, char **value, int max_lenght);
