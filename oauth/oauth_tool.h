#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <curl/curl.h>
#include "base64url.h"
#include "rsa.h"
#include "../prop_tool/prop.h"

void request_auth_token(struct google_pubsub_props *props, const char *scope, const char *private_key_path, size_t (*callback)(char *, size_t, size_t, void *), void *user_pointer);
