#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "../oauth/oauth_tool.h"

void upload_file(char *file_path, struct google_pubsub_props *props);
