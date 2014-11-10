#include"prop.h"

#define SUCCESS 0
#define FAILURE -1

char *trim_quotes(char *str) {
	if(NULL != strstr(str, "'")) {
		char *dst = str;
		char *src = str;
		char c;

		while ((c = *src++) != '\0') {
    			if (c == '\'') {
        			*dst++ = c;
        			if ((c = *src++) == '\0')
        	   		 	break;
        			*dst++ = c;
    			}
		}
		*dst = '\0';
		str = dst;
	}
	return str;
}

int get_prop(char *file_path, char *prop, char **value, int max_lenght) {
	int res;
	FILE *file = fopen(file_path, "r");
	if(!file) {
		printf("Failed to open %s\n", file_path);	
		res = FAILURE;
	} else {
		char *key = (char *)calloc(strlen(prop) + 1, sizeof(char));
		strcpy(key, prop);
		strcat(key, "=");	
		
		size_t read_len;
		size_t len = 0;
		char *read_buf = NULL;
		while (-1 != (read_len = getline(&read_buf, &len, file))) {
			memset(read_buf + read_len - 1, '\0', 1);
			if(NULL != strstr(read_buf, key)) {
				*value = (char *)calloc(strlen(read_buf) - strlen(key) + 1, sizeof(char));
				memcpy(value[0], read_buf + strlen(key), strlen(read_buf) - strlen(key));
				*value = trim_quotes(value[0]);
				res = SUCCESS;
				break;
			}
		}
		fclose(file);
		free(key);
	}
	return res;
}
