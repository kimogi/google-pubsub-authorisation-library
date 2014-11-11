#root Makefile

export CC:=gcc
export LIBS := -lrt -lcurl -lcrypto -lm
export CFLAGS := -g

SUBDIRS = prop_tool google_pubsub oauth
.PHONY: subdirs $(SUBDIRS) clean

all: google_pubsub_utils

subdirs: $(SUBDIRS)	
$(SUBDIRS):	
		$(MAKE) -C $@

utils.o: utils.c
	$(CC) $(CFLAGS) $(LDFLAGS) -c utils.c $(LIBS)

google_pubsub_utils: subdirs utils.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o google_pubsub_utils utils.o google_pubsub/google_pubsub_tool.o oauth/oauth_tool.o oauth/base64url.o oauth/rsa.o prop_tool/prop.o $(LIBS)

clean:
	rm -rf google_pubsub_utils
	rm -rf *.o
	for d in $(SUBDIRS); do (cd $$d; $(MAKE) clean ); done
