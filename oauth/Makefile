.PHONY: all clean

all: base64url.o rsa.o oauth_tool.o

base64url.o: base64url.c base64url.h
	$(CC) $(CFLAGS) $(LDFLAGS) -c base64url.c $(LIBS)

rsa.o: rsa.c rsa.h
	$(CC) $(CFLAGS) $(LDFLAGS) -c rsa.c $(LIBS)

oauth_tool.o: oauth_tool.h oauth_tool.c
	$(CC) $(CFLAGS) $(LDFLAGS) -c oauth_tool.c $(LIBS)

clean:
	rm -rf *.o
