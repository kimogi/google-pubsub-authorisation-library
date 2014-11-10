.PHONY: all clean

all: google_pubsub_tool.o

google_pubsub_tool.o: google_pubsub_tool.c google_pubsub_tool.h
	$(CC) $(CFLAGS) $(LDFLAGS) -c google_pubsub_tool.c $(LIBS)

clean:
	rm -rf *.o
