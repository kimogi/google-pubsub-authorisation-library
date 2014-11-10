#prop_tool Makefile

.PHONY: all clean

all: prop.o

prop.o: prop.c prop.h
	$(CC) $(CFLAGS) $(LDFLAGS) -c prop.c

clean:
	rm -rf *.o
