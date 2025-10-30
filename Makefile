CC = gcc
CFLAGS = -Wall -g -Wextra -pedantic -O3
LDLIBS = -lssl -lcrypto -lpthread
SOURCES = server.c
TARGET = server

$(TARGET): $(SOURCES)
	$(CC) $(CFLAGS) $(SOURCES) -o $(TARGET) $(LDLIBS)

.PHONY: clean
clean:
	rm -f $(TARGET)
