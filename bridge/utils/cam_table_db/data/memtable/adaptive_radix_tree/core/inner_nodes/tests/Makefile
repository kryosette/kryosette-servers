CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -g
TARGET = test_node4
SOURCES = test_node4.c node4.c
HEADERS = node4.h

# If you have smemset as a separate library
SMEMSET_DIR = third-party/smemset
CFLAGS += -I$(SMEMSET_DIR)/include
LDFLAGS += -L$(SMEMSET_DIR)/lib -lsmemset

$(TARGET): $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCES) $(LDFLAGS)

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: run clean