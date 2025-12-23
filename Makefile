CC ?= gcc
CFLAGS ?= -std=c11 -Wall -Wextra -pedantic
LDFLAGS ?=
LIBS = -lncurses -ljansson -lm

TARGET = trivytui
SRCS = main.c

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) $(LDFLAGS) $(SRCS) $(LIBS) -o $(TARGET)

clean:
	rm -f $(TARGET)
