CC ?= gcc
CFLAGS ?= -std=c11 -Wall -Wextra -pedantic
LDFLAGS ?=
LIBS = -lncurses -ljansson -lm

TARGET = trivytui
SRCS = main.c
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
ALT_PREFIX ?= /opt/$(TARGET)
ALT_BINDIR ?= $(ALT_PREFIX)/bin

.PHONY: all clean install altinstall

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) $(LDFLAGS) $(SRCS) $(LIBS) -o $(TARGET)

install: $(TARGET)
	install -d $(BINDIR)
	install -m 0755 $(TARGET) $(BINDIR)/$(TARGET)

altinstall: $(TARGET)
	install -d $(ALT_BINDIR)
	install -m 0755 $(TARGET) $(ALT_BINDIR)/$(TARGET)

clean:
	rm -f $(TARGET)
