# Makefile for trivytui - Terminal UI for Trivy scanner
#
# Targets:
#   all        - Build main binary (default)
#   test       - Build and run unit tests
#   check      - Alias for test
#   install    - Install to /usr/local/bin (or PREFIX)
#   altinstall - Install to /opt/trivytui/bin (or ALT_PREFIX)
#   packages   - Build RPM and DEB packages (requires build-packages.sh)
#   clean      - Remove build artifacts
#
# Variables:
#   CC         - C compiler (default: gcc)
#   CFLAGS     - Compiler flags
#   PREFIX     - Install prefix for 'make install' (default: /usr/local)
#   ALT_PREFIX - Install prefix for 'make altinstall' (default: /opt/trivytui)
#   VERSION    - Package version for 'make packages' (default: 0.0.0)

CC ?= gcc
CFLAGS ?= -std=c11 -Wall -Wextra -pedantic
LDFLAGS ?=
LIBS = -lncurses -ljansson -lm

TARGET = trivytui
TEST_TARGET = test_trivytui
SRCS = main.c
TEST_SRCS = test_trivytui.c
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
ALT_PREFIX ?= /opt/$(TARGET)
ALT_BINDIR ?= $(ALT_PREFIX)/bin

# Version detection: Git tags → hardcoded fallback → manual override
# Usage: make                    (uses git tags or 0.9.3)
#        make VERSION=1.0.0      (manual override)
#        make packages VERSION=1.0.0
GIT_VERSION := $(shell git describe --tags --abbrev=0 2>/dev/null | sed 's/^v//')
VERSION ?= $(if $(GIT_VERSION),$(GIT_VERSION),0.9.3)

.PHONY: all clean install altinstall test check packages show-version

all: $(TARGET)

# Helper target to show detected version
show-version:
	@echo "Detected version: $(VERSION)"
	@echo "Git version: $(if $(GIT_VERSION),$(GIT_VERSION),(none - using fallback))"
	@echo ""
	@echo "To set manually: make VERSION=1.0.0"

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -DAPP_VERSION=\"$(VERSION)\" $(LDFLAGS) $(SRCS) $(LIBS) -o $(TARGET)

$(TEST_TARGET): $(TEST_SRCS)
	$(CC) $(CFLAGS) -o $(TEST_TARGET) $(TEST_SRCS) -lm

test:
	@echo "Running unit tests..."
	@$(MAKE) -B $(TEST_TARGET)
	@chmod +x $(TEST_TARGET)
	./$(TEST_TARGET)

check: test

install: $(TARGET)
	install -d $(BINDIR)
	install -m 0755 $(TARGET) $(BINDIR)/$(TARGET)

altinstall: $(TARGET)
	install -d $(ALT_BINDIR)
	install -m 0755 $(TARGET) $(ALT_BINDIR)/$(TARGET)

clean:
	rm -f $(TARGET) $(TEST_TARGET)

packages:
	@echo "Building RPM and DEB packages..."
	@if [ ! -f build-packages.sh ]; then \
		echo "Error: build-packages.sh not found"; \
		exit 1; \
	fi
	@chmod +x build-packages.sh
	@./build-packages.sh $(VERSION)
