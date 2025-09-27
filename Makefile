# Enhanced Makefile for PCAPture with multiple build modes
CC = gcc
CPPFLAGS = -D_GNU_SOURCE -Iinclude

# Development-friendly flags (default)
DEV_CFLAGS = -Wall -Wextra -std=c99 -g -O1
DEV_LDFLAGS = 
DEV_LIBS = 

# Production security flags
PROD_CFLAGS = -Wall -Wextra -Werror -std=c99 -pedantic \
              -Wformat=2 -Wformat-security -Wconversion -Wsign-conversion \
              -Wstrict-prototypes -Wmissing-prototypes -Wold-style-definition \
              -fstack-protector-strong -fPIE -D_FORTIFY_SOURCE=2

PROD_LDFLAGS = -pie -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack
PROD_LIBS = -lcap -lrt

# Default to development mode
CFLAGS = $(DEV_CFLAGS)
LDFLAGS = $(DEV_LDFLAGS)
LIBS = $(DEV_LIBS)

# Source files
SRC = src/main.c src/capture.c src/parser.c src/utils.c
OBJ = $(SRC:.c=.o)
TARGET = pcapture

# Build modes
DEBUG_CFLAGS = -g -O0 -DDEBUG -fsanitize=address -fsanitize=undefined

# Default target (development mode - easy compilation)
all: dev

# Development build (fast, minimal warnings)
dev: $(TARGET)
	@echo "Development build completed"

# Debug build (with sanitizers)
debug: CFLAGS = $(DEV_CFLAGS) $(DEBUG_CFLAGS)
debug: LDFLAGS += -fsanitize=address -fsanitize=undefined
debug: clean $(TARGET)
	@echo "Debug build completed"

# Production build (full security hardening)
production: CFLAGS = $(PROD_CFLAGS)
production: LDFLAGS = $(PROD_LDFLAGS)
production: LIBS = $(PROD_LIBS)
production: clean $(TARGET)
	@echo "Production build completed with full security hardening"

# Main target
$(TARGET): $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)
	@echo "Build completed: $@"
	@echo "Run with: sudo ./$@"

# Object file compilation
%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

# Install target (requires root)
install: release
	@if [ "$$(id -u)" != "0" ]; then \
		echo "Error: Installation requires root privileges. Run with sudo make install"; \
		exit 1; \
	fi
	install -m 755 $(TARGET) /usr/local/bin/
	install -m 644 README.md /usr/local/share/doc/pcapture/
	@echo "PCAPture installed to /usr/local/bin/"

# Uninstall target
uninstall:
	@if [ "$$(id -u)" != "0" ]; then \
		echo "Error: Uninstallation requires root privileges. Run with sudo make uninstall"; \
		exit 1; \
	fi
	rm -f /usr/local/bin/$(TARGET)
	rm -rf /usr/local/share/doc/pcapture/
	@echo "PCAPture uninstalled"

# Clean build artifacts
clean:
	rm -f src/*.o $(TARGET)
	rm -f core.*
	@echo "Clean completed"

# Run with default options
run: $(TARGET)
	sudo ./$(TARGET)

# Run with verbose output
run-verbose: $(TARGET)
	sudo ./$(TARGET) --verbose

# Run with packet limit
run-test: $(TARGET)
	sudo ./$(TARGET) --count 10 --verbose

# Static analysis
lint:
	@which cppcheck > /dev/null || { echo "cppcheck not installed"; exit 1; }
	cppcheck --enable=all --std=c99 --platform=unix64 \
		--suppress=missingIncludeSystem \
		--suppress=unusedFunction \
		-I include src/

# Security analysis
security-check:
	@which flawfinder > /dev/null || { echo "flawfinder not installed"; exit 1; }
	flawfinder --minlevel=1 --html src/ include/ > security_report.html
	@echo "Security report generated: security_report.html"

# Memory leak checking (requires valgrind)
memcheck: debug
	@which valgrind > /dev/null || { echo "valgrind not installed"; exit 1; }
	sudo valgrind --tool=memcheck --leak-check=full --track-origins=yes \
		--show-reachable=yes ./$(TARGET) --count 5

# Performance profiling
profile: 
	$(MAKE) CFLAGS="$(CFLAGS) -pg" $(TARGET)
	sudo ./$(TARGET) --count 100
	gprof $(TARGET) gmon.out > profile_report.txt
	@echo "Profile report generated: profile_report.txt"

# Code formatting
format:
	@which clang-format > /dev/null || { echo "clang-format not installed"; exit 1; }
	clang-format -i src/*.c include/*.h

# Create distribution tarball
dist: clean
	tar -czf pcapture-$(shell date +%Y%m%d).tar.gz \
		src/ include/ Makefile README.md

# Help target
help:
	@echo "PCAPture Build System"
	@echo "====================="
	@echo ""
	@echo "Build Modes:"
	@echo "  make dev         Development build (fast, minimal warnings) [DEFAULT]"
	@echo "  make debug       Debug build with sanitizers"
	@echo "  make production  Full security hardening (strict warnings)"
	@echo ""
	@echo "Other Targets:"
	@echo "  install      Install to /usr/local/bin (requires sudo)"
	@echo "  uninstall    Remove from /usr/local/bin (requires sudo)"
	@echo "  clean        Remove build artifacts"
	@echo "  run          Run PCAPture with sudo"
	@echo "  run-verbose  Run with verbose output"
	@echo "  run-test     Run with packet limit for testing"
	@echo "  lint         Run static code analysis"
	@echo "  security-check Run security analysis"
	@echo "  memcheck     Run memory leak detection"
	@echo "  profile      Generate performance profile"
	@echo "  format       Format code with clang-format"
	@echo "  dist         Create distribution tarball"
	@echo "  help         Show this help message"
	@echo ""
	@echo "Security Features:"
	@echo "  - Stack protection (-fstack-protector-strong)"
	@echo "  - Position Independent Executable (PIE)"
	@echo "  - Format string protection"
	@echo "  - Buffer overflow detection"
	@echo "  - RELRO and NX bit protection"

# Dependencies for object files
src/main.o: include/capture.h include/utils.h
src/capture.o: include/capture.h include/parser.h include/utils.h  
src/parser.o: include/parser.h include/utils.h
src/utils.o: include/utils.h

# Phony targets
.PHONY: all debug release clean install uninstall run run-verbose run-test \
        lint security-check memcheck profile format dist help