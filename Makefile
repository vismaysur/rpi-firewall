# Compiler and flags
CC = clang
CFLAGS = -Wall -Wextra -Iinclude
LDFLAGS = -lpcap

# Directories
SRC_DIR = src
CORE_DIR = $(SRC_DIR)/core
MODULES_DIR = $(SRC_DIR)/modules
OBJ_DIR = obj
BIN_DIR = bin
INCLUDE_DIR = include
LOGS_DIR = logs
RULES_DIR = rules

# Source files
SRCS = $(CORE_DIR)/sniffer.c \
       $(MODULES_DIR)/user_rules.c \
       $(MODULES_DIR)/dos_detection.c 

# Object files
OBJS = $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(SRCS))

# Target executable
TARGET = $(BIN_DIR)/sniffer

# OS-specific flags
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
    CFLAGS += -D__APPLE__
endif

# Default target
all: directories $(TARGET)

# Create necessary directories
directories:
	@mkdir -p $(OBJ_DIR)/core
	@mkdir -p $(OBJ_DIR)/modules
	@mkdir -p $(BIN_DIR)
	@mkdir -p $(LOGS_DIR)/general
	@mkdir -p $(LOGS_DIR)/dos_attacks
	@mkdir -p $(RULES_DIR)

# Link the target executable
$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)

# Compile source files to object files
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean up build files
clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)

clean-logs:
	rm -rf $(LOGS_DIR)/general/*
	rm -rf $(LOGS_DIR)/dos_attacks/*

# Install the program
install: $(TARGET)
	install -d /usr/local/bin
	install $(TARGET) /usr/local/bin/

# Uninstall the program
uninstall:
	rm -f /usr/local/bin/$(notdir $(TARGET))

# Create symlinks for headers
link-headers:
	@mkdir -p $(INCLUDE_DIR)
	@ln -sf ../src/core/*.h $(INCLUDE_DIR)/
	@ln -sf ../src/modules/*.h $(INCLUDE_DIR)/

# Help target
help:
	@echo "Available targets:"
	@echo "  all        : Build the sniffer program (default)"
	@echo "  clean      : Remove build files"
	@echo "  install    : Install the program to /usr/local/bin (requires root)"
	@echo "  uninstall  : Remove the program from /usr/local/bin"
	@echo "  link-headers: Create symlinks for header files"

.PHONY: all clean install uninstall help directories link-headers