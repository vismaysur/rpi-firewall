CC = clang
CFLAGS = -Wall -Wextra
LDFLAGS = -lpcap

SRCS = sniffer.c user_rules.c
OBJS = $(SRCS:.c=.o)
HEADERS = user_rules.h

TARGET = sniffer

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
    CFLAGS += -D__APPLE__
endif

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET) $(LDFLAGS)

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

install: $(TARGET)
	cp $(TARGET) /usr/local/bin/

uninstall:
	rm -f /usr/local/bin/$(TARGET)

help:
	@echo "Available targets:"
	@echo "  all       : Build the sniffer program (default)"
	@echo "  clean     : Remove build files"
	@echo "  install   : Install the program to /usr/local/bin (requires root)"
	@echo "  uninstall : Remove the program from /usr/local/bin (requires root)"

.PHONY: all clean install uninstall help