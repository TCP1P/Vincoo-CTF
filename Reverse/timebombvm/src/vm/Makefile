CC ?= gcc
CFLAGS ?= -std=c99 -O2 -Wall -Wextra -Wshadow -Wconversion -Wno-sign-conversion -fno-omit-frame-pointer
LDFLAGS ?= -static

OUT := ../../dist/timebombvm

all: $(OUT)

$(OUT): timebombvm.c
	$(CC) $(CFLAGS) $(LDFLAGS) -s -o $(OUT) timebombvm.c

clean:
	rm -f $(OUT)
