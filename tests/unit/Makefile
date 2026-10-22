CC ?= cc
CPPFLAGS += -Icompat -I../../src
CFLAGS ?= -O2 -g
WARNINGS := -std=c11 -Wall -Wextra -Werror
SOURCES := test-map.c ../../src/dm-writeboost-map.c
HEADERS := ../../src/dm-writeboost-map.h $(wildcard compat/linux/*.h)
BUILD_DIR := .build

.PHONY: test test-sanitize clean

test: $(BUILD_DIR)/test-map
	./$<

test-sanitize: $(BUILD_DIR)/test-map-sanitize
	./$<

$(BUILD_DIR)/test-map: $(SOURCES) $(HEADERS) Makefile | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(WARNINGS) $(SOURCES) $(LDFLAGS) -o $@

$(BUILD_DIR)/test-map-sanitize: $(SOURCES) $(HEADERS) Makefile | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(WARNINGS) -O1 \
		-fsanitize=address,undefined -fno-omit-frame-pointer \
		$(SOURCES) $(LDFLAGS) -fsanitize=address,undefined -o $@

$(BUILD_DIR):
	mkdir -p $@

clean:
	rm -rf $(BUILD_DIR)
