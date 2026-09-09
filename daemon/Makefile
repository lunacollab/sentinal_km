# SPDX-License-Identifier: Apache-2.0
# sentinel-daemon -- userspace consumer.
#
# Build:   make
# Clean:   make clean
# Install: make install DESTDIR= PREFIX=/usr/local

CC      ?= cc
PREFIX  ?= /usr/local
INCLUDES = -I../kernel/ipc -I.
CFLAGS  ?= -O2 -Wall -Wextra
CFLAGS  += $(INCLUDES)

SRCS := src/main.c src/genl_client.c src/ringmap_client.c src/filter.c src/parse.c src/correlate.c src/cglabel.c src/config.c src/esc.c
OBJS := $(SRCS:.c=.o)

# The CRC-32C reference is shared with the kernel module; building from the
# single source keeps the signature and the vector the daemon verifies from
# drifting. Its object lives under build/, never among the kernel sources.
BUILD := build
CRCOBJ := $(BUILD)/sentinel_crc.o

$(CRCOBJ): ../kernel/ipc/sentinel_crc.c
	mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -c -o $@ $<

BIN := sentinel-daemon

# CRCOBJ's rule below is the first in the file; without an explicit default
# goal bare `make` would stop after the CRC object. Pin the daemon binary.
.DEFAULT_GOAL := all

all: $(BIN)

$(BIN): $(OBJS) $(CRCOBJ)
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

install: $(BIN)
	install -Dm755 $(BIN) $(DESTDIR)$(PREFIX)/sbin/$(BIN)

# Sanitized build: rebuild the daemon and every unit test with ASan+UBSan
# and run the tests. Catches use-after-free / UB that -O2 alone cannot.
SAN_CFLAGS := -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer
sanitize:
	$(CC) $(CFLAGS) $(SAN_CFLAGS) -Isrc -I../kernel/ipc \
		-o /tmp/daemon_parser_test_san \
		../tests/unit/daemon_parser_test.c src/parse.c src/filter.c ../kernel/ipc/sentinel_crc.c
	ASAN_OPTIONS=detect_leaks=1 /tmp/daemon_parser_test_san
	$(CC) $(CFLAGS) $(SAN_CFLAGS) -Isrc -I../kernel/ipc \
		-o /tmp/correlator_test_san \
		../tests/unit/correlator_test.c src/correlate.c src/parse.c src/filter.c ../kernel/ipc/sentinel_crc.c
	ASAN_OPTIONS=detect_leaks=1 /tmp/correlator_test_san
	$(CC) $(CFLAGS) $(SAN_CFLAGS) -Isrc -I../kernel/ipc \
		-o /tmp/cglabel_test_san ../tests/unit/cglabel_test.c
	ASAN_OPTIONS=detect_leaks=1 /tmp/cglabel_test_san
	$(CC) $(CFLAGS) $(SAN_CFLAGS) -Isrc -I../kernel/ipc \
		-o /tmp/crc_test_san ../tests/unit/crc_test.c ../kernel/ipc/sentinel_crc.c
	ASAN_OPTIONS=detect_leaks=1 /tmp/crc_test_san
	$(CC) $(CFLAGS) $(SAN_CFLAGS) -Isrc -I../kernel/ipc \
		-o /tmp/config_test_san ../tests/unit/config_test.c src/config.c src/filter.c
	ASAN_OPTIONS=detect_leaks=1 /tmp/config_test_san
	$(CC) $(CFLAGS) $(SAN_CFLAGS) -Isrc -I../kernel/ipc \
		-o /tmp/esc_test_san ../tests/unit/esc_test.c src/esc.c
	ASAN_OPTIONS=detect_leaks=1 /tmp/esc_test_san
	$(CC) $(CFLAGS) -include ../tests/unit/sym_shim.h \
		-c -o /tmp/crc32c_asm.o ../kernel/arch/x86_64/sentinel_crc32c.S
	$(CC) $(CFLAGS) $(SAN_CFLAGS) -include ../tests/unit/sym_shim.h \
		-o /tmp/crc_asm_test_san ../tests/unit/crc_asm_test.c \
		../kernel/ipc/sentinel_crc.c /tmp/crc32c_asm.o
	ASAN_OPTIONS=detect_leaks=1 /tmp/crc_asm_test_san
	rm -f /tmp/daemon_parser_test_san /tmp/correlator_test_san /tmp/cglabel_test_san /tmp/crc_test_san /tmp/crc_asm_test_san /tmp/config_test_san /tmp/esc_test_san

# LibFuzzer harness for the parsers. Requires clang; degrades to a clear
# message when the toolchain lacks -fsanitize=fuzzer.
FUZZ_DIR := build/fuzz
fuzz:
	@command -v clang >/dev/null 2>&1 || \
		{ echo "fuzz: clang required for libFuzzer"; exit 1; }
	mkdir -p $(FUZZ_DIR)
	clang $(CFLAGS) -g -fsanitize=fuzzer,address,undefined \
		-I../kernel/ipc -Isrc \
		-o $(FUZZ_DIR)/fuzz_parse \
		../tests/fuzz/fuzz_parse.c src/parse.c src/filter.c ../kernel/ipc/sentinel_crc.c
	@echo "fuzz: built $(FUZZ_DIR)/fuzz_parse; run it against a corpus:"
	@echo "  $(FUZZ_DIR)/fuzz_parse -max_total_time=60 -jobs=4 seed"

# Code coverage (quality.yml): instrument the actual unit battery sources
# (daemon/src/*.c + the shared CRC) and emit an lcov report to
# build/coverage/. The CI job gates on the line-coverage floor.
COV := build/coverage
COV_CFLAGS := -O0 -g --coverage
coverage:
	@command -v lcov >/dev/null 2>&1 || \
		{ echo "coverage: lcov required (apt install lcov)"; exit 1; }
	@rm -rf $(COV)
	mkdir -p $(COV)
	$(CC) $(CFLAGS) $(COV_CFLAGS) -c -Isrc -I../kernel/ipc -o $(COV)/parse.o src/parse.c
	$(CC) $(CFLAGS) $(COV_CFLAGS) -c -Isrc -I../kernel/ipc -o $(COV)/filter.o src/filter.c
	$(CC) $(CFLAGS) $(COV_CFLAGS) -c -Isrc -I../kernel/ipc -o $(COV)/correlate.o src/correlate.c
	$(CC) $(CFLAGS) $(COV_CFLAGS) -c -Isrc -I../kernel/ipc -o $(COV)/config.o src/config.c
	$(CC) $(CFLAGS) $(COV_CFLAGS) -c -Isrc -I../kernel/ipc -o $(COV)/esc.o src/esc.c
	$(CC) $(CFLAGS) $(COV_CFLAGS) -c -I../kernel/ipc -o $(COV)/crc.o ../kernel/ipc/sentinel_crc.c
	# cglabel_test.c pulls src/cglabel.c in via #include, so there is no
	# linked object for it (matches the plain `test` target).
	$(CC) $(CFLAGS) $(COV_CFLAGS) -Isrc -I../kernel/ipc -o $(COV)/cglabel_test \
		../tests/unit/cglabel_test.c
	$(CC) $(CFLAGS) $(COV_CFLAGS) -Isrc -I../kernel/ipc -o $(COV)/correlator_test \
		../tests/unit/correlator_test.c $(COV)/correlate.o $(COV)/parse.o $(COV)/filter.o $(COV)/crc.o
	$(CC) $(CFLAGS) $(COV_CFLAGS) -Isrc -I../kernel/ipc -o $(COV)/daemon_parser_test \
		../tests/unit/daemon_parser_test.c $(COV)/parse.o $(COV)/filter.o $(COV)/crc.o
	$(CC) $(CFLAGS) $(COV_CFLAGS) -Isrc -I../kernel/ipc -o $(COV)/config_test \
		../tests/unit/config_test.c $(COV)/config.o $(COV)/filter.o
	$(CC) $(CFLAGS) $(COV_CFLAGS) -Isrc -I../kernel/ipc -o $(COV)/esc_test \
		../tests/unit/esc_test.c $(COV)/esc.o
	cd $(COV) && ./cglabel_test && ./correlator_test && ./daemon_parser_test && ./config_test && ./esc_test
	lcov --quiet --capture --directory $(COV) --base-directory . \
		--rc lcov_branch_coverage=1 \
		--exclude '*/tests/*' -o $(COV)/coverage.info
	genhtml --quiet --branch-coverage $(COV)/coverage.info \
		-o $(COV)/html 2>/dev/null || true
	@echo "coverage: report at build/coverage/html (lcov summary in CI quality.yml)"

clean:
	rm -f $(OBJS) $(BIN) $(CRCOBJ) ../tests/unit/daemon_parser_test ../tests/unit/cglabel_test ../tests/unit/correlator_test ../tests/unit/memchr_zero_test ../tests/unit/capture_store_test ../tests/unit/crc_test ../tests/unit/crc_asm_test ../tests/unit/config_test ../tests/unit/esc_test
	rm -rf build

test: clean
	$(CC) $(CFLAGS) -Isrc -I../kernel/ipc \
		-o ../tests/unit/daemon_parser_test \
		../tests/unit/daemon_parser_test.c src/parse.c src/filter.c ../kernel/ipc/sentinel_crc.c
	../tests/unit/daemon_parser_test
	$(CC) $(CFLAGS) -Isrc -I../kernel/ipc \
		-o ../tests/unit/cglabel_test \
		../tests/unit/cglabel_test.c
	../tests/unit/cglabel_test
	$(CC) $(CFLAGS) -Isrc -I../kernel/ipc \
		-o ../tests/unit/correlator_test \
		../tests/unit/correlator_test.c src/correlate.c src/parse.c src/filter.c ../kernel/ipc/sentinel_crc.c
	../tests/unit/correlator_test
	$(CC) $(CFLAGS) -include ../tests/unit/sym_shim.h \
		-c -o /tmp/memchr_zero_test.o ../kernel/arch/x86_64/sentinel_memchr_zero.S
	$(CC) $(CFLAGS) -o ../tests/unit/memchr_zero_test \
		../tests/unit/memchr_zero_test.c /tmp/memchr_zero_test.o
	../tests/unit/memchr_zero_test
	$(CC) $(CFLAGS) -include ../tests/unit/sym_shim.h \
		-c -o /tmp/capture_store_test.o ../kernel/arch/x86_64/sentinel_capture_store.S
	$(CC) $(CFLAGS) -o ../tests/unit/capture_store_test \
		../tests/unit/capture_store_test.c /tmp/capture_store_test.o
	../tests/unit/capture_store_test
	$(CC) $(CFLAGS) -Isrc -I../kernel/ipc \
		-o ../tests/unit/crc_test \
		../tests/unit/crc_test.c ../kernel/ipc/sentinel_crc.c
	../tests/unit/crc_test
	$(CC) $(CFLAGS) -include ../tests/unit/sym_shim.h \
		-c -o /tmp/crc32c_asm.o ../kernel/arch/x86_64/sentinel_crc32c.S
	$(CC) $(CFLAGS) -o ../tests/unit/crc_asm_test \
		../tests/unit/crc_asm_test.c ../kernel/ipc/sentinel_crc.c \
		/tmp/crc32c_asm.o
	../tests/unit/crc_asm_test || [ $$? -eq 77 ]
	$(CC) $(CFLAGS) -Isrc -I../kernel/ipc \
		-o ../tests/unit/config_test \
		../tests/unit/config_test.c src/config.c src/filter.c
	../tests/unit/config_test
	$(CC) $(CFLAGS) -Isrc -I../kernel/ipc \
		-o ../tests/unit/esc_test \
		../tests/unit/esc_test.c src/esc.c
	../tests/unit/esc_test

.PHONY: all install clean test sanitize fuzz coverage
