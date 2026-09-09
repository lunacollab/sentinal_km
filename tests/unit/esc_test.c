// SPDX-License-Identifier: Apache-2.0
/*
 * esc_test.c -- unit tests for the JSON escaper.
 *
 * Verifies the structural escapes, the \u00XX hardening for control bytes
 * and DEL, and that esc_json_fixed() honors a fixed-width buffer that is
 * not NUL-terminated without over-reading.
 *
 * Builds only against userspace headers:
 *   cc -Isrc esc_test.c ../src/esc.c
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "esc.h"

static int checks;

#define CHECK(cond)							\
	do {								\
		if (!(cond)) {						\
			fprintf(stderr, "line %d: CHECK(%s) failed\n", \
				__LINE__, #cond);			\
			return 1;					\
		}							\
		checks++;						\
	} while (0)

static char *escape(const char *s)
{
	static char buf[256];
	FILE *fp = tmpfile();
	char *r;

	assert(fp != NULL);
	esc_json(fp, s);
	fflush(fp);
	rewind(fp);
	r = fgets(buf, sizeof(buf), fp);
	if (!r)
		buf[0] = '\0';
	fclose(fp);
	return buf;
}

static char *escape_fixed(const char *s, size_t n)
{
	static char buf[256];
	FILE *fp = tmpfile();
	char *r;

	assert(fp != NULL);
	esc_json_fixed(fp, s, n);
	fflush(fp);
	rewind(fp);
	r = fgets(buf, sizeof(buf), fp);
	if (!r)
		buf[0] = '\0';
	fclose(fp);
	return buf;
}

static int test_basic(void)
{
	CHECK(!strcmp(escape("plain"), "plain"));
	CHECK(!strcmp(escape("a\"b"), "a\\\"b"));
	CHECK(!strcmp(escape("a\\b"), "a\\\\b"));
	CHECK(!strcmp(escape("x\ny"), "x\\ny"));
	CHECK(!strcmp(escape("\r"), "\\r"));
	CHECK(!strcmp(escape("\t"), "\\t"));
	CHECK(!strcmp(escape("\b"), "\\b"));
	CHECK(!strcmp(escape("\f"), "\\f"));
	return 0;
}

static int test_controls(void)
{
	CHECK(!strcmp(escape("\x01"), "\\u0001"));
	CHECK(!strcmp(escape("\x1b\x01\x00"), "\\u001b\\u0001"));
	CHECK(!strcmp(escape("\x7f"), "\\u007f"));
	CHECK(!strcmp(escape("\x00"), ""));
	CHECK(!strcmp(escape("a\x00" "b"), "a"));
	CHECK(!strcmp(escape("\x0a\x1f"), "\\n\\u001f"));
	return 0;
}

static int test_fixed(void)
{
	const char raw[4] = { 'a', 'b', '"', 'c' };	/* no NUL */

	CHECK(!strcmp(escape_fixed(raw, 4), "ab\\\"c"));
	CHECK(!strcmp(escape_fixed("\x01\xff" "ab", 4), "\\u0001\xff" "ab"));
	/* Embedded NUL stops the fixed read like %.Ns does. */
	CHECK(!strcmp(escape_fixed("hi\x00rest", 8), "hi"));
	/* Zero-length is a no-op even with garbage beyond. */
	CHECK(!strcmp(escape_fixed(raw, 0), ""));
	return 0;
}

int main(void)
{
	int ret = 0;

	ret |= test_basic();
	ret |= test_controls();
	ret |= test_fixed();
	printf("esc_test: %d checks passed\n", checks);
	return ret;
}
