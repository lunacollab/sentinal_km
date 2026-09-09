// SPDX-License-Identifier: Apache-2.0
/*
 * esc.c -- JSON output escaping (see esc.h).
 *
 * The kernel packets that reach these strings are semi-trusted, so every
 * byte is either structural (escaped) or printable: control bytes < 0x20
 * and DEL never reach the stream raw. Non-NUL-terminated wire fields are
 * honored via the fixed-length entry point.
 */
#include <stdint.h>
#include <stdio.h>

#include "esc.h"

static void esc_byte(FILE *out, unsigned char c)
{
	static const char hex[] = "0123456789abcdef";

	switch (c) {
	case '"':  fputs("\\\"", out); break;
	case '\\': fputs("\\\\", out); break;
	case '\b': fputs("\\b", out); break;
	case '\f': fputs("\\f", out); break;
	case '\n': fputs("\\n", out); break;
	case '\r': fputs("\\r", out); break;
	case '\t': fputs("\\t", out); break;
	default:
		fprintf(out, "\\u00%c%c", hex[c >> 4], hex[c & 0xf]);
		break;
	}
}

/* Emit up to n bytes of s, stopping at the first NUL; returns the number
 * of bytes consumed (including a terminating NUL, should the caller need
 * the delta to count progress). */
static size_t esc_core(FILE *out, const char *s, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++) {
		unsigned char c = (unsigned char)s[i];

		if (c == '\0') {
			i++;
			break;
		}
		if (c == '"' || c == '\\' || c < 0x20 || c == 0x7f)
			esc_byte(out, c);
		else
			fputc(c, out);
	}
	return i;
}

size_t esc_json(FILE *out, const char *s)
{
	return esc_core(out, s, SIZE_MAX);
}

size_t esc_json_fixed(FILE *out, const char *s, size_t n)
{
	return esc_core(out, s, n);
}
