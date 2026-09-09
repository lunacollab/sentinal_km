// SPDX-License-Identifier: Apache-2.0
#ifndef _ESC_H
#define _ESC_H
/* JSON output escaping for daemon fields.
 *
 * esc_json() escapes the NUL-terminated string s to out as a JSON string
 * body. esc_json_fixed() does the same for an exactly-n-byte buffer: it
 * stops at an embedded NUL (C-string semantics) and never reads past n --
 * the wire `comm` field is a fixed 16-byte array that is not guaranteed to
 * be NUL-terminated.
 *
 * Both escape the ASCII controls: " \ \b \f \n \r \t as their two-char
 * forms and every other byte < 0x20 plus DEL as \u00XX, so the emitted
 * stream is valid JSON regardless of the semi-trusted kernel payload.
 */
#include <stddef.h>
#include <stdio.h>

size_t esc_json(FILE *out, const char *s);
size_t esc_json_fixed(FILE *out, const char *s, size_t n);

#endif /* _ESC_H */
