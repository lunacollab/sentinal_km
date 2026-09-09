// SPDX-License-Identifier: Apache-2.0
#ifndef _PARSE_H
#define _PARSE_H

#include <stddef.h>
#include "filter.h"
#include "sentinel_proto.h"

/* Decoded execve payload (v2 offsets-addressed blob). */
struct sentinel_execve_view {
	char path[SENTINEL_PATH_MAX];
	char argv[SENTINEL_ARGV_MAX_ARGS][SENTINEL_ARGV_STR_MAX];
	int argc;
};

/* Callback invoked for each validated, unfiltered event. payload points to
 * payload_len bytes already validated against the expected struct size. */
struct sentinel_printer {
	void (*dispatch)(const struct sentinel_event_hdr *hdr,
			 const void *payload, size_t payload_len, const void *opaque);
	const void *opaque;
};

/*
 * Parse one genl multicast datagram (nlmsghdr + genlmsghdr + EVENT and
 * PAYLOAD attrs). Returns 0 on success, -1 on a malformed/foreign message.
 */
int sentinel_parse_message(const void *buf, size_t len,
			   const struct event_filter *filter,
			   const struct sentinel_printer *out);

/*
 * Parse one packed ring record (struct sentinel_ring_rec) starting at rec.
 * len is the bytes available; *consumed is set to rec_len when accepted.
 * Returns 0 on success, -1 when the record is malformed.
 */
int sentinel_parse_capture(const void *rec, size_t len, size_t *consumed,
			   const struct event_filter *filter,
			   const struct sentinel_printer *out);

/*
 * Validate + decode an execve payload into a view. Returns 0, or -1 if any
 * offset is out of range or the blob is unterminated. Re-runs the bounds
 * checks even though the parse layer already validated, because printers
 * may sit behind a test harness that bypasses it.
 */
int sentinel_execve_parse(const void *payload, size_t payload_len,
			  struct sentinel_execve_view *out);

/* execveat variant: same blob, different fixed head
 * (SENTINEL_EXECVEAT_PATH_OFF). dirfd/flags live in the payload struct and
 * are read by the printer after validation, not decoded here. */
int sentinel_execveat_parse(const void *payload, size_t payload_len,
			    struct sentinel_execve_view *out);

#endif /* _PARSE_H */
