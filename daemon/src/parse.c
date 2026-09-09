// SPDX-License-Identifier: Apache-2.0
/*
 * parse.c -- netlink/mmap event validation and decoding.
 *
 * The kernel is treated as semi-trusted input. proto_version must match and
 * every payload is bounds-checked (public enum) or size-consistent (fixed
 * structs, offsets-addressed execve blobs) before any field is dereferenced.
 * A failed parse returns -1 and emits nothing; callers decide whether that
 * is fatal or just a dropped message.
 */
#include <string.h>

#include "parse.h"
#include "genl_compat.h"
#include "sentinel_proto.h"
#include "sentinel_crc.h"

/* ------------------------------------------------------------------ */
/* offsets-addressed string blob (execve v2 / execveat)                */
/* ------------------------------------------------------------------ */
/*
 * Both struct sentinel_ev_execve and struct sentinel_ev_execveat open with
 * the same three u16 fields (path_off, args_off, argc); the fixed structure
 * differs only in its tail. So one shared validator/parser serves both,
 * parameterized by the fixed-head size the payload must start with.
 */
static int execve_blob_validate(size_t head, const void *payload, size_t len)
{
	const struct sentinel_ev_execve *ev = payload;
	size_t path_off, args_off, argc, nuls = 0;
	size_t i;

	if (len < head)
		return -1;
	path_off = ev->path_off;
	args_off = ev->args_off;
	argc = ev->argc;

	if (path_off != head)
		return -1;
	if ((size_t)args_off < (size_t)path_off + 1 || (size_t)args_off > len)
		return -1;
	if (argc > SENTINEL_ARGV_MAX_ARGS)
		return -1;

	/* path region must contain exactly one NUL, the strings start after */
	if (!memchr((const char *)payload + path_off, '\0',
		    args_off - path_off))
		return -1;

	for (i = (size_t)args_off; i < len; i++)
		if (((const char *)payload)[i] == '\0')
			nuls++;
	/* one NUL per captured argv string, no slack bytes after the last */
	if (nuls != (size_t)argc)
		return -1;
	return 0;
}

static int execve_blob_parse(size_t head, const void *payload, size_t len,
			     struct sentinel_execve_view *out)
{
	const struct sentinel_ev_execve *ev = payload;

	/* Validate before the first deref: a sub-header payload must not be
	 * interpreted as a struct. ev (== payload) is only ever read after
	 * execve_blob_validate() has certified len >= head. */
	if (execve_blob_validate(head, payload, len))
		return -1;

	{
		const char *path = (const char *)payload + ev->path_off;
		const char *blob = (const char *)payload + ev->args_off;
		size_t remain, path_len;

		path_len = strnlen(path, ev->args_off - ev->path_off);
		memcpy(out->path, path, path_len);
		out->path[path_len] = '\0';

		remain = len - ev->args_off;
		out->argc = ev->argc;
		for (int i = 0; i < ev->argc; i++) {
			size_t n = strnlen(blob, remain);
			size_t cpy = n < SENTINEL_ARGV_STR_MAX - 1 ?
					n : SENTINEL_ARGV_STR_MAX - 1;

			memcpy(out->argv[i], blob, cpy);
			out->argv[i][cpy] = '\0';
			if (n + 1 > remain)
				break;
			blob += n + 1;
			remain -= n + 1;
		}
	}
	return 0;
}

int sentinel_execve_parse(const void *payload, size_t payload_len,
			  struct sentinel_execve_view *out)
{
	return execve_blob_parse(SENTINEL_EXECVE_PATH_OFF, payload,
				 payload_len, out);
}

int sentinel_execveat_parse(const void *payload, size_t payload_len,
			    struct sentinel_execve_view *out)
{
	return execve_blob_parse(SENTINEL_EXECVEAT_PATH_OFF, payload,
				 payload_len, out);
}

/* ------------------------------------------------------------------ */
/* shared payload gate + dispatch                                      */
/* ------------------------------------------------------------------ */

static int validate_payload(const struct sentinel_event_hdr *hdr,
			    const void *payload, size_t payload_len)
{
	if (hdr->proto_version != SENTINEL_PROTO_VERSION)
		return -1;
	if (hdr->event_type <= 0 || hdr->event_type >= SENTINEL_EV__MAX)
		return -1;
	if (hdr->payload_len != payload_len)
		return -1;
	if (payload_len > SENTINEL_MAX_PAYLOAD)
		return -1;

	switch (hdr->event_type) {
	case SENTINEL_EV_EXECVE:
		return execve_blob_validate(SENTINEL_EXECVE_PATH_OFF,
					    payload, payload_len);
	case SENTINEL_EV_EXECVEAT:
		return execve_blob_validate(SENTINEL_EXECVEAT_PATH_OFF,
					    payload, payload_len);
	case SENTINEL_EV_OPENAT:
		return payload_len == sizeof(struct sentinel_ev_openat) ? 0 : -1;
	case SENTINEL_EV_CONNECT:
		return payload_len == sizeof(struct sentinel_ev_connect) ? 0 : -1;
	case SENTINEL_EV_MMAP_EXEC:
		return payload_len == sizeof(struct sentinel_ev_mmap_exec) ? 0 : -1;
	case SENTINEL_EV_MPROTECT:
		return payload_len == sizeof(struct sentinel_ev_mprotect) ? 0 : -1;
	case SENTINEL_EV_MEMFD_CREATE:
		return payload_len == sizeof(struct sentinel_ev_memfd_create) ? 0 : -1;
	case SENTINEL_EV_PTRACE:
		return payload_len == sizeof(struct sentinel_ev_ptrace) ? 0 : -1;
	case SENTINEL_EV_CLONE3:
		return payload_len == sizeof(struct sentinel_ev_clone3) ? 0 : -1;
	case SENTINEL_EV_IO_URING_ENTER:
		return payload_len == sizeof(struct sentinel_ev_io_uring_enter) ? 0 : -1;
	case SENTINEL_EV_FINIT_MODULE:
		return payload_len == sizeof(struct sentinel_ev_finit_module) ? 0 : -1;
	}
	return -1;
}

static void gate_and_dispatch(const struct sentinel_event_hdr *hdr,
			      const void *payload, size_t payload_len,
			      const struct event_filter *filter,
			      const struct sentinel_printer *out)
{
	if (validate_payload(hdr, payload, payload_len))
		return;
	if (hdr->crc32 != sentinel_crc_payload(hdr, payload, payload_len))
		return;	/* dropped as malformed, never "repaired" */
	if (filter && !filter_apply(filter, hdr))
		return;
	if (out && out->dispatch)
		out->dispatch(hdr, payload, payload_len, out->opaque);
}

/* ------------------------------------------------------------------ */
/* netlink datagram path                                               */
/* ------------------------------------------------------------------ */

int sentinel_parse_message(const void *buf, size_t len,
			   const struct event_filter *filter,
			   const struct sentinel_printer *out)
{
	const struct nlmsghdr *nlh = (const struct nlmsghdr *)buf;
	const struct nlattr *na;
	struct sentinel_event_hdr hdr;
	int rem, seen_event = 0;

	if (len < sizeof(*nlh) + GENL_HDRLEN)
		return -1;
	/* The claimed datagram length must fit the received buffer, and
	 * must at least cover the fixed headers. Only then is `rem` (the
	 * attribute region) guaranteed to stay inside the buffer: the walk
	 * below treats it as authoritative for the [na, na + rem) range. */
	if (nlh->nlmsg_len < NLMSG_HDRLEN + GENL_HDRLEN ||
	    nlh->nlmsg_len > len)
		return -1;
	rem = (int)(nlh->nlmsg_len - NLMSG_HDRLEN - GENL_HDRLEN);
	na = (const struct nlattr *)((const char *)nlh + NLMSG_HDRLEN
				     + GENL_HDRLEN);
	memset(&hdr, 0, sizeof(hdr));

	for (; NLA_OK(na, rem); na = NLA_NEXT(na, rem)) {
		if (na->nla_type == SENTINEL_ATTR_EVENT) {
			const void *data = NLA_DATA(na);

			if (NLA_PAYLOAD(na) != sizeof(hdr))
				return -1;
			memcpy(&hdr, data, sizeof(hdr));
			if (hdr.proto_version != SENTINEL_PROTO_VERSION)
				return -1;	/* ABI drift: fail loudly */
			seen_event = 1;
		} else if (na->nla_type == SENTINEL_ATTR_PAYLOAD) {
			if (!seen_event)
				return -1;
			gate_and_dispatch(&hdr, NLA_DATA(na),
					  NLA_PAYLOAD(na), filter, out);
		}
	}
	return seen_event ? 0 : -1;
}

/* ------------------------------------------------------------------ */
/* mmap ring record path                                               */
/* ------------------------------------------------------------------ */

int sentinel_parse_capture(const void *rec, size_t len, size_t *consumed,
			   const struct event_filter *filter,
			   const struct sentinel_printer *out)
{
	const struct sentinel_ring_rec *rr = rec;
	struct sentinel_event_hdr hdr;
	unsigned int rec_len;

	if (len < SENTINEL_RING_REC_HDR_SIZE)
		return -1;
	memcpy(&rec_len, &rr->rec_len, sizeof(rec_len));
	if (rec_len < SENTINEL_RING_REC_HDR_SIZE)
		return -1;
	if (rec_len > len)
		return -1;

	memcpy(&hdr, &rr->hdr, sizeof(hdr));
	/* rec_len must be exactly hdr + payload; a loose kernel would be
	 * caught here, as would an ABI drift on the record header. */
	if (hdr.proto_version != SENTINEL_PROTO_VERSION)
		return -1;
	if (rec_len != SENTINEL_RING_REC_HDR_SIZE + hdr.payload_len)
		return -1;

	if (consumed)
		*consumed = rec_len;
	gate_and_dispatch(&hdr, (const char *)rec + SENTINEL_RING_REC_HDR_SIZE,
			  hdr.payload_len, filter, out);
	return 0;
}
