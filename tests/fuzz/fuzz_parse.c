// SPDX-License-Identifier: Apache-2.0
/*
 * fuzz_parse.c -- libFuzzer entry point for the daemon's message/capture
 * parsers.
 *
 * The kernel is a semi-trusted source: this harness feeds arbitrary,
 * possibly-malformed bytes into both parse entry points and the per-payload
 * validators. Memory errors and crashes here are bugs in the daemon, not the
 * kernel. Run with:
 *
 *   make -C daemon fuzz CC=clang
 *
 * or point the built binary at a corpus directory:
 *
 *   ./build/fuzz_parse -max_total_time=60 /path/to/corpus
 */
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "filter.h"
#include "parse.h"
#include "genl_compat.h"
#include "sentinel_proto.h"
#include "sentinel_crc.h"

static struct event_filter filter;

/* Scratch staging for the CRC re-stamp (see LLVMFuzzerTestOneInput).
 * Sized for the deepest plausible record; larger inputs are still parsed
 * read-only on the reject path. Force at least u64 alignment so the u32
 * crc writes land on a safe boundary. */
static union {
	uint8_t bytes[65536];
	uint64_t align;
} scratch_u;

static uint8_t *scratch = scratch_u.bytes;

/* No-op printer: the fuzzed input must never crash the dispatch path. */
static void fuzz_dispatch(const struct sentinel_event_hdr *hdr,
			  const void *payload, size_t payload_len,
			  const void *opaque)
{
	(void)hdr;
	(void)payload;
	(void)payload_len;
	(void)opaque;
}

/*
 * Self-healing CRC: the wire format carries crc32 in the header, so mutant
 * input is virtually always dropped at the integrity gate before the deeper
 * field validation runs. To keep that validation reachable, re-stamp the
 * crc32 field to match the mutated record before feeding the parser. The
 * integrity check itself is covered by the unit battery (daemon_parser_test
 * flips bits and asserts the drop); here we want the grammar, not the CRC.
 */
static void patch_ring_crc(uint8_t *data, size_t size)
{
	struct sentinel_ring_rec *rr = (struct sentinel_ring_rec *)data;
	uint32_t rec_len;
	const uint8_t *hdr;
	size_t plen;

	if (size < SENTINEL_RING_REC_HDR_SIZE)
		return;
	rec_len = rr->rec_len;
	if (rec_len < SENTINEL_RING_REC_HDR_SIZE || rec_len > size)
		return;
	hdr = (const uint8_t *)&rr->hdr;
	plen = rec_len - SENTINEL_RING_REC_HDR_SIZE;
	*(uint32_t *)(void *)(hdr + 48) =
		sentinel_crc_payload(&rr->hdr, hdr + sizeof(rr->hdr), plen);
}

static void patch_message_crc(uint8_t *data, size_t size)
{
	const struct nlmsghdr *nlh = (const struct nlmsghdr *)data;
	const uint8_t *p;
	int rem;

	if (size < sizeof(*nlh) + GENL_HDRLEN)
		return;
	if (nlh->nlmsg_len < NLMSG_HDRLEN + GENL_HDRLEN ||
	    nlh->nlmsg_len > size)
		return;
	rem = (int)(nlh->nlmsg_len - NLMSG_HDRLEN - GENL_HDRLEN);
	p = data + NLMSG_HDRLEN + GENL_HDRLEN;
	while (rem >= (int)sizeof(struct nlattr)) {
		const struct nlattr *na = (const struct nlattr *)p;

		if (na->nla_len < sizeof(struct nlattr) || na->nla_len > (unsigned)rem)
			break;
		if (na->nla_type == SENTINEL_ATTR_EVENT) {
			uint8_t *hdr = (uint8_t *)NLA_DATA(na);
			const uint8_t *payload;

			if (NLA_PAYLOAD(na) != sizeof(struct sentinel_event_hdr)) {
				rem -= NLA_ALIGN(na->nla_len);
				p += NLA_ALIGN(na->nla_len);
				continue;
			}
			payload = p + NLA_ALIGN(na->nla_len);
			rem -= NLA_ALIGN(na->nla_len);
			if (rem < (int)sizeof(struct nlattr))
				break;
			na = (const struct nlattr *)payload;
			if (na->nla_type != SENTINEL_ATTR_PAYLOAD ||
			    na->nla_len < sizeof(struct nlattr))
				break;
			*(uint32_t *)(void *)(hdr + 48) =
				sentinel_crc_payload((void *)hdr, NLA_DATA(na),
						     NLA_PAYLOAD(na));
			return;
		}
		rem -= NLA_ALIGN(na->nla_len);
		p += NLA_ALIGN(na->nla_len);
	}
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc;
	(void)argv;
	filter_init(&filter);
	return 0;
}

/* Feed the parsers read-only raw bytes (no CRC patch): oversized inputs
 * keep exercising the bounds-reject paths even though they never reach the
 * deeper validators. */
static void parse_raw(const uint8_t *data, size_t size,
		      const struct sentinel_printer *printer)
{
	size_t consumed = 0;

	sentinel_parse_capture(data, size, &consumed, &filter, printer);
	sentinel_parse_message(data, size, &filter, printer);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct sentinel_printer printer = { fuzz_dispatch, NULL };

	/*
	 * libFuzzer hands us a const buffer the harness may not write, yet
	 * the CRC re-stamp must write: stage a private copy. Parsing the
	 * staged copy keeps the entire shallow-to-deep stack reachable.
	 */
	if (size > sizeof(scratch_u.bytes)) {
		parse_raw(data, size, &printer);
		return 0;
	}
	{
		size_t consumed = 0;

		memcpy(scratch, data, size);

		/* Ring-record path: possibly-truncated packed record. */
		patch_ring_crc(scratch, size);
		sentinel_parse_capture(scratch, size, &consumed, &filter,
				       &printer);

		/* Full genl datagram path. */
		patch_message_crc(scratch, size);
		sentinel_parse_message(scratch, size, &filter, &printer);

		/* Payload validators in isolation. */
		{
			struct sentinel_execve_view v;
			struct sentinel_execve_view w;

			sentinel_execve_parse(scratch, size, &v);
			sentinel_execveat_parse(scratch, size, &w);
		}
	}
	return 0;
}
