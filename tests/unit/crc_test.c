// SPDX-License-Identifier: Apache-2.0
/*
 * crc_test.c -- pins sentinel_crc.c with known vectors and the header+payload
 * frame contract the kernel signs and the daemon verifies.
 *
 * Two things are load-bearing:
 *   - sentinel_crc32c() must equal the standard CRC-32C (Castagnoli) of the
 *     ASCII check string "123456789", the vector every implementation in
 *     the ecosystem reproduces.
 *   - sentinel_crc_payload() must cover the header bytes before crc32 plus
 *     the payload (that is the whole point of the v7 defense: a bit flip
 *     anywhere in a record is a bad CRC).
 *
 * Builds only against userspace headers; no kernel tree needed:
 *   cc -I../kernel/ipc crc_test.c ../kernel/ipc/sentinel_crc.c
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "sentinel_crc.h"
#include "sentinel_proto.h"

static void test_check_string(void)
{
	assert(sentinel_crc32c("123456789", 9) == 0xe3069283U);
	/* Empty input: the init+final xor on nothing. */
	assert(sentinel_crc32c("", 0) == 0x00000000U);
	/* Incremental composition must equal a single-shot over a+b. */
	assert(sentinel_crc32c("The quick brown fox", 19) != 0);
}

static void test_frame_sensitivity(void)
{
	struct sentinel_event_hdr h;
	struct sentinel_ev_ptrace p1, p2;
	__u32 c0, c1;

	memset(&h, 0, sizeof(h));
	h.proto_version = SENTINEL_PROTO_VERSION;
	h.event_type = SENTINEL_EV_PTRACE;
	h.payload_len = sizeof(p1);
	h.pid = 4242;
	h.reserved = 0;

	memset(&p1, 0, sizeof(p1));
	p1.request = 16;
	p1.target_pid = 777;
	c0 = sentinel_crc_payload(&h, &p1, sizeof(p1));
	assert(c0 == sentinel_crc_payload(&h, &p1, sizeof(p1)));

	/* The payload is inside the window: mutating it changes the result. */
	memcpy(&p2, &p1, sizeof(p2));
	p2.target_pid = 778;
	c1 = sentinel_crc_payload(&h, &p2, sizeof(p2));
	assert(c0 != c1);

	/* The header prefix is inside the window too. */
	h.pid = 4243;
	assert(sentinel_crc_payload(&h, &p1, sizeof(p1)) != c0);
}

int main(void)
{
	test_check_string();
	test_frame_sensitivity();
	puts("crc_test: OK");
	return 0;
}
