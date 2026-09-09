// SPDX-License-Identifier: GPL-2.0-only
#ifndef _SENTINEL_GENL_H
#define _SENTINEL_GENL_H

#include <linux/types.h>
#include <linux/build_bug.h>
#include <linux/skbuff.h>

#include "sentinel_proto.h"
#include "sentinel_crc.h"

/*
 * Every event is transported as one of these, produced by a hook ret
 * handler and consumed verbatim by sentinel_genl_emit(). The header fields
 * (pid / ppid / uid / gid / timestamp / cpu / comm) are filled at capture
 * time so the ring and the wire layer never need to guess them from current
 * context.
 */
struct sentinel_capture {
	u8	event_type;
	u16	payload_len;
	u32	pid;
	u32	ppid;
	u32	uid;
	u32	gid;
	u64	timestamp_ns;
	u16	cpu;
	u8	comm[SENTINEL_TASK_COMM_MAX];
	u8	payload[SENTINEL_MAX_PAYLOAD];
} __packed;

/*
 * The capture object is a single packed blob: a fixed 45-byte header
 * followed by the payload. The whole thing is stored into the ring by
 * sentinel_capture_store(), which moves the populated header+payload prefix
 * and zero-fills the remainder. The two numbers below are shared byte-for-byte
 * between the C reference (sentinel_capture_store_c) and the x86_64 asm
 * (arch/x86_64/sentinel_capture_store.S) so a layout drift cannot happen
 * silently -- see the differential selftest in kernel/ipc/sentinel_capture.c.
 */
#define SENTINEL_CAPTURE_HDR_SIZE	offsetof(struct sentinel_capture, payload)
#define SENTINEL_CAPTURE_BYTES		(sizeof(struct sentinel_capture))

static_assert(SENTINEL_CAPTURE_HDR_SIZE == 45,
	      "capture header layout changed; update the asm store");

/*
 * Store one capture into a ring slot at dst, moving the first n_filled bytes
 * of src and zeroing the remainder of the slot. n_filled is validated to stay
 * within the object, so the asm never writes past dst+SENTINEL_CAPTURE_BYTES.
 * Returns dst. x86_64 uses the asm implementation; other arches use the C
 * reference, which is also what the selftest compares the asm against.
 */
void *sentinel_capture_store(void *dst, const void *src, size_t n_filled);

/*
 * Byte-for-byte reference implementation of the store (memcpy + memset).
 * Used as the non-x86_64 production path and, in the selftest, as the oracle
 * the asm must reproduce identically.
 */
void *sentinel_capture_store_c(void *dst, const void *src, size_t n_filled);

/*
 * Differential selftest: runs the x86_64 asm store against the C reference
 * over n_filled x alignment and requires identical output. Returns 0 on
 * success; a failure should refuse the module load. No-op off x86_64.
 */
int sentinel_capture_selftest(void);

/*
 * Fill struct sentinel_event_hdr from a capture. Shared by the netlink and
 * mmap emitters so the two transports lay out identical headers. Only the
 * crc32 field is left for sentinel_event_hdr_sign().
 */
static inline void sentinel_event_hdr_fill(struct sentinel_event_hdr *hdr,
					   const struct sentinel_capture *cap)
{
	hdr->proto_version = SENTINEL_PROTO_VERSION;
	hdr->event_type = cap->event_type;
	hdr->payload_len = cap->payload_len;
	hdr->pid = cap->pid;
	hdr->ppid = cap->ppid;
	hdr->uid = cap->uid;
	hdr->gid = cap->gid;
	hdr->timestamp_ns = cap->timestamp_ns;
	hdr->cpu = cap->cpu;
	memcpy(hdr->comm, cap->comm, sizeof(hdr->comm));
	hdr->reserved = 0;
}

/*
 * Stamp crc32 in an already-filled header: CRC-32C over the 48 header bytes
 * before crc32 plus cap->payload. Must be called after the header and payload
 * are final (payload bytes are read, never modified). The daemon verifies the
 * identical window.
 */
static inline void sentinel_event_hdr_sign(struct sentinel_event_hdr *hdr,
					   const struct sentinel_capture *cap)
{
	hdr->crc32 = sentinel_crc_payload(hdr, cap->payload, cap->payload_len);
}

/*
 * Multi-event multicast datagram. A drain worker accumulates up to
 * SENTINEL_GENL_BATCH_MAX events into one skb (repeating EVENT+PAYLOAD attr
 * pairs) and multicasts once, which turns a burst into one syscall + one skb
 * instead of one per event. BATCH_MAX is a soft bound: an event that will
 * not fit (the classic worst-case execve blob) flushes the current batch and
 * starts a fresh datagram rather than being dropped.
 */
#define SENTINEL_GENL_BATCH_MAX	16

struct sentinel_genl_batch {
	struct sk_buff	*skb;
	void		*genl_hdr;	/* genlmsg_put() handle */
	unsigned int	n;		/* events stuffed into skb so far */
};

/*
 * Append one capture to the batch, allocating and opening the skb lazily on
 * first use. Never drops an event on overflow -- it closes out the current
 * datagram and re-emits the event into a fresh one. Process context.
 */
void sentinel_genl_batch_emit(struct sentinel_genl_batch *b,
			      struct sentinel_capture *cap);

/*
 * Close out and multicast the batch. Returns 0 when the datagram went out
 * (or had no listeners / was empty); a negative errno when it failed for
 * real, which callers may use to keep the ring tail parked for a retry.
 * Also advances the "sent" counter on a successful send.
 */
int sentinel_genl_batch_flush(struct sentinel_genl_batch *b);

/*
 * Total multicast datagrams successfully sent. Surfaced in CMD_STATS and
 * sysfs "stats" so a consumer can tell "noise delivered" from "silently
 * lost": pushed - dropped vs sent is the batch-level funnel.
 */
u64 sentinel_genl_sent_total(void);

int sentinel_genl_register(void);
void sentinel_genl_unregister(void);

#endif /* _SENTINEL_GENL_H */
