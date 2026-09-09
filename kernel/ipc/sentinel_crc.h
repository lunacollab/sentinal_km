/* SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0 */
/*
 * sentinel_crc.h -- CRC-32C (Castagnoli) primitives shared by the kernel
 *                   module and the userspace daemon.
 *
 * Peer to sentinel_proto.h: this header must compile unmodified on both
 * sides so the kernel signs a record with exactly the value the daemon
 * verifies. The kernel includes it as a normal kernel header; the daemon
 * compiles sentinel_crc.c directly (see daemon/Makefile).
 */
#ifndef _SENTINEL_CRC_H
#define _SENTINEL_CRC_H

/* Compiles against <linux/types.h> on both sides, like sentinel_proto.h. */
#include <linux/types.h>

/*
 * Standard CRC-32C (iSCSI / Castagnoli): poly 0x1EDC6F41, reflected, with
 * the bitwise init/final xor used by the kernel's crc32c() and the
 * legacy crc() helpers (0xffffffff both ways). This matches the value the
 * kernel's own crc32c() hardware path produces, so a record the module
 * signs on x86_64 with the SSE4.2 crc32 instruction verifies identically on
 * a machine without it, and in the daemon. See the differential vector test.
 * Returns the raw CRC; apply the final xor (or leave it to the helper that
 * ors it in) -- sentinel_crc_payload does.
 */
extern __u32 sentinel_crc32c(void const *data, unsigned long len);

/*
 * CRC-32C over the packed header+payload frame the wire carries: the 48
 * header bytes before crc32 plus the payload. crc_hdr points at
 * struct sentinel_event_hdr; the function skips the trailing crc32 field
 * itself, so the producer stamps in place over bytes [0..48) and the
 * consumer re-checks the same bytes. Word-at-a-time where alignment allows;
 * byte-granular otherwise. Neither pointer may be NULL when len > 0.
 */
extern __u32 sentinel_crc_payload(void const *crc_hdr, void const *payload,
				  unsigned long payload_len);

/*
 * Module init / differential-selftest entry points. sentinel_crc_init()
 * selects the x86_64 SSE4.2 path behind a static key when the CPU has it
 * (no-op elsewhere); sentinel_crc_selftest() then proves the asm equals the
 * table reference -- the module refuses to load on mismatch. Userspace
 * builds compile the no-op stubs.
 */
extern int sentinel_crc_init(void);
extern int sentinel_crc_selftest(void);

#if defined(__KERNEL__) && defined(CONFIG_X86_64)
/*
 * Streaming seed fold in assembly (arch/x86_64/sentinel_crc32c.S): folds
 * len bytes into the running CRC and returns it without a final xor. This
 * is the building block behind sentinel_crc_payload(); the daemon cannot
 * use it, only the kernel can, hence the kernel-only guard.
 */
extern __u32 sentinel_crc32c_seed(__u32 crc, const void *p,
				  unsigned long len);
#endif /* __KERNEL__ && CONFIG_X86_64 */

#endif /* _SENTINEL_CRC_H */
