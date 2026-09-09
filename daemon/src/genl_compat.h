// SPDX-License-Identifier: Apache-2.0
/*
 * genl_compat.h -- userspace stand-ins for kernel netlink attribute macros.
 *
 * <linux/netlink.h> exposes struct nlattr and NLA_ALIGN but not the iteration
 * helpers (they live in kernel's <linux/netlink.h> internal header). Define
 * the subset we use here so the daemon parses attributes identically to how
 * the kernel constructs them.
 */
#ifndef _GENL_COMPAT_H
#define _GENL_COMPAT_H

#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <stdint.h>

/* Kernel-style scalar aliases used by parse.c and genl_client.c. */
typedef uint8_t		u8;
typedef uint16_t	u16;
typedef uint32_t	u32;
typedef uint64_t	u64;

/* Kernel-internal helpers missing from userspace headers. */
#ifndef GENLMSG_DATA
#define GENLMSG_DATA(gh)	((void *)((char *)(gh) + GENL_HDRLEN))
#endif

#ifndef NLA_HDRLEN
#define NLA_HDRLEN	((int)NLA_ALIGN(sizeof(struct nlattr)))
#endif

#ifndef NLA_ALIGN
#define NLA_ALIGNTO	4
#define NLA_ALIGN(len)	(((len) + NLA_ALIGNTO - 1) & ~(NLA_ALIGNTO - 1))
#endif

#ifndef NLA_DATA
#define NLA_DATA(na)	((void *)((char *)(na) + NLA_HDRLEN))
#endif

#ifndef NLA_PAYLOAD
#define NLA_PAYLOAD(na)	((int)((na)->nla_len) - NLA_HDRLEN)
#endif

#ifndef NLA_OK
#define NLA_OK(nla, len)	\
	((len) >= (int)sizeof(struct nlattr) && \
	 (nla)->nla_len >= sizeof(struct nlattr) && \
	 (nla)->nla_len <= (len))
#endif

#ifndef NLA_NEXT
#define NLA_NEXT(nla, attrlen)	\
	((attrlen) -= NLA_ALIGN((nla)->nla_len), \
	 (struct nlattr *)((char *)(nla) + NLA_ALIGN((nla)->nla_len)))
#endif

#endif /* _GENL_COMPAT_H */
