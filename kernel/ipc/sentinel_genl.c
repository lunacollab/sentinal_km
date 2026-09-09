// SPDX-License-Identifier: GPL-2.0-only
/*
 * sentinel_genl.c -- Generic Netlink family registration, event emit, and
 *                    control-plane doit commands.
 *
 * Commands:
 *   STATS  – reply-only; current filter state + ring/bail counters.
 *   SETMASK, SETPIDS, ENABLE – mutate filter state; reply is an ack.
 *
 * Registration uses genl_split_ops (>=6.4) or legacy genl_ops (<6.4).
 * genl2 API drift is documented in docs/KERNEL_COMPAT.md.
 */
#include <linux/skbuff.h>
#include <linux/genetlink.h>
#include <linux/version.h>
#include <linux/module.h>
#include <net/genetlink.h>

#include "sentinel_proto.h"
#include "sentinel_genl.h"
#include "sentinel_ring.h"
#include "../core/sentinel_filter.h"
#include "../core/sentinel_probe.h"
#include "sentinel_ringmap.h"

#define SENTINEL_GENL_NAME		"sentinel_km"

/* Forward declaration: the family struct is defined after the doit array,
 * but sentinel_cmd_stats needs it for genlmsg_put. */
static struct genl_family sentinel_genl_family;

/* ------------------------------------------------------------------ */
/* multicast group                                                    */
/* ------------------------------------------------------------------ */

static struct genl_multicast_group sentinel_mcgrps[] = {
	[SENTINEL_GENL_MCGRP_EVENT] = { .name = "events" },
};

/* ------------------------------------------------------------------ */
/* netlink attribute policy (covers doit requests/replies)             */
/* ------------------------------------------------------------------ */

static const struct nla_policy sentinel_cmd_policy[SENTINEL_ATTR__MAX] = {
	/* The mask rides as hex text (see sentinel_proto.h): wide enough for
	 * a 1024-bit bitmap, i.e. 256 hex digits plus a NUL. */
	[SENTINEL_ATTR_MASK]   = { .type = NLA_BINARY,
				   .len  = SENTINEL_MASK_BYTES * 2 },
	[SENTINEL_ATTR_PIDS]   = { .type = NLA_NUL_STRING,
				   .len  = SENTINEL_GENL_PIDS_MAX },
	[SENTINEL_ATTR_ENABLE] = { .type = NLA_U8 },
	[SENTINEL_ATTR_UIDS]   = { .type = NLA_NUL_STRING,
				   .len  = SENTINEL_GENL_UIDS_MAX },
};

/* ------------------------------------------------------------------ */
/* doit command handlers                                               */
/* ------------------------------------------------------------------ */

static int sentinel_cmd_stats(struct sk_buff *skb, struct genl_info *info)
{
	struct sk_buff *msg;
	void *hdr;
	char pid_buf[256];
	char mask_buf[SENTINEL_MASK_BYTES * 2 + 1];
	int pid_len, mask_len;

	msg = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	hdr = genlmsg_put(msg, info->snd_portid, info->snd_seq,
			  &sentinel_genl_family, 0, SENTINEL_CMD_STATS);
	if (!hdr)
		goto nla_put_failure;

	/* The mask echo is the same hex text as the sysfs "filter" knob.
	 */
	mask_len = sentinel_filter_sysfs_mask(mask_buf, sizeof(mask_buf));
	if (mask_len < 0)
		goto nla_put_failure;

	if (nla_put_u8(msg, SENTINEL_ATTR_ENABLE,
			sentinel_filter_enabled()) ||
	    nla_put(msg, SENTINEL_ATTR_MASK, mask_len + 1, mask_buf) ||
	    nla_put_u64_64bit(msg, SENTINEL_ATTR_STATS_PUSHED,
			       sentinel_ring_pushed_total(), NLA_UNSPEC) ||
	    nla_put_u64_64bit(msg, SENTINEL_ATTR_STATS_DROPPED,
			       sentinel_ring_dropped_total(), NLA_UNSPEC) ||
	    nla_put_u64_64bit(msg, SENTINEL_ATTR_STATS_RINGMAP_DROPPED,
			       sentinel_ringmap_drop_total(), NLA_UNSPEC) ||
	    nla_put_u64_64bit(msg, SENTINEL_ATTR_STATS_BAILED,
			       sentinel_probe_bailed_total(), NLA_UNSPEC) ||
	    nla_put_u64_64bit(msg, SENTINEL_ATTR_STATS_REQUEUED,
			       sentinel_ring_requeued_total(), NLA_UNSPEC) ||
	    nla_put_u64_64bit(msg, SENTINEL_ATTR_STATS_DRAIN_NS,
			       sentinel_ring_drain_ns_total(), NLA_UNSPEC) ||
	    nla_put_u64_64bit(msg, SENTINEL_ATTR_STATS_SENT,
			       sentinel_genl_sent_total(), NLA_UNSPEC))
		goto nla_put_failure;

	memset(pid_buf, 0, sizeof(pid_buf));
	pid_len = sentinel_filter_sysfs_pids(pid_buf, sizeof(pid_buf));
	if (nla_put(msg, SENTINEL_ATTR_PIDS, pid_len + 1, pid_buf))
		goto nla_put_failure;

	memset(pid_buf, 0, sizeof(pid_buf));
	pid_len = sentinel_filter_sysfs_uids(pid_buf, sizeof(pid_buf));
	if (nla_put(msg, SENTINEL_ATTR_UIDS, pid_len + 1, pid_buf))
		goto nla_put_failure;

	genlmsg_end(msg, hdr);
	return genlmsg_reply(msg, info);

nla_put_failure:
	kfree_skb(msg);
	return -EMSGSIZE;
}

static int sentinel_cmd_setmask(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr *a = info->attrs[SENTINEL_ATTR_MASK];
	char buf[SENTINEL_MASK_BYTES * 2 + 1];
	const char *s;
	size_t slen;

	if (!a)
		return -EINVAL;
	s = nla_data(a);
	slen = strnlen(s, nla_len(a) - 1);
	if (slen >= sizeof(buf))
		return -ERANGE;
	memcpy(buf, s, slen);
	buf[slen] = '\0';
	/* Parse with the exact interpreter the sysfs "filter" knob uses, so
	 * the two control planes can never drift.
	 */
	return sentinel_filter_mask_store(buf, slen);
}

static int sentinel_cmd_setpids(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr *a = info->attrs[SENTINEL_ATTR_PIDS];
	char buf[256];
	const char *s;
	size_t slen;

	if (!a)
		return -EINVAL;

	s = nla_data(a);
	slen = strnlen(s, nla_len(a) - 1);
	if (slen >= sizeof(buf))
		return -ERANGE;
	memcpy(buf, s, slen);
	buf[slen] = '\0';

	return sentinel_filter_pids_parse(buf);
}

static int sentinel_cmd_enable(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr *a = info->attrs[SENTINEL_ATTR_ENABLE];

	if (!a)
		return -EINVAL;
	sentinel_filter_set_enabled(!!nla_get_u8(a));
	return 0;
}

static int sentinel_cmd_setuids(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr *a = info->attrs[SENTINEL_ATTR_UIDS];
	char buf[256];
	const char *s;
	size_t slen;

	if (!a)
		return -EINVAL;

	s = nla_data(a);
	slen = strnlen(s, nla_len(a) - 1);
	if (slen >= sizeof(buf))
		return -ERANGE;
	memcpy(buf, s, slen);
	buf[slen] = '\0';

	return sentinel_filter_uids_parse(buf);
}

/* ------------------------------------------------------------------ */
/* operation arrays                                                    */
/* ------------------------------------------------------------------ */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)

static struct genl_split_ops sentinel_split_ops[] = {
	{ .cmd = SENTINEL_CMD_STATS,   .flags = GENL_CMD_CAP_DO,
	  .doit = sentinel_cmd_stats, },
	{ .cmd = SENTINEL_CMD_SETMASK, .flags = GENL_CMD_CAP_DO,
	  .doit = sentinel_cmd_setmask, },
	{ .cmd = SENTINEL_CMD_SETPIDS, .flags = GENL_CMD_CAP_DO,
	  .doit = sentinel_cmd_setpids, },
	{ .cmd = SENTINEL_CMD_ENABLE,  .flags = GENL_CMD_CAP_DO,
	  .doit = sentinel_cmd_enable, },
	{ .cmd = SENTINEL_CMD_SETUIDS, .flags = GENL_CMD_CAP_DO,
	  .doit = sentinel_cmd_setuids, },
};

#else /* < 6.4: legacy genl_ops with per-op policy */

static struct genl_ops sentinel_genl_ops[] = {
	{ .cmd = SENTINEL_CMD_STATS,
	  .doit = sentinel_cmd_stats,
	  .policy = sentinel_cmd_policy,
	  .maxattr = SENTINEL_ATTR__MAX - 1, },
	{ .cmd = SENTINEL_CMD_SETMASK,
	  .doit = sentinel_cmd_setmask,
	  .policy = sentinel_cmd_policy,
	  .maxattr = SENTINEL_ATTR__MAX - 1, },
	{ .cmd = SENTINEL_CMD_SETPIDS,
	  .doit = sentinel_cmd_setpids,
	  .policy = sentinel_cmd_policy,
	  .maxattr = SENTINEL_ATTR__MAX - 1, },
	{ .cmd = SENTINEL_CMD_ENABLE,
	  .doit = sentinel_cmd_enable,
	  .policy = sentinel_cmd_policy,
	  .maxattr = SENTINEL_ATTR__MAX - 1, },
	{ .cmd = SENTINEL_CMD_SETUIDS,
	  .doit = sentinel_cmd_setuids,
	  .policy = sentinel_cmd_policy,
	  .maxattr = SENTINEL_ATTR__MAX - 1, },
};

#endif

/* ------------------------------------------------------------------ */
/* family definition                                                   */
/* ------------------------------------------------------------------ */

static struct genl_family sentinel_genl_family = {
	.name		= SENTINEL_GENL_NAME,
	.version	= SENTINEL_PROTO_VERSION,
	.maxattr	= SENTINEL_ATTR__MAX - 1,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
	.policy		= sentinel_cmd_policy,
	.resv_start_op	= SENTINEL_CMD_STATS,
	.split_ops	= sentinel_split_ops,
	.n_split_ops	= ARRAY_SIZE(sentinel_split_ops),
#else
	.ops		= sentinel_genl_ops,
	.n_ops		= ARRAY_SIZE(sentinel_genl_ops),
#endif
	.mcgrps		= sentinel_mcgrps,
	.n_mcgrps	= ARRAY_SIZE(sentinel_mcgrps),
};

/* ------------------------------------------------------------------ */
/* multicast event emit (batched)                                      */
/* ------------------------------------------------------------------ */

static atomic64_t sent_total = ATOMIC64_INIT(0);

static void genl_batch_open(struct sentinel_genl_batch *b, size_t room)
{
	struct sk_buff *skb;

	skb = genlmsg_new(room, GFP_KERNEL);
	if (!skb)
		return;
	/* genlmsg_new caps at the natural payload, so a room request over
	 * NLMSG_GOODSIZE cannot silently shrink the datagram. */
	b->genl_hdr = genlmsg_put(skb, 0, 0, &sentinel_genl_family, 0,
				  SENTINEL_CMD_EVENT);
	if (!b->genl_hdr) {
		kfree_skb(skb);
		return;
	}
	b->skb = skb;
	b->n = 0;
}

void sentinel_genl_batch_emit(struct sentinel_genl_batch *b,
			      struct sentinel_capture *cap)
{
	struct sentinel_event_hdr hdr;

	sentinel_event_hdr_fill(&hdr, cap);
	sentinel_event_hdr_sign(&hdr, cap);

retry:
	if (!b->skb) {
		genl_batch_open(b, SENTINEL_EVENT_HDR_LEN + cap->payload_len);
		if (!b->skb)
			return;
	}
	if (b->n >= SENTINEL_GENL_BATCH_MAX) {
		sentinel_genl_batch_flush(b);
		goto retry;
	}

	if (nla_put(b->skb, SENTINEL_ATTR_EVENT, sizeof(hdr), &hdr) ||
	    nla_put(b->skb, SENTINEL_ATTR_PAYLOAD, cap->payload_len,
		    cap->payload)) {
		/* The datagram is full -- ship it and put this event in a
		 * fresh one. On the failure path the batch is always non-
		 * empty, so nothing is lost. */
		sentinel_genl_batch_flush(b);
		goto retry;
	}
	b->n++;
}

int sentinel_genl_batch_flush(struct sentinel_genl_batch *b)
{
	int ret;

	if (!b->skb)
		return 0;
	if (b->n == 0) {
		kfree_skb(b->skb);
		b->skb = NULL;
		b->genl_hdr = NULL;
		return 0;
	}

	genlmsg_end(b->skb, b->genl_hdr);
	ret = genlmsg_multicast(&sentinel_genl_family, b->skb, 0,
				SENTINEL_GENL_MCGRP_EVENT, GFP_KERNEL);
	b->skb = NULL;
	b->genl_hdr = NULL;
	b->n = 0;

	if (ret == 0)
		atomic64_inc(&sent_total);
	else if (ret != -ESRCH)
		pr_debug("sentinel_km: multicast ret %d\n", ret);
	return ret;
}

u64 sentinel_genl_sent_total(void)
{
	return atomic64_read(&sent_total);
}

/* ------------------------------------------------------------------ */
/* register / unregister                                               */
/* ------------------------------------------------------------------ */

int sentinel_genl_register(void)
{
	int ret = genl_register_family(&sentinel_genl_family);

	if (ret)
		pr_err("sentinel_km: genl family register failed (%d)\n", ret);
	return ret;
}

void sentinel_genl_unregister(void)
{
	genl_unregister_family(&sentinel_genl_family);
}
