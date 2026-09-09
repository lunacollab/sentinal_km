// SPDX-License-Identifier: GPL-2.0-only
/*
 * hook_connect.c -- kretprobe on connect.
 *
 * Entry: capture context + a bounded copy of the userspace sockaddr (arg1)
 * up to addrlen bytes. Ret: parse the family/port/address and enqueue.
 *
 * The sockaddr is read with the nofault copy primitive, the same one every
 * hook uses for user memory: it needs no live exception table entry in the
 * kprobe path and it cannot take page faults, so a probe firing against a
 * target that is concurrently unmap(ped) degrades to an empty event instead
 * of a kernel fault handled on the probe's behalf.
 */
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/net.h>
#include "hook_common.h"

#define SENTINEL_SOCKADDR_MAX	sizeof(struct sockaddr_storage)

struct connect_ctx {
	u64	ts;
	u32	pid;
	u16	cpu;
	int	sockfd;
	u8	addr[SENTINEL_SOCKADDR_MAX];
	u32	addrlen;
	int	probed;
	int	armed;
};

static_assert(sizeof(struct connect_ctx) <= SENTINEL_KTASK_DATA_MAX,
	      "connect entry ctx must stay within kretprobe data budget");

static struct kretprobe connect_krp;

static inline unsigned long connect_arg(struct pt_regs *regs, unsigned int n)
{
#ifdef CONFIG_X86_64
	switch (n) {
	case 0:
		return regs->di;
	case 1:
		return regs->si;
	case 2:
		return regs->dx;
	default:
		return 0;
	}
#else
	return n < 3 ? regs->regs[n] : 0;
#endif
}

static int connect_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct connect_ctx *ctx = (struct connect_ctx *)ri->data;
	const struct sockaddr __user *usockaddr =
		(const struct sockaddr __user *)connect_arg(regs, 1);
	u32 addrlen = (u32)connect_arg(regs, 2);

	ctx->armed = 0;
	ctx->probed = hook_probe_enter();
	if (!ctx->probed)
		return 0;
	if (!hook_filter_gate(SENTINEL_SC_CONNECT))
		return 0;

	ctx->armed = 1;
	ctx->ts = ktime_get_real_fast_ns();
	ctx->pid = task_pid_nr(current);
	ctx->cpu = raw_smp_processor_id();
	ctx->sockfd = (int)connect_arg(regs, 0);
	ctx->addrlen = 0;

	if (addrlen > SENTINEL_SOCKADDR_MAX)
		addrlen = SENTINEL_SOCKADDR_MAX;
	if (addrlen &&
	    hook_copy_from_user_nofault(ctx->addr, usockaddr, addrlen) ==
	    (long)addrlen)
		ctx->addrlen = addrlen;
	return 0;
}

static void connect_fill_inet(struct sentinel_ev_connect *ev,
			      const u8 *raw, u32 len)
{
	/* sockaddr_in: family(2 LE) port(2 BE) addr(4). */
	if (len >= sizeof(struct sockaddr_in)) {
		ev->port_be = (raw[2] << 8) | raw[3];
		/* Bounded by the fixed sockaddr_in layout; ev->addr is far
		 * larger, so this copy is provably in-bounds.
		 */
		memcpy(ev->addr, raw + 4, sizeof(struct in_addr));
	}
}

static int connect_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct connect_ctx *ctx = (struct connect_ctx *)ri->data;
	struct sentinel_capture *cap;
	struct sentinel_ev_connect *ev;
	sa_family_t family = AF_UNSPEC;

	if (!ctx->probed)
		return 0;
	hook_probe_leave();
	if (!ctx->armed)
		return 0;
	if (ctx->addrlen >= sizeof(sa_family_t))
		memcpy(&family, ctx->addr, sizeof(family));

	cap = sentinel_capture_alloc_gfp_atomic();
	if (!cap)
		return 0;
	memset(cap, 0, sizeof(*cap));
	cap->event_type = SENTINEL_EV_CONNECT;
	cap->pid = ctx->pid;
	cap->timestamp_ns = ctx->ts;
	cap->cpu = ctx->cpu;
	hook_capture_identity(cap);
	cap->payload_len = sizeof(struct sentinel_ev_connect);

	ev = (struct sentinel_ev_connect *)cap->payload;
	ev->sockfd = ctx->sockfd;
	ev->addr_family = family;

	if (family == AF_INET)
		connect_fill_inet(ev, ctx->addr, ctx->addrlen);
	else if (family == AF_INET6 && ctx->addrlen >= sizeof(struct sockaddr_in6)) {
		/* sockaddr_in6: family(2) port(2 BE) flowinfo(4) addr(16). */
		const u8 *raw = ctx->addr;

		ev->port_be = (raw[2] << 8) | raw[3];
		memcpy(ev->addr, raw + 8, sizeof(struct in6_addr));
	}
	/* Other families: keep addr_family set, leave addr/port blank. */

	hook_enqueue(cap);
	sentinel_capture_free(cap);
	return 0;
}

static int connect_enable(void)
{
	connect_krp.kp.symbol_name = "__sys_connect";
	connect_krp.entry_handler = connect_entry;
	connect_krp.handler = connect_ret;
	connect_krp.data_size = sizeof(struct connect_ctx);
	connect_krp.maxactive = 16;
	return register_kretprobe(&connect_krp);
}

static void connect_disable(void)
{
	unregister_kretprobe(&connect_krp);
}

const struct sentinel_hook_ops sentinel_hook_connect_ops = {
	.name		= "connect",
	.enable		= connect_enable,
	.disable	= connect_disable,
};
