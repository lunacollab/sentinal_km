// SPDX-License-Identifier: Apache-2.0
/*
 * sentinel-daemon -- userspace consumer for sentinel_km.
 *
 * Single-threaded event loop. Two mutually exclusive transports:
 *   - generic netlink multicast socket (default);
 *   - mmap ring export when --mmap is given (-EBUSY if the ring is attached).
 *
 * Both paths hand each event to the same validator/dispatch in parse.c,
 * which is independently unit-tested. The kernel is treated as a
 * semi-trusted source: proto_version is pinned and every payload is
 * bounds-checked before any field is dereferenced.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "genl_client.h"
#include "genl_compat.h"
#include "parse.h"
#include "filter.h"
#include "correlate.h"
#include "cglabel.h"
#include "ringmap_client.h"
#include "config.h"
#include "esc.h"
#include "sentinel_proto.h"

#define RECV_BUF_SIZE	(1u << 16)
#define RING_REC_SZ	(SENTINEL_RING_REC_HDR_SIZE + SENTINEL_MAX_PAYLOAD)
#define REPLY_BUF_SIZE	4096

static volatile sig_atomic_t quit_flag;

/* Control-plane helpers defined further down; prototypes for run_genl(). */
static int print_stats(struct genl_client *c);
static int ctrl_apply(struct genl_client *c, const char *spec);

static void on_signal(int sig)
{
	(void)sig;
	quit_flag = 1;
}

/* ------------------------- printers ------------------------- */

struct print_ctx {
	int json;
	int labels;
	struct correlate_state corr;
	struct cglabel_state cgl;
};

static void json_escape(const char *s)
{
	(void)esc_json(stdout, s);
}

static unsigned int be16(const unsigned char *p)
{
	return ((unsigned int)p[0] << 8) | p[1];
}

/*
 * Common process-context prefix, text form: pid/ppid/uid/gid and the exec
 * base name. comm is a fixed 16-byte wire field, possibly without a NUL, so
 * the %.16s precision bounds the read regardless of the kernel's state.
 * clabel (NULL when labels are disabled or unresolvable) is appended as the
 * resolved container label.
 */
static void text_ctx_header(const struct sentinel_event_hdr *hdr,
			    const char *clabel)
{
	printf("pid=%u ppid=%u uid=%u gid=%u comm=%.16s",
	       hdr->pid, hdr->ppid, hdr->uid, hdr->gid,
	       (const char *)hdr->comm);
	if (clabel)
		printf(" cgroup=%s", clabel);
}

/* Same prefix, JSON form. Emits up to (and including) the trailing comma
 * after "cpu", so each event case follows with its own field list. The comm
 * is NUL-terminated into a local before escaping for the same reason the
 * text form uses a precision bound. */
static void json_ctx_header(const struct sentinel_event_hdr *hdr,
			    const char *type, const char *clabel)
{
	char comm[SENTINEL_TASK_COMM_MAX + 1];

	memcpy(comm, hdr->comm, SENTINEL_TASK_COMM_MAX);
	comm[SENTINEL_TASK_COMM_MAX] = '\0';
	printf("{\"type\":\"%s\",\"pid\":%u,\"ppid\":%u,\"uid\":%u,"
	       "\"gid\":%u,\"comm\":\"",
	       type, hdr->pid, hdr->ppid, hdr->uid, hdr->gid);
	json_escape(comm);
	printf("\",\"ts\":%llu,\"cpu\":%u,",
	       (unsigned long long)hdr->timestamp_ns, hdr->cpu);
	if (clabel) {
		fputs("\"container\":\"", stdout);
		json_escape(clabel);
		fputs("\",", stdout);
	}
}

static void flush_argv_core(const struct sentinel_execve_view *v)
{
	int i;

	printf("\"args\":[");
	for (i = 0; i < v->argc; i++) {
		if (i)
			fputs(",", stdout);
		putchar('"');
		json_escape(v->argv[i]);
		putchar('"');
	}
	putchar(']');
}

static void dispatch_event(const struct sentinel_event_hdr *hdr,
			   const void *payload, size_t payload_len, const void *opaque)
{
	struct print_ctx *ctx = (struct print_ctx *)opaque;
	struct correlate_annot annot;
	const char *clabel = NULL;

	(void)payload_len;
	if (ctx->labels)
		clabel = cglabel_resolve(&ctx->cgl, hdr->pid);
	correlate_observe(&ctx->corr, hdr, payload, &annot);

	if (!ctx->json) {
		switch (hdr->event_type) {
		case SENTINEL_EV_EXECVE: {
			struct sentinel_execve_view v;
			if (sentinel_execve_parse(payload, hdr->payload_len, &v))
				return;
			printf("execve ");
			text_ctx_header(hdr, clabel);
			printf(" path=%s argc=%d", v.path, v.argc);
			for (int i = 0; i < v.argc; i++)
				printf(" arg[%d]=%s", i, v.argv[i]);
			putchar('\n');
			break;
		}
		case SENTINEL_EV_OPENAT: {
			const struct sentinel_ev_openat *ev =
				(const struct sentinel_ev_openat *)payload;
			printf("openat ");
			text_ctx_header(hdr, clabel);
			printf(" dfd=%d flags=%#x filename=%s\n",
			       ev->dfd, ev->flags, ev->filename);
			break;
		}
		case SENTINEL_EV_CONNECT: {
			const struct sentinel_ev_connect *ev =
				(const struct sentinel_ev_connect *)payload;
			printf("connect ");
			text_ctx_header(hdr, clabel);
			printf(" sockfd=%d family=%u port=%u\n",
			       ev->sockfd, ev->addr_family,
			       be16((const unsigned char *)&ev->port_be));
			break;
		}
		case SENTINEL_EV_MMAP_EXEC: {
			const struct sentinel_ev_mmap_exec *ev =
				(const struct sentinel_ev_mmap_exec *)payload;
			printf("mmap_exec ");
			text_ctx_header(hdr, clabel);
			printf(" addr=%#llx req=%#llx len=%llu "
			       "prot=%#x flags=%#x fd=%d offset=%llu",
			       (unsigned long long)ev->mapped_addr,
			       (unsigned long long)ev->req_addr,
			       (unsigned long long)ev->length, ev->prot,
			       ev->flags, ev->fd,
			       (unsigned long long)ev->offset);
			if (annot.exec_trans && annot.exec)
				printf(" [exec-trans:%s]", annot.exec->path);
			putchar('\n');
			break;
		}
		case SENTINEL_EV_MPROTECT: {
			const struct sentinel_ev_mprotect *ev =
				(const struct sentinel_ev_mprotect *)payload;
			printf("mprotect ");
			text_ctx_header(hdr, clabel);
			printf(" addr=%#llx len=%llu prot=%#x",
			       (unsigned long long)ev->addr,
			       (unsigned long long)ev->len, ev->prot);
			if (annot.exec_trans && annot.exec)
				printf(" [exec-trans:%s]", annot.exec->path);
			putchar('\n');
			break;
		}
		case SENTINEL_EV_EXECVEAT: {
			const struct sentinel_ev_execveat *ev =
				(const struct sentinel_ev_execveat *)payload;
			struct sentinel_execve_view v;
			if (sentinel_execveat_parse(payload, hdr->payload_len, &v))
				return;
			printf("execveat ");
			text_ctx_header(hdr, clabel);
			printf(" dirfd=%d flags=%#x path=%s argc=%d",
			       ev->dirfd, ev->flags, v.path, v.argc);
			for (int i = 0; i < v.argc; i++)
				printf(" arg[%d]=%s", i, v.argv[i]);
			if (annot.fileless)
				fputs(" [fileless]", stdout);
			putchar('\n');
			break;
		}
		case SENTINEL_EV_MEMFD_CREATE: {
			const struct sentinel_ev_memfd_create *ev =
				(const struct sentinel_ev_memfd_create *)payload;
			printf("memfd_create ");
			text_ctx_header(hdr, clabel);
			printf(" name=%s flags=%#x fd=%d\n", ev->name,
			       ev->flags, ev->fd);
			break;
		}
		case SENTINEL_EV_PTRACE: {
			const struct sentinel_ev_ptrace *ev =
				(const struct sentinel_ev_ptrace *)payload;
			printf("ptrace ");
			text_ctx_header(hdr, clabel);
			printf(" request=%u target=%d addr=%#llx "
			       "data=%#llx\n",
			       ev->request, ev->target_pid,
			       (unsigned long long)ev->addr,
			       (unsigned long long)ev->data);
			break;
		}
		case SENTINEL_EV_CLONE3: {
			const struct sentinel_ev_clone3 *ev =
				(const struct sentinel_ev_clone3 *)payload;
			printf("clone3 ");
			text_ctx_header(hdr, clabel);
			printf(" flags=%#llx args_size=%u exit_signal=%u\n",
			       (unsigned long long)ev->flags, ev->args_size,
			       ev->exit_signal);
			break;
		}
		case SENTINEL_EV_IO_URING_ENTER: {
			const struct sentinel_ev_io_uring_enter *ev =
				(const struct sentinel_ev_io_uring_enter *)payload;
			printf("io_uring_enter ");
			text_ctx_header(hdr, clabel);
			printf(" fd=%u to_submit=%u min_complete=%u flags=%#x "
			       "submitted=%u completed=%u\n",
			       ev->fd, ev->to_submit, ev->min_complete,
			       ev->flags, ev->submitted, ev->completed);
			break;
		}
		case SENTINEL_EV_FINIT_MODULE: {
			const struct sentinel_ev_finit_module *ev =
				(const struct sentinel_ev_finit_module *)payload;
			printf("finit_module ");
			text_ctx_header(hdr, clabel);
			printf(" fd=%d flags=%#x\n", ev->fd, ev->flags);
			break;
		}
		}
		return;
	}

	switch (hdr->event_type) {
	case SENTINEL_EV_EXECVE: {
		struct sentinel_execve_view v;
		if (sentinel_execve_parse(payload, hdr->payload_len, &v))
			return;
		json_ctx_header(hdr, "execve", clabel);
		printf("\"path\":\"");
		json_escape(v.path);
		putchar('"');
		putchar(',');
		flush_argv_core(&v);
		putchar('}');
		putchar('\n');
		break;
	}
	case SENTINEL_EV_OPENAT: {
		const struct sentinel_ev_openat *ev =
			(const struct sentinel_ev_openat *)payload;
		json_ctx_header(hdr, "openat", clabel);
		printf("\"dfd\":%d,\"flags\":%d,\"filename\":\"",
		       ev->dfd, ev->flags);
		json_escape(ev->filename);
		printf("\"}\n");
		break;
	}
	case SENTINEL_EV_CONNECT: {
		const struct sentinel_ev_connect *ev =
			(const struct sentinel_ev_connect *)payload;
		json_ctx_header(hdr, "connect", clabel);
		printf("\"sockfd\":%d,\"family\":%u,\"port\":%u}\n",
		       ev->sockfd, ev->addr_family,
		       be16((const unsigned char *)&ev->port_be));
		break;
	}
	case SENTINEL_EV_MMAP_EXEC: {
		const struct sentinel_ev_mmap_exec *ev =
			(const struct sentinel_ev_mmap_exec *)payload;
		json_ctx_header(hdr, "mmap_exec", clabel);
		printf("\"addr\":%llu,\"req\":%llu,\"len\":%llu,"
		       "\"prot\":%u,\"flags\":%u,\"fd\":%d,\"offset\":%llu",
		       (unsigned long long)ev->mapped_addr,
		       (unsigned long long)ev->req_addr,
		       (unsigned long long)ev->length, ev->prot, ev->flags,
		       ev->fd, (unsigned long long)ev->offset);
		if (annot.exec_trans && annot.exec) {
			fputs(",\"exec_trans\":true,\"known_exec\":\"", stdout);
			json_escape(annot.exec->path);
			putchar('"');
		}
		printf("}\n");
		break;
	}
	case SENTINEL_EV_MPROTECT: {
		const struct sentinel_ev_mprotect *ev =
			(const struct sentinel_ev_mprotect *)payload;
		json_ctx_header(hdr, "mprotect", clabel);
		printf("\"addr\":%llu,\"len\":%llu,\"prot\":%u",
		       (unsigned long long)ev->addr, (unsigned long long)ev->len,
		       ev->prot);
		if (annot.exec_trans && annot.exec) {
			fputs(",\"exec_trans\":true,\"known_exec\":\"", stdout);
			json_escape(annot.exec->path);
			putchar('"');
		}
		printf("}\n");
		break;
	}
	case SENTINEL_EV_EXECVEAT: {
		const struct sentinel_ev_execveat *ev =
			(const struct sentinel_ev_execveat *)payload;
		struct sentinel_execve_view v;
		if (sentinel_execveat_parse(payload, hdr->payload_len, &v))
			return;
		json_ctx_header(hdr, "execveat", clabel);
		printf("\"dirfd\":%d,\"flags\":%u,\"path\":\"",
		       ev->dirfd, ev->flags);
		json_escape(v.path);
		putchar('"');
		putchar(',');
		flush_argv_core(&v);
		if (annot.fileless)
			fputs(",\"fileless\":true", stdout);
		putchar('}');
		putchar('\n');
		break;
	}
	case SENTINEL_EV_MEMFD_CREATE: {
		const struct sentinel_ev_memfd_create *ev =
			(const struct sentinel_ev_memfd_create *)payload;
		json_ctx_header(hdr, "memfd_create", clabel);
		printf("\"name\":\"");
		json_escape((const char *)ev->name);
		printf("\",\"flags\":%u,\"fd\":%d}\n", ev->flags, ev->fd);
		break;
	}
	case SENTINEL_EV_PTRACE: {
		const struct sentinel_ev_ptrace *ev =
			(const struct sentinel_ev_ptrace *)payload;
		json_ctx_header(hdr, "ptrace", clabel);
		printf("\"request\":%u,\"target_pid\":%d,"
		       "\"addr\":%llu,\"data\":%llu}\n",
		       ev->request, ev->target_pid,
		       (unsigned long long)ev->addr,
		       (unsigned long long)ev->data);
		break;
	}
	case SENTINEL_EV_CLONE3: {
		const struct sentinel_ev_clone3 *ev =
			(const struct sentinel_ev_clone3 *)payload;
		json_ctx_header(hdr, "clone3", clabel);
		printf("\"flags\":%llu,\"args_size\":%u,"
		       "\"exit_signal\":%u,\"pidfd_ptr\":%llu}\n",
		       (unsigned long long)ev->flags, ev->args_size,
		       ev->exit_signal, (unsigned long long)ev->pidfd_ptr);
		break;
	}
	case SENTINEL_EV_IO_URING_ENTER: {
		const struct sentinel_ev_io_uring_enter *ev =
			(const struct sentinel_ev_io_uring_enter *)payload;
		json_ctx_header(hdr, "io_uring_enter", clabel);
		printf("\"fd\":%u,\"to_submit\":%u,\"min_complete\":%u,"
		       "\"flags\":%u,\"submitted\":%u,\"completed\":%u}\n",
		       ev->fd, ev->to_submit, ev->min_complete, ev->flags,
		       ev->submitted, ev->completed);
		break;
	}
	case SENTINEL_EV_FINIT_MODULE: {
		const struct sentinel_ev_finit_module *ev =
			(const struct sentinel_ev_finit_module *)payload;
		json_ctx_header(hdr, "finit_module", clabel);
		printf("\"fd\":%d,\"flags\":%u}\n", ev->fd, ev->flags);
		break;
	}
	}
}

/* ------------------------- transports ------------------------- */

static void nap_ms(long ms)
{
	struct timespec ts = { ms / 1000, (long)(ms % 1000) * 1000000L };

	nanosleep(&ts, NULL);
}

/* Re-create + re-resolve the socket. With reconnect enabled this spins
 * until the module reappears, backing off from 1s to 30s, so the daemon
 * can start before (and outlive) sentinel_km loads. Returns 0 once the
 * family is re-joined, or -1 when quit_flag was raised. */
static int genl_reconnect(struct genl_client *client)
{
	long backoff = 1000;

	genl_client_close(client);
	while (!quit_flag) {
		int ret;

		ret = genl_client_init(client);
		if (ret == 0)
			ret = genl_client_resolve(client);
		if (ret == 0) {
			fprintf(stderr, "netlink reconnected (family %u)\n",
				client->family_id);
			return 0;
		}
		fprintf(stderr, "netlink resolve retry: %s\n", strerror(-ret));
		nap_ms(backoff);
		if (backoff < 30000)
			backoff *= 2;
	}
	return -1;
}

static int run_genl(const struct event_filter *filter,
		    const struct sentinel_printer *printer, int reconnect,
		    int do_stats, const char *apply_spec, int want_events)
{
	struct genl_client client;
	char *buf;
	int ret = 0, resolve_ret;

	buf = malloc(RECV_BUF_SIZE);
	if (!buf)
		return -1;

	if (genl_client_init(&client) < 0) {
		perror("genl_client_init");
		free(buf);
		return 1;
	}
	resolve_ret = genl_client_resolve(&client);
	if (resolve_ret < 0) {
		if (!reconnect) {
			fprintf(stderr, "resolve failed (is sentinel_km "
				"loaded?): %s\n", strerror(-resolve_ret));
			goto out;
		}
		fprintf(stderr, "resolve failed; waiting for sentinel_km "
			"(-r)\n");
		if (genl_reconnect(&client) < 0)
			goto out;
	}

	if (apply_spec) {
		ret = ctrl_apply(&client, apply_spec);
		if (ret < 0)
			goto out;
	}
	if (do_stats) {
		ret = print_stats(&client);
		if (ret < 0)
			goto out;
	}

	/* Control-plane-only invocations exit once the reply is received. */
	if (!want_events)
		goto out;

	while (!quit_flag) {
		ssize_t n = recv(client.fd, buf, RECV_BUF_SIZE, 0);
		if (n == 0) {
			/* Family socket torn down by module unload. */
			if (!reconnect) {
				fprintf(stderr, "netlink EOF (module "
					"unloaded?)\n");
				break;
			}
			if (genl_reconnect(&client) < 0)
				break;
			continue;
		}
		if (n < 0) {
			if (errno == EINTR)
				continue;
			if (!reconnect) {
				perror("recv");
				break;
			}
			fprintf(stderr, "recv error (%s); re-resolving\n",
				strerror(errno));
			if (genl_reconnect(&client) < 0)
				break;
			continue;
		}
		if (sentinel_parse_message(buf, (size_t)n, filter, printer) < 0)
			fprintf(stderr, "malformed event (%zd bytes)\n", n);
	}
out:
	free(buf);
	genl_client_close(&client);
	return ret;
}

static int run_mmap(const char *ring_path, const struct event_filter *filter,
		    const struct sentinel_printer *printer)
{
	struct ringmap_client rc;
	unsigned char *scratch;
	ssize_t n;
	int rc_ret = 0;

	scratch = malloc(RING_REC_SZ);
	if (!scratch)
		return -1;
	if (ringmap_open(&rc, ring_path) < 0) {
		fprintf(stderr, "ringmap_open(%s): %s\n",
			ring_path ? ring_path : "/dev/sentinel_ring",
			strerror(errno));
		free(scratch);
		return 1;
	}
	if (ringmap_validate(&rc) < 0) {
		fprintf(stderr, "ring magic mismatch; module/kernel ABI drift?\n");
		rc_ret = 1;
		goto out;
	}

	while (!quit_flag) {
		int ready = ringmap_wait(&rc, 500);
		if (ready < 0) {
			perror("ringmap_wait");
			rc_ret = 1;
			break;
		}
		if (!ready)
			continue;
		while (!quit_flag) {
			n = ringmap_next(&rc, scratch, RING_REC_SZ);
			if (n < 0) {
				fprintf(stderr, "ring record error: %s\n",
					strerror(-n));
				continue;
			}
			if (n == 0)
				break;
			if (sentinel_parse_capture(scratch, (size_t)n, NULL,
						   filter, printer) < 0)
				fprintf(stderr, "malformed ring record (%zd)\n",
					n);
		}
	}
out:
	ringmap_close(&rc);
	free(scratch);
	return rc_ret;
}

static int run_ring_read(const char *ring_path,
			 const struct event_filter *filter,
			 const struct sentinel_printer *printer)
{
	unsigned char *scratch;
	ssize_t n;
	int fd, rc_ret = 0;

	scratch = malloc(RING_REC_SZ);
	if (!scratch)
		return -1;

	fd = ringmap_ro_open(ring_path, 0);
	if (fd < 0) {
		fprintf(stderr, "ring read_open(%s): %s\n",
			ring_path ? ring_path : "/dev/sentinel_ring",
			strerror(-fd));
		free(scratch);
		return 1;
	}

	while (!quit_flag) {
		int ready = ringmap_ro_wait(fd, 200);
		if (ready < 0) {
			perror("ring poll");
			rc_ret = 1;
			break;
		}
		if (!ready)
			continue;
		n = ringmap_ro_read(fd, scratch, RING_REC_SZ);
		if (n < 0) {
			if (n == -EAGAIN)
				continue;
			fprintf(stderr, "ring read: %s\n", strerror(-n));
			rc_ret = 1;
			break;
		}
		if (sentinel_parse_capture(scratch, (size_t)n, NULL,
					   filter, printer) < 0)
			fprintf(stderr, "malformed ring record (%zd)\n", n);
	}
	close(fd);
	free(scratch);
	return rc_ret;
}

/* ------------------------- control plane ------------------------- */

struct rx_attr {
	unsigned int len;
	const void *data;
};

static void parse_reply_attrs(const void *msg, size_t len,
			      struct rx_attr *rx, unsigned int nrx)
{
	const struct nlmsghdr *nlh = (const struct nlmsghdr *)msg;
	const struct genlmsghdr *gh = (const struct genlmsghdr *)NLMSG_DATA(nlh);
	const struct nlattr *na;
	int rem;

	rem = len - NLMSG_LENGTH(GENL_HDRLEN);
	na = (const struct nlattr *)GENLMSG_DATA(gh);
	for (; NLA_OK(na, rem); na = NLA_NEXT(na, rem)) {
		if (na->nla_type < nrx) {
			rx[na->nla_type].data = NLA_DATA(na);
			rx[na->nla_type].len = NLA_PAYLOAD(na);
		}
	}
}

static int print_stats(struct genl_client *c)
{
	char reply[REPLY_BUF_SIZE];
	struct rx_attr rx[SENTINEL_ATTR__MAX] = { 0 };
	struct nlmsghdr *nlh;
	const struct genlmsghdr *gh;
	u64 pushed, dropped, rmap_dropped, bailed, requeued, drain_ns, sent;
	int mask_len;
	size_t len;
	int ret;

	ret = genl_client_doit(c, SENTINEL_CMD_STATS, NULL,
			       reply, sizeof(reply));
	if (ret < 0)
		return ret;

	nlh = (struct nlmsghdr *)reply;
	if (nlh->nlmsg_len < NLMSG_LENGTH(GENL_HDRLEN) ||
	    nlh->nlmsg_len > sizeof(reply))
		return -EPROTO;
	len = nlh->nlmsg_len;
	gh = (struct genlmsghdr *)NLMSG_DATA(nlh);
	if (gh->cmd != SENTINEL_CMD_STATS)
		return -EPROTO;

	parse_reply_attrs(reply, len, rx, SENTINEL_ATTR__MAX);

	if (!rx[SENTINEL_ATTR_STATS_PUSHED].len)
		return -EPROTO;

	mask_len = rx[SENTINEL_ATTR_MASK].len ?
		   (int)rx[SENTINEL_ATTR_MASK].len : 0;
	pushed = *(u64 *)rx[SENTINEL_ATTR_STATS_PUSHED].data;
	dropped = *(u64 *)rx[SENTINEL_ATTR_STATS_DROPPED].data;
	rmap_dropped = *(u64 *)rx[SENTINEL_ATTR_STATS_RINGMAP_DROPPED].data;
	bailed = *(u64 *)rx[SENTINEL_ATTR_STATS_BAILED].data;
	requeued = rx[SENTINEL_ATTR_STATS_REQUEUED].len ?
		   *(u64 *)rx[SENTINEL_ATTR_STATS_REQUEUED].data : 0;
	drain_ns = rx[SENTINEL_ATTR_STATS_DRAIN_NS].len ?
		   *(u64 *)rx[SENTINEL_ATTR_STATS_DRAIN_NS].data : 0;
	sent = rx[SENTINEL_ATTR_STATS_SENT].len ?
	       *(u64 *)rx[SENTINEL_ATTR_STATS_SENT].data : 0;

	printf("sentinel stats\n"
	       "  enabled: %s\n"
	       "  mask:    %.*s\n"
	       "  pids:    %.*s"
	       "  uids:    %.*s"
	       "  ring:    pushed=%llu dropped=%llu requeued=%llu\n"
	       "  genl:    sent=%llu datagrams\n"
	       "  ringmap: dropped=%llu\n"
	       "  probe:   bailed=%llu\n"
	       "  drain:   %llu ns\n",
	       rx[SENTINEL_ATTR_ENABLE].len &&
	       *(u8 *)rx[SENTINEL_ATTR_ENABLE].data ? "on" : "off",
	       mask_len, (const char *)rx[SENTINEL_ATTR_MASK].data,
	       (int)rx[SENTINEL_ATTR_PIDS].len,
	       (const char *)rx[SENTINEL_ATTR_PIDS].data,
	       (int)rx[SENTINEL_ATTR_UIDS].len,
	       (const char *)rx[SENTINEL_ATTR_UIDS].data,
	       (unsigned long long)pushed, (unsigned long long)dropped,
	       (unsigned long long)requeued,
	       (unsigned long long)sent,
	       (unsigned long long)rmap_dropped, (unsigned long long)bailed,
	       (unsigned long long)drain_ns);
	return 0;
}

/* The mask travels as the same hex text the kernel's sysfs "filter" knob
 * parses (v8). Forward the spec verbatim; the kernel is the only interpreter
 * of "all"/"none"/"set NR"/"clr NR"/hex forms, so the daemon cannot drift on
 * bitmap semantics.
 */
static int apply_setmask(struct genl_client *c, const char *spec)
{
	const struct genl_attr attrs[] = {
		{ SENTINEL_ATTR_MASK, spec, strlen(spec) + 1 },
		{ -1, NULL, 0 },
	};

	if (!spec[0])
		return -EINVAL;
	return genl_client_doit(c, SENTINEL_CMD_SETMASK, attrs, NULL, 0);
}

static int apply_setpids(struct genl_client *c, const char *spec)
{
	const struct genl_attr attrs[] = {
		{ SENTINEL_ATTR_PIDS, spec, strlen(spec) + 1 },
		{ -1, NULL, 0 },
	};

	return genl_client_doit(c, SENTINEL_CMD_SETPIDS, attrs, NULL, 0);
}

static int apply_setuids(struct genl_client *c, const char *spec)
{
	const struct genl_attr attrs[] = {
		{ SENTINEL_ATTR_UIDS, spec, strlen(spec) + 1 },
		{ -1, NULL, 0 },
	};

	return genl_client_doit(c, SENTINEL_CMD_SETUIDS, attrs, NULL, 0);
}

static int apply_enable(struct genl_client *c, const char *spec)
{
	unsigned long v;
	char *end;
	u8 on;
	const struct genl_attr attrs[] = {
		{ SENTINEL_ATTR_ENABLE, &on, sizeof(on) },
		{ -1, NULL, 0 },
	};

	errno = 0;
	v = strtoul(spec, &end, 0);
	if (errno || *end != '\0' || v > 1)
		return -EINVAL;
	on = (u8)v;
	return genl_client_doit(c, SENTINEL_CMD_ENABLE, attrs, NULL, 0);
}

static int ctrl_apply(struct genl_client *c, const char *spec)
{
	char *copy;
	const char *tok;
	int ret, done = 0;

	copy = strdup(spec);
	if (!copy)
		return -ENOMEM;

	for (tok = strtok(copy, ","); tok; tok = strtok(NULL, ",")) {
		const char *eq = strchr(tok, '=');
		const char *val;
		size_t key_len;

		if (!eq) {
			ret = -EINVAL;
			goto out;
		}
		key_len = (size_t)(eq - tok);
		val = eq + 1;

		if (key_len == 4 && !strncmp(tok, "mask", key_len)) {
			ret = apply_setmask(c, val);
			done = 1;
		} else if (key_len == 4 && !strncmp(tok, "pids", key_len)) {
			ret = apply_setpids(c, val);
			done = 1;
		} else if (key_len == 4 && !strncmp(tok, "uids", key_len)) {
			ret = apply_setuids(c, val);
			done = 1;
		} else if (key_len == 6 && !strncmp(tok, "enable", key_len)) {
			ret = apply_enable(c, val);
			done = 1;
		} else {
			fprintf(stderr, "unknown key: %.*s\n", (int)key_len, tok);
			ret = -EINVAL;
			goto out;
		}
		if (ret < 0) {
			fprintf(stderr, "apply %.*s=%s failed: %s\n", (int)key_len,
				tok, val,
				strerror(-ret));
			goto out;
		}
	}
	if (!done) {
		ret = -EINVAL;
		goto out;
	}
	ret = 0;
out:
	free(copy);
	return ret;
}

/* ------------------------- CLI ------------------------- */

static void usage(const char *prog)
{
	fprintf(stderr,
		"usage: %s [options]\n"
		"  -p, --pid PID        filter: only events from PID (repeatable)\n"
		"  -u, --uid UID        filter: only events from UID (repeatable)\n"
		"  -t, --type EVENT     filter: execve|openat|connect|mmap|mprotect|"
			"execveat|memfd|ptrace|clone3|io_uring_enter|finit_module\n"
		"                       (repeatable)\n"
		"  -j, --json           emit newline-delimited JSON\n"
		"  -m, --mmap [PATH]    consume the mmap ring instead of netlink\n"
		"                       (default PATH: /dev/sentinel_ring)\n"
		"  -R, --ring-read[=PATH]  consume the ring via read(2) instead of\n"
		"                       netlink or mmap (default PATH as above)\n"
		"  -r, --reconnect      keep running across module reloads (netlink)\n"
		"  -s, --stats          query and print filter/ring counters (netlink)\n"
		"  -a, --apply SPEC     apply control-plane settings, e.g.\n"
		"                       mask=all or mask=clr 435 ... (v8: sysfs-"
			"style hex text),\n"
			"                       enable=1,pids=123,456,uids=1000\n"
		"  -C, --no-correlate   disable process correlation (fileless/\n"
		"                       exec-trans annotations)\n"
		"  -L, --container-labels  annotate events with the container label\n"
		"                       resolved from the task's cgroup\n"
		"  -f, --config FILE   read key=value defaults from FILE (#\n"
		"                       comments); every CLI option overrides it\n"
		"  -h, --help           this message\n",
		prog);
}

int main(int argc, char **argv)
{
	static const struct option longopts[] = {
		{ "pid", required_argument, NULL, 'p' },
		{ "uid", required_argument, NULL, 'u' },
		{ "type", required_argument, NULL, 't' },
		{ "json", no_argument, NULL, 'j' },
		{ "mmap", optional_argument, NULL, 'm' },
		{ "ring-read", optional_argument, NULL, 'R' },
		{ "reconnect", no_argument, NULL, 'r' },
		{ "stats", no_argument, NULL, 's' },
		{ "apply", required_argument, NULL, 'a' },
		{ "no-correlate", no_argument, NULL, 'C' },
		{ "container-labels", no_argument, NULL, 'L' },
		{ "config", required_argument, NULL, 'f' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, 0, NULL, 0 },
	};
#define OPTV_MAX	128
	struct { int opt; const char *arg; } optv[OPTV_MAX] = { 0 };
	struct print_ctx prctx = { .json = 0 };
	struct sentinel_printer printer = { dispatch_event, &prctx };
	struct cfg_opts cfg;
	int nopt = 0, i, ret;
	int has_m = 0, has_R = 0;
	int opt;

	cfg_init(&cfg);
	correlate_init(&prctx.corr, 1);
	cglabel_init(&prctx.cgl);
	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);

	while ((opt = getopt_long(argc, argv, "p:u:t:jm::R::rsa:CLf:h",
				  longopts, NULL)) != -1) {
		if (opt == 'h') {
			usage(argv[0]);
			return 0;
		}
		if (nopt < OPTV_MAX) {
			optv[nopt].opt = opt;
			optv[nopt].arg = optarg;
		}
		nopt++;
	}

	/* A config file is a defaults source: apply it first, then let
	 * every CLI option override it. A single ring consumer means
	 * -m and -R are mutually exclusive regardless of source. */
	for (i = 0; i < nopt; i++)
		if (optv[i].opt == 'm')
			has_m = 1;
		else if (optv[i].opt == 'R')
			has_R = 1;
	for (i = 0; i < nopt; i++)
		if (optv[i].opt == 'f' && cfg_read_file(&cfg, optv[i].arg))
			return 1;
	if (has_m && has_R) {
		fprintf(stderr, "--mmap and --ring-read are mutually "
			"exclusive (single ring consumer)\n");
		cfg_fini(&cfg);
		return 1;
	}
	for (i = 0; i < nopt; i++)
		if (optv[i].opt != 'f' && cfg_apply(&cfg, optv[i].opt,
						    optv[i].arg)) {
			fprintf(stderr, "invalid argument for -%c\n",
				optv[i].opt);
			cfg_fini(&cfg);
			return 1;
		}

	prctx.json = cfg.json;
	prctx.corr.enabled = !cfg.no_corr;
	prctx.labels = cfg.labels;

	if (cfg.stats || cfg.apply_spec) {
		if (cfg.transport) {
			fprintf(stderr, "--stats/--apply require the netlink "
				"transport, not the ring\n");
			cfg_fini(&cfg);
			return 1;
		}
	}

	if (cfg.transport == 'm')
		ret = run_mmap(cfg.ring_path, &cfg.filter, &printer);
	else if (cfg.transport == 'R')
		ret = run_ring_read(cfg.ring_path, &cfg.filter, &printer);
	else
		ret = run_genl(&cfg.filter, &printer, cfg.reconnect, cfg.stats,
			       cfg.apply_spec,
			       cfg.had_filter || prctx.json ||
			       !(cfg.stats || cfg.apply_spec));
	cfg_fini(&cfg);
	return ret;
}
