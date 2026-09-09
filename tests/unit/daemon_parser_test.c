// SPDX-License-Identifier: Apache-2.0
/*
 * daemon_parser_test.c -- unit tests for the shared event parser.
 *
 * Exercises both transports through the same validator:
 *   - sentinel_parse_message() on synthetic genl multicast datagrams;
 *   - sentinel_parse_capture() on synthetic mmap ring records.
 *
 * Builds only against userspace headers; no kernel tree needed:
 *   cc -I../kernel/ipc -I../src daemon_parser_test.c ../src/parse.c ../src/filter.c
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <linux/netlink.h>

#include "parse.h"
#include "genl_compat.h"
#include "sentinel_proto.h"
#include "sentinel_crc.h"

static struct sentinel_event_hdr last_hdr_store;
static const struct sentinel_event_hdr *last_hdr;
static const void *last_payload;
static size_t last_plen;

struct test_counts {
	int dispatched;
	int last_type;
	int bad;
};

static void test_dispatch(const struct sentinel_event_hdr *hdr,
			  const void *payload, size_t payload_len, const void *opaque)
{
	struct test_counts *tc = (struct test_counts *)opaque;

	tc->dispatched++;
	tc->last_type = hdr->event_type;
	/* Copy the header: the parser hands the printer a pointer into its
	 * own stack frame which is only valid during the callback. */
	last_hdr_store = *hdr;
	last_hdr = &last_hdr_store;
	last_payload = payload;
	last_plen = payload_len;
}

/* ABI sanity: these are load-bearing on both sides of the wire. */
_Static_assert(sizeof(struct sentinel_event_hdr) == 52, "hdr must be 52");
_Static_assert(SENTINEL_EVENT_HDR_CRC_OFF == 48, "crc must sit at 48");
_Static_assert(sizeof(struct sentinel_ev_execve) == 6, "ev_execve must be 6");
_Static_assert(sizeof(struct sentinel_ev_mprotect) == 24,
	       "ev_mprotect must be 24");
_Static_assert(sizeof(struct sentinel_ring_rec) == 56, "ring rec must be 56");
_Static_assert(SENTINEL_EXECVE_PATH_OFF == 6, "path off must be 6");
_Static_assert(sizeof(struct sentinel_ev_execveat) == 14,
	       "ev_execveat must be 14");
_Static_assert(SENTINEL_EXECVEAT_PATH_OFF == 14, "execveat path off must be 14");
_Static_assert(sizeof(struct sentinel_ev_memfd_create) == 28,
	       "ev_memfd_create must be 28");
_Static_assert(sizeof(struct sentinel_ev_ptrace) == 24,
	       "ev_ptrace must be 24");
_Static_assert(sizeof(struct sentinel_ev_clone3) == 24,
	       "ev_clone3 must be 24");
_Static_assert(sizeof(struct sentinel_ev_io_uring_enter) == 32,
	       "ev_io_uring_enter must be 32 in v8");
_Static_assert(sizeof(struct sentinel_ev_finit_module) == 8,
	       "ev_finit_module must be 8");
_Static_assert(SENTINEL_MASK_BYTES == SENTINEL_MASK_BITS / 8,
	       "mask bytes must match mask bits");
_Static_assert(SENTINEL_EV_FINIT_MODULE == 11, "finit_module must be ev 11");

/* Build a v2 execve blob: [fixed hdr][path\0][arg0\0 arg1\0 ...]. */
static size_t build_execve_payload(char *out, size_t cap, const char *path,
				   char *const *argv, int argc)
{
	struct sentinel_ev_execve ev;
	size_t p;

	(void)cap;
	ev.path_off = sizeof(ev);
	p = ev.path_off;
	strcpy(out + p, path);
	p += strlen(path) + 1;
	ev.args_off = (unsigned short)p;
	ev.argc = (unsigned short)argc;
	for (int i = 0; i < argc; i++) {
		size_t n = strlen(argv[i]);

		memcpy(out + p, argv[i], n + 1);
		p += n + 1;
	}
	memcpy(out, &ev, sizeof(ev));
	return p;
}

/* Build an execveat blob: [fixed hdr][path\0][arg0\0 arg1\0 ...]. */
static size_t build_execveat_payload(char *out, size_t cap, const char *path,
				     char *const *argv, int argc,
				     int dirfd, unsigned int flags)
{
	struct sentinel_ev_execveat ev;
	size_t p;

	(void)cap;
	ev.path_off = sizeof(ev);
	p = ev.path_off;
	strcpy(out + p, path);
	p += strlen(path) + 1;
	ev.args_off = (unsigned short)p;
	ev.argc = (unsigned short)argc;
	ev.dirfd = dirfd;
	ev.flags = flags;
	for (int i = 0; i < argc; i++) {
		size_t n = strlen(argv[i]);

		memcpy(out + p, argv[i], n + 1);
		p += n + 1;
	}
	memcpy(out, &ev, sizeof(ev));
	return p;
}

/* Build a fake genl multicast datagram, mirroring sentinel_genl_emit(). */
static size_t build_msg(char *buf, size_t buflen, unsigned char proto_ver,
			unsigned char type, size_t payload_len,
			const void *payload)
{
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	struct genlmsghdr *gh;
	struct nlattr *na_event;
	struct nlattr *na_payload;
	struct sentinel_event_hdr hdr;

	memset(buf, 0, buflen);
	nlh->nlmsg_len = NLMSG_HDRLEN + GENL_HDRLEN;
	nlh->nlmsg_type = 0x10;
	gh = (struct genlmsghdr *)(buf + NLMSG_HDRLEN);
	gh->cmd = 0;

	hdr.proto_version = proto_ver;
	hdr.event_type = type;
	hdr.payload_len = (unsigned short)payload_len;
	hdr.pid = 4242;
	hdr.ppid = 2000;
	hdr.uid = 1000;
	hdr.gid = 1001;
	memcpy(hdr.comm, "ls", 2);
	hdr.timestamp_ns = 1234567890ULL;
	hdr.cpu = 3;
	hdr.reserved = 0;
	hdr.crc32 = 0;
	hdr.crc32 = sentinel_crc_payload(&hdr, payload, payload_len);

	na_event = (struct nlattr *)(buf + nlh->nlmsg_len);
	na_event->nla_type = SENTINEL_ATTR_EVENT;
	na_event->nla_len = NLA_HDRLEN + sizeof(hdr);
	memcpy(NLA_DATA(na_event), &hdr, sizeof(hdr));
	nlh->nlmsg_len += NLA_ALIGN(na_event->nla_len);

	na_payload = (struct nlattr *)(buf + nlh->nlmsg_len);
	na_payload->nla_type = SENTINEL_ATTR_PAYLOAD;
	na_payload->nla_len = NLA_HDRLEN + payload_len;
	if (payload_len)
		memcpy(NLA_DATA(na_payload), payload, payload_len);
	nlh->nlmsg_len += NLA_ALIGN(na_payload->nla_len);

	return nlh->nlmsg_len;
}

/* Build a multi-event (batched) datagram: N repeating EVENT+PAYLOAD pairs,
 * mirroring sentinel_genl_batch_emit(). */
static size_t build_msg_batch(char *buf, size_t buflen, unsigned int n,
			      unsigned char type, size_t payload_len,
			      const void *payload)
{
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	struct genlmsghdr *gh;
	struct sentinel_event_hdr hdr;
	unsigned int k;

	memset(buf, 0, buflen);
	nlh->nlmsg_len = NLMSG_HDRLEN + GENL_HDRLEN;
	nlh->nlmsg_type = 0x10;
	gh = (struct genlmsghdr *)(buf + NLMSG_HDRLEN);
	gh->cmd = 0;

	for (k = 0; k < n; k++) {
		struct nlattr *na;

		hdr.proto_version = SENTINEL_PROTO_VERSION;
		hdr.event_type = type;
		hdr.payload_len = (unsigned short)payload_len;
		hdr.pid = 4242;
		hdr.ppid = 2000;
		hdr.uid = 1000;
		hdr.gid = 1001;
		memcpy(hdr.comm, "ls", 2);
		hdr.timestamp_ns = 1234567890ULL + k;
		hdr.cpu = 3;
		hdr.reserved = 0;
		hdr.crc32 = 0;
		hdr.crc32 = sentinel_crc_payload(&hdr, payload, payload_len);

		na = (struct nlattr *)(buf + nlh->nlmsg_len);
		na->nla_type = SENTINEL_ATTR_EVENT;
		na->nla_len = NLA_HDRLEN + sizeof(hdr);
		memcpy(NLA_DATA(na), &hdr, sizeof(hdr));
		nlh->nlmsg_len += NLA_ALIGN(na->nla_len);

		na = (struct nlattr *)(buf + nlh->nlmsg_len);
		na->nla_type = SENTINEL_ATTR_PAYLOAD;
		na->nla_len = NLA_HDRLEN + payload_len;
		memcpy(NLA_DATA(na), payload, payload_len);
		nlh->nlmsg_len += NLA_ALIGN(na->nla_len);
	}
	return nlh->nlmsg_len;
}

static void test_valid_execve(void)
{
	char buf[1024];
	char payload[256];
	char *argv[] = { "/bin/ls", "-l", NULL };
	struct test_counts tc = { 0 };
	struct sentinel_printer p = { test_dispatch, &tc };
	struct sentinel_execve_view v;
	struct event_filter f;
	size_t plen, n;
	int ret;

	filter_init(&f);
	plen = build_execve_payload(payload, sizeof(payload), "/bin/ls",
				    argv, 2);
	n = build_msg(buf, sizeof(buf), SENTINEL_PROTO_VERSION,
		      SENTINEL_EV_EXECVE, plen, payload);
	ret = sentinel_parse_message(buf, n, &f, &p);

	assert(ret == 0);
	assert(tc.dispatched == 1);
	assert(tc.last_type == SENTINEL_EV_EXECVE);

	/* v6 context quartet must survive the wire untouched. */
	assert(last_hdr->ppid == 2000);
	assert(last_hdr->uid == 1000);
	assert(last_hdr->gid == 1001);
	assert(!strncmp((const char *)last_hdr->comm, "ls", 2));

	assert(sentinel_execve_parse(last_payload, last_plen, &v) == 0);
	assert(!strcmp(v.path, "/bin/ls"));
	assert(v.argc == 2);
	assert(!strcmp(v.argv[0], "/bin/ls"));
	assert(!strcmp(v.argv[1], "-l"));
}

static void test_bad_proto_version(void)
{
	char buf[1024];
	char payload[256];
	char *argv[] = { NULL };
	struct test_counts tc = { 0 };
	struct sentinel_printer p = { test_dispatch, &tc };
	struct event_filter f;
	size_t plen, n;
	int ret;

	filter_init(&f);
	plen = build_execve_payload(payload, sizeof(payload), "/bin/true",
				    argv, 0);
	n = build_msg(buf, sizeof(buf), SENTINEL_PROTO_VERSION + 1,
		      SENTINEL_EV_EXECVE, plen, payload);
	ret = sentinel_parse_message(buf, n, &f, &p);

	assert(ret == -1);
	assert(tc.dispatched == 0);
}

static void test_bad_execve_offsets(void)
{
	char buf[1024];
	char payload[256];
	char *argv[] = { NULL };
	struct test_counts tc = { 0 };
	struct sentinel_printer p = { test_dispatch, &tc };
	struct event_filter f;
	size_t plen, n;
	int ret;

	filter_init(&f);
	plen = build_execve_payload(payload, sizeof(payload), "/bin/true",
				    argv, 0);
	/* args_off beyond the payload => must be rejected in-flight. */
	((struct sentinel_ev_execve *)payload)->args_off = 0xffff;

	n = build_msg(buf, sizeof(buf), SENTINEL_PROTO_VERSION,
		      SENTINEL_EV_EXECVE, plen, payload);
	ret = sentinel_parse_message(buf, n, &f, &p);

	assert(ret == 0);		/* message well-formed... */
	assert(tc.dispatched == 0);	/* ...but the event is rejected */
}

static void test_valid_connect(void)
{
	char buf[1024];
	struct test_counts tc = { 0 };
	struct sentinel_printer p = { test_dispatch, &tc };
	struct sentinel_ev_connect ev;
	struct event_filter f;
	size_t n;
	int ret;

	memset(&ev, 0, sizeof(ev));
	ev.sockfd = 5;
	ev.addr_family = 2;
	ev.port_be = 0x1f90; /* 8080 */
	filter_init(&f);
	n = build_msg(buf, sizeof(buf), SENTINEL_PROTO_VERSION,
		      SENTINEL_EV_CONNECT, sizeof(ev), &ev);
	ret = sentinel_parse_message(buf, n, &f, &p);

	assert(ret == 0);
	assert(tc.dispatched == 1);
	assert(tc.last_type == SENTINEL_EV_CONNECT);
}

static void test_valid_mmap_exec(void)
{
	char buf[1024];
	struct test_counts tc = { 0 };
	struct sentinel_printer p = { test_dispatch, &tc };
	struct sentinel_ev_mmap_exec ev;
	struct event_filter f;
	size_t n;
	int ret;

	memset(&ev, 0, sizeof(ev));
	ev.mapped_addr = 0x7f0000001000ULL;
	ev.req_addr = 0;
	ev.length = 4096;
	ev.prot = 5; /* PROT_READ|PROT_EXEC */
	ev.flags = 0x22; /* MAP_PRIVATE|MAP_ANONYMOUS */
	ev.fd = -1;
	filter_init(&f);
	n = build_msg(buf, sizeof(buf), SENTINEL_PROTO_VERSION,
		      SENTINEL_EV_MMAP_EXEC, sizeof(ev), &ev);
	ret = sentinel_parse_message(buf, n, &f, &p);

	assert(ret == 0);
	assert(tc.dispatched == 1);
	assert(tc.last_type == SENTINEL_EV_MMAP_EXEC);
}

static void test_valid_mprotect(void)
{
	char buf[1024];
	struct test_counts tc = { 0 };
	struct sentinel_printer p = { test_dispatch, &tc };
	struct sentinel_ev_mprotect ev;
	struct event_filter f;
	size_t n;
	int ret;

	memset(&ev, 0, sizeof(ev));
	ev.addr = 0x7f0000001000ULL;
	ev.len = 0x3000;
	ev.prot = 5; /* PROT_READ|PROT_EXEC */
	filter_init(&f);
	n = build_msg(buf, sizeof(buf), SENTINEL_PROTO_VERSION,
		      SENTINEL_EV_MPROTECT, sizeof(ev), &ev);
	ret = sentinel_parse_message(buf, n, &f, &p);

	assert(ret == 0);
	assert(tc.dispatched == 1);
	assert(tc.last_type == SENTINEL_EV_MPROTECT);
}

static void test_mprotect_bad_size(void)
{
	char buf[1024];
	struct test_counts tc = { 0 };
	struct sentinel_printer p = { test_dispatch, &tc };
	struct sentinel_ev_mprotect ev;
	struct event_filter f;
	size_t n;
	int ret;

	memset(&ev, 0, sizeof(ev));
	filter_init(&f);
	/* Truncated payload: the dispatcher must refuse the size check. */
	n = build_msg(buf, sizeof(buf), SENTINEL_PROTO_VERSION,
		      SENTINEL_EV_MPROTECT, sizeof(ev) - 4, &ev);
	ret = sentinel_parse_message(buf, n, &f, &p);

	assert(ret == 0);		/* message well-formed... */
	assert(tc.dispatched == 0);	/* ...but the event is rejected */
}

static void test_valid_execveat(void)
{
	char buf[1024];
	char payload[256];
	char *argv[] = { "-l", NULL };
	struct test_counts tc = { 0 };
	struct sentinel_printer p = { test_dispatch, &tc };
	struct sentinel_execve_view v;
	struct sentinel_ev_execveat *ev;
	struct event_filter f;
	size_t plen, n;
	int ret;

	filter_init(&f);
	plen = build_execveat_payload(payload, sizeof(payload), "/bin/ls",
				      argv, 1, -100, 0x1000 /* AT_EMPTY_PATH */);
	n = build_msg(buf, sizeof(buf), SENTINEL_PROTO_VERSION,
		      SENTINEL_EV_EXECVEAT, plen, payload);
	ret = sentinel_parse_message(buf, n, &f, &p);

	assert(ret == 0);
	assert(tc.dispatched == 1);
	assert(tc.last_type == SENTINEL_EV_EXECVEAT);

	ev = (struct sentinel_ev_execveat *)last_payload;
	assert(ev->dirfd == -100);
	assert(ev->flags == 0x1000);
	assert(sentinel_execveat_parse(last_payload, last_plen, &v) == 0);
	assert(!strcmp(v.path, "/bin/ls"));
	assert(v.argc == 1);
	assert(!strcmp(v.argv[0], "-l"));
}

static void test_execveat_bad_size(void)
{
	char buf[1024];
	char payload[256];
	char *argv[] = { NULL };
	struct test_counts tc = { 0 };
	struct sentinel_printer p = { test_dispatch, &tc };
	struct event_filter f;
	size_t plen, n;
	int ret;

	filter_init(&f);
	plen = build_execveat_payload(payload, sizeof(payload), "/bin/true",
				      argv, 0, -100, 0);
	/* Truncated fixed head: path_off must still equal 14 and the offsets
	 * must fit, so a 2-byte truncation of the struct must be refused. */
	n = build_msg(buf, sizeof(buf), SENTINEL_PROTO_VERSION,
		      SENTINEL_EV_EXECVEAT, plen - 2, payload);
	ret = sentinel_parse_message(buf, n, &f, &p);

	assert(ret == 0);		/* message well-formed... */
	assert(tc.dispatched == 0);	/* ...but the event is rejected */
}

static void test_valid_memfd_create(void)
{
	char buf[1024];
	struct test_counts tc = { 0 };
	struct sentinel_printer p = { test_dispatch, &tc };
	struct sentinel_ev_memfd_create ev;
	struct event_filter f;
	size_t n;
	int ret;

	memset(&ev, 0, sizeof(ev));
	strncpy((char *)ev.name, "staged", sizeof(ev.name));
	ev.name[sizeof(ev.name) - 1] = '\0';
	ev.flags = 1; /* MFD_CLOEXEC */
	ev.fd = 7;
	filter_init(&f);
	n = build_msg(buf, sizeof(buf), SENTINEL_PROTO_VERSION,
		      SENTINEL_EV_MEMFD_CREATE, sizeof(ev), &ev);
	ret = sentinel_parse_message(buf, n, &f, &p);

	assert(ret == 0);
	assert(tc.dispatched == 1);
	assert(tc.last_type == SENTINEL_EV_MEMFD_CREATE);
	assert(!strcmp((const char *)
		       ((struct sentinel_ev_memfd_create *)last_payload)->name,
		       "staged"));
	/* v7 fd identity key survives the wire intact (incl. failure sign). */
	assert(((struct sentinel_ev_memfd_create *)last_payload)->fd == 7);
}

static void test_memfd_bad_size(void)
{
	char buf[1024];
	struct test_counts tc = { 0 };
	struct sentinel_printer p = { test_dispatch, &tc };
	struct sentinel_ev_memfd_create ev;
	struct event_filter f;
	size_t n;
	int ret;

	memset(&ev, 0, sizeof(ev));
	filter_init(&f);
	n = build_msg(buf, sizeof(buf), SENTINEL_PROTO_VERSION,
		      SENTINEL_EV_MEMFD_CREATE, sizeof(ev) - 4, &ev);
	ret = sentinel_parse_message(buf, n, &f, &p);

	assert(ret == 0);		/* message well-formed... */
	assert(tc.dispatched == 0);	/* ...but the event is rejected */
}

static void test_message_bad_crc(void)
{
	char buf[1024];
	char payload[256];
	char *argv[] = { "/bin/true", NULL };
	struct test_counts tc = { 0 };
	struct sentinel_printer p = { test_dispatch, &tc };
	struct event_filter f;
	size_t plen, n;
	int ret;

	filter_init(&f);
	plen = build_execve_payload(payload, sizeof(payload), "/bin/true",
				    argv, 0);
	n = build_msg(buf, sizeof(buf), SENTINEL_PROTO_VERSION,
		      SENTINEL_EV_EXECVE, plen, payload);

	/* Flip a header body byte (pid), leaving the envelope well-formed:
	 * the CRC gate must reject the event -- never "repair" it -- while
	 * the message still parses (returns 0). */
	((unsigned char *)buf)[NLMSG_HDRLEN + GENL_HDRLEN + NLA_HDRLEN + 4]
		^= 0x01;
	ret = sentinel_parse_message(buf, n, &f, &p);
	assert(ret == 0);
	assert(tc.dispatched == 0);
}

static void test_ring_bad_crc(void)
{
	char buf[1024];
	char payload[256];
	char *argv[] = { "/bin/true", NULL };
	struct test_counts tc = { 0 };
	struct sentinel_printer p = { test_dispatch, &tc };
	struct sentinel_ring_rec *rr = (struct sentinel_ring_rec *)buf;
	struct event_filter f;
	size_t plen, consumed = 0;
	int ret;

	filter_init(&f);
	plen = build_execve_payload(payload, sizeof(payload), "/bin/true",
				    argv, 0);
	memset(buf, 0, sizeof(buf));
	rr->rec_len = (unsigned int)(sizeof(*rr) + plen);
	rr->hdr.proto_version = SENTINEL_PROTO_VERSION;
	rr->hdr.event_type = SENTINEL_EV_EXECVE;
	rr->hdr.payload_len = (unsigned short)plen;
	rr->hdr.pid = 4242;
	memcpy(rr->hdr.comm, "true", 4);
	rr->hdr.timestamp_ns = 42ULL;
	memcpy(buf + sizeof(*rr), payload, plen);
	rr->hdr.crc32 = sentinel_crc_payload(&rr->hdr, payload, plen);

	/* Corrupt the payload after signing: CRC must reject the record. */
	((unsigned char *)buf)[sizeof(*rr)] ^= 0xff;
	ret = sentinel_parse_capture(buf, sizeof(*rr) + plen, &consumed,
				     &f, &p);
	assert(ret == 0);
	assert(tc.dispatched == 0);
}

static void test_valid_ptrace(void)
{
	char buf[1024];
	struct test_counts tc = { 0 };
	struct sentinel_printer p = { test_dispatch, &tc };
	struct sentinel_ev_ptrace ev;
	struct event_filter f;
	size_t n;
	int ret;

	memset(&ev, 0, sizeof(ev));
	ev.request = 3; /* PTRACE_PEEKUSER */
	ev.target_pid = 1234;
	ev.addr = 0x7f0000001000ULL;
	filter_init(&f);
	n = build_msg(buf, sizeof(buf), SENTINEL_PROTO_VERSION,
		      SENTINEL_EV_PTRACE, sizeof(ev), &ev);
	ret = sentinel_parse_message(buf, n, &f, &p);

	assert(ret == 0);
	assert(tc.dispatched == 1);
	assert(tc.last_type == SENTINEL_EV_PTRACE);
	assert(((struct sentinel_ev_ptrace *)last_payload)->request == 3);
	assert(((struct sentinel_ev_ptrace *)last_payload)->target_pid == 1234);
}

static void test_valid_io_uring_enter(void)
{
	char buf[1024];
	struct test_counts tc = { 0 };
	struct sentinel_printer p = { test_dispatch, &tc };
	struct sentinel_ev_io_uring_enter ev;
	struct event_filter f;
	size_t n;
	int ret;

	memset(&ev, 0, sizeof(ev));
	ev.fd = 7;
	ev.to_submit = 3;
	ev.min_complete = 2;
	ev.flags = 1; /* IORING_ENTER_GETEVENTS */
	ev.sig_ptr = 0x7f0000000000ULL;
	ev.submitted = 3;
	ev.completed = 2;
	filter_init(&f);
	n = build_msg(buf, sizeof(buf), SENTINEL_PROTO_VERSION,
		      SENTINEL_EV_IO_URING_ENTER, sizeof(ev), &ev);
	ret = sentinel_parse_message(buf, n, &f, &p);

	assert(ret == 0);
	assert(tc.dispatched == 1);
	assert(tc.last_type == SENTINEL_EV_IO_URING_ENTER);
	{
		const struct sentinel_ev_io_uring_enter *e =
			(const struct sentinel_ev_io_uring_enter *)last_payload;
		assert(e->fd == 7);
		assert(e->to_submit == 3);
		assert(e->min_complete == 2);
		assert(e->flags == 1);
		assert(e->submitted == 3);
		assert(e->completed == 2);
	}
}

static void test_invalid_io_uring_enter(void)
{
	char buf[1024];
	struct test_counts tc = { 0 };
	struct sentinel_printer p = { test_dispatch, &tc };
	struct sentinel_ev_io_uring_enter ev;
	struct event_filter f;
	size_t n;
	int ret;

	memset(&ev, 0, sizeof(ev));
	filter_init(&f);
	/* A truncated v8 payload must be rejected, not decoded. */
	n = build_msg(buf, sizeof(buf), SENTINEL_PROTO_VERSION,
		      SENTINEL_EV_IO_URING_ENTER, sizeof(ev) - 4, &ev);
	ret = sentinel_parse_message(buf, n, &f, &p);
	assert(ret == 0);		/* message well-formed... */
	assert(tc.dispatched == 0);	/* ...but the size check refuses it */
}

static void test_valid_finit_module(void)
{
	char buf[1024];
	struct test_counts tc = { 0 };
	struct sentinel_printer p = { test_dispatch, &tc };
	struct sentinel_ev_finit_module ev;
	struct event_filter f;
	size_t n;
	int ret;

	memset(&ev, 0, sizeof(ev));
	ev.fd = 42; /* a memfd the daemon can correlate */
	ev.flags = 0; /* MODULE_INIT_IGNORE_MODVERSIONS at most */
	filter_init(&f);
	n = build_msg(buf, sizeof(buf), SENTINEL_PROTO_VERSION,
		      SENTINEL_EV_FINIT_MODULE, sizeof(ev), &ev);
	ret = sentinel_parse_message(buf, n, &f, &p);

	assert(ret == 0);
	assert(tc.dispatched == 1);
	assert(tc.last_type == SENTINEL_EV_FINIT_MODULE);
	assert(((struct sentinel_ev_finit_module *)last_payload)->fd == 42);
	assert(((struct sentinel_ev_finit_module *)last_payload)->flags == 0);
}

static void test_batched_message(void)
{
	char buf[2048];
	struct test_counts tc = { 0 };
	struct sentinel_printer p = { test_dispatch, &tc };
	struct sentinel_ev_ptrace ev;
	struct event_filter f;
	size_t n;
	int ret;

	memset(&ev, 0, sizeof(ev));
	ev.request = 3; /* PTRACE_PEEKUSER */
	ev.target_pid = 1234;
	filter_init(&f);
	/* The kernel's batched emitter puts up to SENTINEL_GENL_BATCH_MAX
	 * events in one datagram; the parser must dispatch every pair. */
	n = build_msg_batch(buf, sizeof(buf), 3, SENTINEL_EV_PTRACE,
			    sizeof(ev), &ev);
	ret = sentinel_parse_message(buf, n, &f, &p);

	assert(ret == 0);
	assert(tc.dispatched == 3);
	assert(tc.last_type == SENTINEL_EV_PTRACE);
}

static void test_filter_pid(void)
{
	char buf[1024];
	struct test_counts tc = { 0 };
	struct sentinel_printer p = { test_dispatch, &tc };
	struct sentinel_ev_connect ev;
	struct event_filter f;
	size_t n;
	int ret;

	memset(&ev, 0, sizeof(ev));
	filter_init(&f);
	assert(filter_add_pid(&f, 9999) == 0);
	n = build_msg(buf, sizeof(buf), SENTINEL_PROTO_VERSION,
		      SENTINEL_EV_CONNECT, sizeof(ev), &ev);
	ret = sentinel_parse_message(buf, n, &f, &p);

	assert(ret == 0);
	assert(tc.dispatched == 0);
}

static void test_filter_type(void)
{
	char buf[1024];
	char payload[128];
	char *argv[] = { NULL };
	struct test_counts tc = { 0 };
	struct sentinel_printer p = { test_dispatch, &tc };
	struct event_filter f;
	size_t plen, n;
	int ret;

	filter_init(&f);
	f.event_mask = 1u << SENTINEL_EV_OPENAT; /* only openat passes */
	plen = build_execve_payload(payload, sizeof(payload), "/bin/true",
				    argv, 0);
	n = build_msg(buf, sizeof(buf), SENTINEL_PROTO_VERSION,
		      SENTINEL_EV_EXECVE, plen, payload);
	ret = sentinel_parse_message(buf, n, &f, &p);

	assert(ret == 0);
	assert(tc.dispatched == 0);
}

static void test_filter_uid(void)
{
	char buf[1024];
	struct test_counts tc = { 0 };
	struct sentinel_printer p = { test_dispatch, &tc };
	struct sentinel_ev_connect ev;
	struct event_filter f;
	size_t n;
	int ret;

	memset(&ev, 0, sizeof(ev));
	filter_init(&f);
	/* build_msg stamps uid=1000; ask for a different uid => reject */
	assert(filter_add_uid(&f, 2000) == 0);
	n = build_msg(buf, sizeof(buf), SENTINEL_PROTO_VERSION,
		      SENTINEL_EV_CONNECT, sizeof(ev), &ev);
	ret = sentinel_parse_message(buf, n, &f, &p);
	assert(ret == 0);
	assert(tc.dispatched == 0);

	/* matching uid => accept */
	filter_init(&f);
	assert(filter_add_uid(&f, 1000) == 0);
	n = build_msg(buf, sizeof(buf), SENTINEL_PROTO_VERSION,
		      SENTINEL_EV_CONNECT, sizeof(ev), &ev);
	ret = sentinel_parse_message(buf, n, &f, &p);
	assert(ret == 0);
	assert(tc.dispatched == 1);

	/* pid and uid lists AND together: pid matches, uid does not => drop */
	filter_init(&f);
	assert(filter_add_pid(&f, 4242) == 0);
	assert(filter_add_uid(&f, 2000) == 0);
	tc.dispatched = 0;
	n = build_msg(buf, sizeof(buf), SENTINEL_PROTO_VERSION,
		      SENTINEL_EV_CONNECT, sizeof(ev), &ev);
	ret = sentinel_parse_message(buf, n, &f, &p);
	assert(ret == 0);
	assert(tc.dispatched == 0);

	/* both match => accept */
	tc.dispatched = 0;
	filter_init(&f);
	assert(filter_add_pid(&f, 4242) == 0);
	assert(filter_add_uid(&f, 1000) == 0);
	n = build_msg(buf, sizeof(buf), SENTINEL_PROTO_VERSION,
		      SENTINEL_EV_CONNECT, sizeof(ev), &ev);
	ret = sentinel_parse_message(buf, n, &f, &p);
	assert(ret == 0);
	assert(tc.dispatched == 1);
}

static void test_ring_record(void)
{
	char buf[1024];
	char payload[256];
	char *argv[] = { "/bin/ls", "-la", NULL };
	struct test_counts tc = { 0 };
	struct sentinel_printer p = { test_dispatch, &tc };
	struct sentinel_ring_rec *rr = (struct sentinel_ring_rec *)buf;
	struct event_filter f;
	size_t plen, consumed = 0;
	int ret;

	filter_init(&f);
	plen = build_execve_payload(payload, sizeof(payload), "/bin/ls",
				    argv, 2);
	memset(buf, 0, sizeof(buf));
	rr->rec_len = (unsigned int)(sizeof(*rr) + plen);
	rr->hdr.proto_version = SENTINEL_PROTO_VERSION;
	rr->hdr.event_type = SENTINEL_EV_EXECVE;
	rr->hdr.payload_len = (unsigned short)plen;
	rr->hdr.pid = 4242;
	rr->hdr.ppid = 911;
	rr->hdr.uid = 1002;
	rr->hdr.gid = 1003;
	memcpy(rr->hdr.comm, "ls", 2);
	rr->hdr.timestamp_ns = 42ULL;
	rr->hdr.cpu = 0;
	rr->hdr.reserved = 0;
	memcpy(buf + sizeof(*rr), payload, plen);
	rr->hdr.crc32 = sentinel_crc_payload(&rr->hdr, payload, plen);

	ret = sentinel_parse_capture(buf, sizeof(*rr) + plen, &consumed,
				     &f, &p);
	assert(ret == 0);
	assert(tc.dispatched == 1);
	assert(consumed == sizeof(*rr) + plen);
	assert(last_hdr->ppid == 911);
	assert(last_hdr->uid == 1002);
	assert(!strncmp((const char *)last_hdr->comm, "ls", 2));

	/* truncated record: parser must refuse at the rec_len check */
	tc.dispatched = 0;
	ret = sentinel_parse_capture(buf, sizeof(*rr) + plen - 1, &consumed,
				     &f, &p);
	assert(ret == -1);
	assert(tc.dispatched == 0);

	/* rec_len inconsistent with hdr.payload_len => refuse */
	rr->rec_len += 4;
	tc.dispatched = 0;
	ret = sentinel_parse_capture(buf, sizeof(*rr) + plen + 4, &consumed,
				     &f, &p);
	assert(ret == -1);
	assert(tc.dispatched == 0);
}

/* Regression: a sub-header execve payload (len < sizeof(struct
 * sentinel_ev_execve)) must be rejected before the parser casts the bytes to
 * the struct and reads args_off. Fuzzer artifact: empty input. */
static void test_execve_payload_too_short(void)
{
	unsigned char tiny[3] = { 0xff, 0xff, 0x00 };
	struct sentinel_execve_view v;

	assert(sentinel_execve_parse(tiny, 0, &v) == -1);
	assert(sentinel_execve_parse(tiny, 3, &v) == -1);
	assert(sentinel_execveat_parse(tiny, 0, &v) == -1);
	assert(sentinel_execveat_parse(tiny, 3, &v) == -1);
}

/* Regression: a datagram whose nlmsg_len overclaims the received buffer
 * (header says len + 20) must be refused before the attribute walk can
 * read past the end. Fuzzer artifact: 51-byte record with nlmsg_len = len+20. */
static void test_message_overclaimed_len(void)
{
	char buf[1024];
	char payload[256];
	char *argv[] = { "/bin/echo", "hi", NULL };
	struct test_counts tc = { 0 };
	struct sentinel_printer p = { test_dispatch, &tc };
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	struct event_filter f;
	size_t n, plen;

	filter_init(&f);
	plen = build_execve_payload(payload, sizeof(payload), "/bin/echo",
				    argv, 2);
	n = build_msg(buf, sizeof(buf), SENTINEL_PROTO_VERSION,
		      SENTINEL_EV_EXECVE, plen, payload);

	/* valid baseline still dispatches */
	assert(sentinel_parse_message(buf, n, &f, &p) == 0);
	assert(tc.dispatched == 1);

	/* overclaim: nlmsg_len grows past the buffer we hand the parser */
	nlh->nlmsg_len += 20;
	assert(sentinel_parse_message(buf, n, &f, &p) == -1);

	/* underclaim below the fixed headers */
	nlh->nlmsg_len = NLMSG_HDRLEN + GENL_HDRLEN - 1;
	assert(sentinel_parse_message(buf, n, &f, &p) == -1);
}

int main(void)
{
	test_valid_execve();
	test_bad_proto_version();
	test_bad_execve_offsets();
	test_valid_connect();
	test_valid_mmap_exec();
	test_valid_mprotect();
	test_mprotect_bad_size();
	test_valid_execveat();
	test_execveat_bad_size();
	test_valid_memfd_create();
	test_memfd_bad_size();
	test_message_bad_crc();
	test_ring_bad_crc();
	test_valid_ptrace();
	test_valid_io_uring_enter();
	test_invalid_io_uring_enter();
	test_valid_finit_module();
	test_batched_message();
	test_filter_pid();
	test_filter_uid();
	test_filter_type();
	test_ring_record();
	test_execve_payload_too_short();
	test_message_overclaimed_len();
	puts("daemon_parser_test: OK");
	return 0;
}
