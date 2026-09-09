// SPDX-License-Identifier: Apache-2.0
/*
 * correlator_test.c -- unit tests for the daemon correlation agent.
 *
 * Feeds synthetic, already-validated events straight into correlate_observe()
 * and asserts the annotations that the printers would render:
 * fileless execveat, exec-trans W^X flips inside known images, image
 * replacement on pid reuse, memfd window expiry, and the disabled path.
 *
 * Builds only against userspace headers; no kernel tree needed:
 *   cc -I../kernel/ipc -I../src correlator_test.c ../src/correlate.c ../src/parse.c
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

#include "correlate.h"
#include "parse.h"
#include "sentinel_proto.h"

static int checks;

#define CHECK(cond)							\
	do {								\
		if (!(cond)) {						\
			fprintf(stderr, "line %d: CHECK(%s) failed\n", \
				__LINE__, #cond);			\
			return 1;					\
		}							\
		checks++;						\
	} while (0)

/* Build a v5 execve blob: [fixed hdr][path\0][arg0\0 arg1\0 ...]. */
static size_t build_execve_payload(char *out, const char *path,
				   const char *arg0)
{
	struct sentinel_ev_execve ev;
	size_t p;

	ev.path_off = sizeof(ev);
	p = ev.path_off;
	strcpy(out + p, path);
	p += strlen(path) + 1;
	ev.args_off = (unsigned short)p;
	ev.argc = 1;
	memcpy(out + p, arg0, strlen(arg0) + 1);
	p += strlen(arg0) + 1;
	memcpy(out, &ev, sizeof(ev));
	return p;
}

/* Build an execveat blob (v5), path may be "" for AT_EMPTY_PATH execs.
 * dirfd is the fd-relative handle the correlation keys on. */
static size_t build_execveat_payload(char *out, const char *path,
				     const char *arg0, unsigned int flags,
				     int dirfd)
{
	struct sentinel_ev_execveat ev;
	size_t p;

	ev.path_off = sizeof(ev);
	p = ev.path_off;
	strcpy(out + p, path);
	p += strlen(path) + 1;
	ev.args_off = (unsigned short)p;
	ev.argc = 1;
	ev.dirfd = dirfd;
	ev.flags = flags;
	memcpy(out + p, arg0, strlen(arg0) + 1);
	p += strlen(arg0) + 1;
	memcpy(out, &ev, sizeof(ev));
	return p;
}

static struct sentinel_event_hdr hdr(unsigned char type, unsigned int pid,
				     uint64_t ts, size_t plen)
{
	struct sentinel_event_hdr h;

	memset(&h, 0, sizeof(h));
	h.proto_version = SENTINEL_PROTO_VERSION;
	h.event_type = type;
	h.payload_len = (unsigned short)plen;
	h.pid = pid;
	h.timestamp_ns = ts;
	return h;
}

static void feed(struct correlate_state *c, struct sentinel_event_hdr *h,
		 const void *payload, struct correlate_annot *out)
{
	correlate_observe(c, h, payload, out);
}

static int test_exec_trans(void)
{
	struct correlate_state c;
	struct correlate_annot a;
	struct sentinel_ev_mmap_exec mm;
	struct sentinel_ev_mprotect mp;
	struct sentinel_event_hdr h;
	char blob[512];

	correlate_init(&c, true);

	/* No image yet: a W|X mmap is not a self-modifying binary. */
	h = hdr(SENTINEL_EV_MMAP_EXEC, 7, 1000, sizeof(mm));
	memset(&mm, 0, sizeof(mm));
	mm.prot = PROT_READ | PROT_WRITE | PROT_EXEC;
	feed(&c, &h, &mm, &a);
	CHECK(!a.exec_trans);
	CHECK(a.exec == NULL);

	/* Record the image, then the same W|X mmap must flag it. */
	h = hdr(SENTINEL_EV_EXECVE, 7, 2000,
		build_execve_payload(blob, "/usr/bin/python3", "python3"));
	feed(&c, &h, blob, &a);

	h = hdr(SENTINEL_EV_MMAP_EXEC, 7, 3000, sizeof(mm));
	mm.prot = PROT_WRITE | PROT_EXEC;
	feed(&c, &h, &mm, &a);
	CHECK(a.exec_trans);
	CHECK(a.exec && strcmp(a.exec->path, "/usr/bin/python3") == 0);

	/* mprotect into W|X does the same and carries argv0 too. */
	h = hdr(SENTINEL_EV_MPROTECT, 7, 4000, sizeof(mp));
	memset(&mp, 0, sizeof(mp));
	mp.prot = PROT_WRITE | PROT_EXEC;
	feed(&c, &h, &mp, &a);
	CHECK(a.exec_trans);
	CHECK(a.exec && strcmp(a.exec->argv0, "python3") == 0);

	/* A W-only mprotect is not a violation by itself. */
	mp.prot = PROT_WRITE;
	feed(&c, &h, &mp, &a);
	CHECK(!a.exec_trans);

	/* Pid reuse: a newer image replaces the old one. */
	h = hdr(SENTINEL_EV_EXECVE, 7, 5000,
		build_execve_payload(blob, "/usr/bin/ld-linux-x86-64.so.2",
				    "ld-linux"));
	feed(&c, &h, blob, &a);
	h = hdr(SENTINEL_EV_MMAP_EXEC, 7, 6000, sizeof(mm));
	mm.prot = PROT_WRITE | PROT_EXEC;
	feed(&c, &h, &mm, &a);
	CHECK(a.exec_trans);
	CHECK(a.exec &&
	      strcmp(a.exec->path, "/usr/bin/ld-linux-x86-64.so.2") == 0);
	return 0;
}

static int test_execveat_records_and_fileless(void)
{
	struct correlate_state c;
	struct correlate_annot a;
	struct sentinel_ev_memfd_create mf;
	struct sentinel_ev_mmap_exec mm;
	struct sentinel_event_hdr h;
	char blob[512];

	correlate_init(&c, true);

	/* Plain execveat records the image but is not fileless. */
	h = hdr(SENTINEL_EV_EXECVEAT, 9, 1000,
		build_execveat_payload(blob, "/bin/ls", "ls", 0, 3));
	feed(&c, &h, blob, &a);
	CHECK(!a.fileless);
	CHECK(a.exec == NULL);	/* execveat does not self-annotate */
	h = hdr(SENTINEL_EV_MMAP_EXEC, 9, 1100, sizeof(mm));
	memset(&mm, 0, sizeof(mm));
	mm.prot = PROT_WRITE | PROT_EXEC;
	feed(&c, &h, &mm, &a);
	CHECK(a.exec_trans);
	CHECK(a.exec && strcmp(a.exec->path, "/bin/ls") == 0);

	/* memfd + execveat("", AT_EMPTY_PATH) inside the window => fileless. */
	h = hdr(SENTINEL_EV_MEMFD_CREATE, 9, 2000, sizeof(mf));
	memset(&mf, 0, sizeof(mf));
	strcpy((char *)mf.name, "junk");
	mf.fd = 3;
	feed(&c, &h, &mf, &a);
	h = hdr(SENTINEL_EV_EXECVEAT, 9, 2050,
		build_execveat_payload(blob, "", "scurl",
				       SENTINEL_AT_EMPTY_PATH, 3));
	feed(&c, &h, blob, &a);
	CHECK(a.fileless);

	/* The identity key is the descriptor, not just the pid: an
	 * AT_EMPTY_PATH exec through any other fd is not this memfd, even
	 * though the pid minted one moments ago. */
	h = hdr(SENTINEL_EV_MEMFD_CREATE, 9, 2070, sizeof(mf));
	strcpy((char *)mf.name, "other");
	mf.fd = 5;
	feed(&c, &h, &mf, &a);
	h = hdr(SENTINEL_EV_EXECVEAT, 9, 2080,
		build_execveat_payload(blob, "", "via5",
				       SENTINEL_AT_EMPTY_PATH, 5));
	feed(&c, &h, blob, &a);
	CHECK(a.fileless);
	h = hdr(SENTINEL_EV_EXECVEAT, 9, 2090,
		build_execveat_payload(blob, "", "via3",
				       SENTINEL_AT_EMPTY_PATH, 3));
	feed(&c, &h, blob, &a);
	CHECK(!a.fileless);

	/* A failed memfd (fd < 0) is an intent signal but installs no
	 * identity: it cannot be exec'd, so nothing may match it. */
	h = hdr(SENTINEL_EV_MEMFD_CREATE, 9, 2100, sizeof(mf));
	strcpy((char *)mf.name, "busted");
	mf.fd = -22;	/* -EINVAL simulates a failed memfd_create */
	feed(&c, &h, &mf, &a);
	h = hdr(SENTINEL_EV_EXECVEAT, 9, 2110,
		build_execveat_payload(blob, "", "nope",
				       SENTINEL_AT_EMPTY_PATH, 3));
	feed(&c, &h, blob, &a);
	CHECK(!a.fileless);

	/* AT_EMPTY_PATH with no recent memfd is just execveat. */
	h = hdr(SENTINEL_EV_EXECVEAT, 10, 3000,
		build_execveat_payload(blob, "", "something",
				       SENTINEL_AT_EMPTY_PATH, 3));
	feed(&c, &h, blob, &a);
	CHECK(!a.fileless);

	/* memfd has aged out of the window: no longer "fileless". */
	h = hdr(SENTINEL_EV_MEMFD_CREATE, 11, 5000, sizeof(mf));
	strcpy((char *)mf.name, "stale");
	mf.fd = 3;
	feed(&c, &h, &mf, &a);
	h = hdr(SENTINEL_EV_EXECVEAT, 11, 5000 + SENTINEL_CORR_MEMFD_WINDOW_NS + 1,
		build_execveat_payload(blob, "", "late",
				       SENTINEL_AT_EMPTY_PATH, 3));
	feed(&c, &h, blob, &a);
	CHECK(!a.fileless);
	return 0;
}

static int test_disabled(void)
{
	struct correlate_state c;
	struct correlate_annot a;
	struct sentinel_ev_mmap_exec mm;
	struct sentinel_event_hdr h;
	char blob[512];

	correlate_init(&c, false);
	h = hdr(SENTINEL_EV_EXECVE, 7, 1000,
		build_execve_payload(blob, "/bin/bash", "bash"));
	feed(&c, &h, blob, &a);
	h = hdr(SENTINEL_EV_MMAP_EXEC, 7, 2000, sizeof(mm));
	memset(&mm, 0, sizeof(mm));
	mm.prot = PROT_WRITE | PROT_EXEC;
	feed(&c, &h, &mm, &a);
	CHECK(!a.exec_trans);
	CHECK(a.exec == NULL);
	CHECK(!a.fileless);
	return 0;
}

static int test_full_table_evicts(void)
{
	struct correlate_state c;
	struct correlate_annot a;
	struct sentinel_ev_mmap_exec mm;
	struct sentinel_event_hdr h;
	char blob[512];
	unsigned int i, pid;

	correlate_init(&c, true);

	/* Fill the exec table (1023 live pids) then force recycle churn. */
	for (i = 0, pid = 10000; i < SENTINEL_CORR_EXEC_TABLE - 1; i++, pid++) {
		size_t n = build_execve_payload(blob, "/bin/true", "true");

		h = hdr(SENTINEL_EV_EXECVE, pid, i, n);
		feed(&c, &h, blob, &a);
	}
	for (; pid < 10000 + SENTINEL_CORR_EXEC_TABLE + 2048; pid++) {
		size_t n = build_execve_payload(blob, "/bin/true", "true");

		h = hdr(SENTINEL_EV_EXECVE, pid, (uint64_t)pid, n);
		feed(&c, &h, blob, &a);
	}

	/* The most recent image survives the collision churn. */
	h = hdr(SENTINEL_EV_MMAP_EXEC, pid - 1, (uint64_t)pid, sizeof(mm));
	memset(&mm, 0, sizeof(mm));
	mm.prot = PROT_WRITE | PROT_EXEC;
	feed(&c, &h, &mm, &a);
	CHECK(a.exec_trans);
	CHECK(a.exec && strcmp(a.exec->path, "/bin/true") == 0);
	return 0;
}

int main(void)
{
	int fails = 0;

	fails += test_exec_trans();
	fails += test_execveat_records_and_fileless();
	fails += test_disabled();
	fails += test_full_table_evicts();

	if (fails) {
		fprintf(stderr, "correlator_test: %d FAILED\n", fails);
		return 1;
	}
	printf("correlator_test: %d checks OK\n", checks);
	return 0;
}
