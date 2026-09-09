// SPDX-License-Identifier: Apache-2.0
/*
 * config_test.c -- unit tests for the daemon config-file parser.
 *
 * Exercises read/precedence/CLI-replay semantics end to end:
 *   - key parsing, # comments, blank lines, value whitespace;
 *   - unknown keys and malformed values rejected with diagnostics;
 *   - transport choice, filters, and flag flips land in cfg_opts;
 *   - the file applies first so later CLI options override it.
 *
 * Builds only against userspace headers; no kernel tree needed:
 *   cc -I../kernel/ipc -I../src config_test.c ../src/config.c ../src/filter.c
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "config.h"
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

static const char *write_tmp(const char *text)
{
	static char path[64];
	static int n;
	FILE *fp;

	snprintf(path, sizeof(path), "/tmp/config_test_%d_%d", (int)getpid(), n++);
	fp = fopen(path, "w");
	if (!fp)
		return NULL;
	fputs(text, fp);
	fclose(fp);
	return path;
}

static int test_basic(void)
{
	struct cfg_opts c;
	const char *p = write_tmp(
		"# defaults\n"
		"pid=1234\n"
		"uid=1000\n"
		"type=execve\n"
		"json=yes\n"
		"mmap=/dev/sentinel_ring\n"
		"stats=no\n"
		"container-labels=true\n"
		"\n"
		"   reconnect = 1  \n");

	CHECK(p != NULL);
	cfg_init(&c);
	CHECK(cfg_read_file(&c, p) == 0);
	CHECK(c.filter.n_pid == 1 && c.filter.pids[0] == 1234);
	CHECK(c.filter.n_uid == 1 && c.filter.uids[0] == 1000);
	CHECK(c.filter.event_mask & (1u << SENTINEL_EV_EXECVE));
	CHECK(c.json == 1);
	CHECK(c.transport == 'm');
	CHECK(c.ring_path != NULL && !strcmp(c.ring_path, "/dev/sentinel_ring"));
	CHECK(c.stats == 0);
	CHECK(c.labels == 1);
	CHECK(c.reconnect == 1);
	CHECK(c.had_filter == 1);
	cfg_fini(&c);
	return 0;
}

static int test_apply_cli_override(void)
{
	struct cfg_opts c;
	const char *p = write_tmp("json=0\nmmap=/dev/sentinel_ring\n");

	cfg_init(&c);
	CHECK(cfg_read_file(&c, p) == 0);
	CHECK(c.json == 0);
	/* CLI replay after the file: -j flips, -R overrides the transport,
	 * -a overrides the apply spec. */
	CHECK(cfg_apply(&c, 'j', NULL) == 0);
	CHECK(c.json == 1);
	CHECK(cfg_apply(&c, 'R', "/dev/ring2") == 0);
	CHECK(c.transport == 'R' && !strcmp(c.ring_path, "/dev/ring2"));
	CHECK(cfg_apply(&c, 'a', "mask=all") == 0);
	CHECK(c.apply_spec != NULL && !strcmp(c.apply_spec, "mask=all"));
	cfg_fini(&c);
	return 0;
}

static int test_conflicting_transport(void)
{
	struct cfg_opts c;
	const char *p = write_tmp("mmap=/r\nring-read=/r\n");
	const char *p2 = write_tmp("mmap=/a\nmmap=/b\n");

	cfg_init(&c);
	CHECK(cfg_read_file(&c, p) == -1);	/* one file: one transport */
	cfg_fini(&c);
	cfg_init(&c);
	CHECK(cfg_read_file(&c, p2) == -1);	/* dupe transport: strict too */
	cfg_fini(&c);
	return 0;
}

static int test_errors(void)
{
	struct cfg_opts c;
	const char *p;

	cfg_init(&c);
	CHECK(cfg_read_file(&c, "/nonexistent/sentinel.conf") == -1);
	p = write_tmp("unknownkey=1\n");
	CHECK(p != NULL);
	cfg_init(&c);
	CHECK(cfg_read_file(&c, p) == -1);
	p = write_tmp("json=maybe\n");
	cfg_init(&c);
	CHECK(cfg_read_file(&c, p) == -1);
	p = write_tmp("pid=abc\n");
	cfg_init(&c);
	CHECK(cfg_read_file(&c, p) == -1);
	p = write_tmp("this line has no equals\n");
	cfg_init(&c);
	CHECK(cfg_read_file(&c, p) == -1);
	return 0;
}

static int test_vertical_edges(void)
{
	struct cfg_opts c;
	const char *p = write_tmp(
		"type=memfd  # inline comment\n"
		"  uid=42\n"
		"ring-read=\n");

	cfg_init(&c);
	CHECK(cfg_read_file(&c, p) == 0);
	CHECK(c.filter.event_mask & (1u << SENTINEL_EV_MEMFD_CREATE));
	CHECK(c.filter.n_uid == 1 && c.filter.uids[0] == 42);
	CHECK(c.transport == 'R');
	CHECK(c.ring_path == NULL);	/* empty value -> default path */
	cfg_fini(&c);
	return 0;
}

int main(void)
{
	int ret = 0;

	ret |= test_basic();
	ret |= test_apply_cli_override();
	ret |= test_conflicting_transport();
	ret |= test_errors();
	ret |= test_vertical_edges();
	printf("config_test: %d checks passed\n", checks);
	return ret;
}
