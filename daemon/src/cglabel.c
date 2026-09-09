// SPDX-License-Identifier: Apache-2.0
/*
 * cglabel.c -- container label resolver.
 *
 * /proc/<pid>/cgroup is a kernel-maintained text file with one line per
 * controller (or the unified cgroup2 root). The last path component is the
 * container identity as the runtime chose to name it:
 *
 *   docker:         .../system.slice/docker-<id>.scope
 *   containerd:     .../kubepods.slice/kubepods-...-<pod>.scope/...
 *   cri / podman:   .../cri-containerd-<id>.scope
 *   bare:           /
 *
 * We scan each line, take the last line's final path component (the unified
 * hierarchy entry wins) and emit it as the label. Reads are capped so a
 * pathological line can not run the parser past the buffer.
 *
 * The cache is pid-keyed and age-evicted (capacity-bounded, oldest sequence
 * bumped out on collision), mirroring the correlator's tables. It is read by
 * the single consumer thread only, so no locking is needed.
 */
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "cglabel.h"

#define CGROUP_BUF	256

static unsigned int cglabel_hash(unsigned int pid)
{
	/* xorshift-ish mix so low-bit-heavy pids spread across the table. */
	unsigned int h = pid * 2654435761u;
	h ^= h >> 16;
	return h;
}

/* Insert or update pid's entry (label NULL clears it). Caller owns label.
 * Collisions are newest-wins: a newer pid simply replaces the older mapping,
 * so the cache is bounded at one entry per slot with no global scan.
 * Exposed as an extern when CGLABEL_TEST is defined. */
#ifndef CGLABEL_TEST
static
#endif
void cglabel_put(struct cglabel_state *s, unsigned int pid, const char *label)
{
	unsigned int slot = cglabel_hash(pid) & (SENTINEL_CGLABEL_TABLE - 1);
	struct cglabel *e = &s->slots[slot];

	if (label)
		snprintf(e->label, sizeof(e->label), "%s", label);
	else
		e->label[0] = '\0';
	e->pid = pid;
}

/* Extract the container label from one cgroup line. Returns 0 on success.
 * Exposed as an extern when CGLABEL_TEST is defined so the userspace unit
 * test can exercise the parser directly. */
#ifndef CGLABEL_TEST
static
#endif
int cglabel_parse_line(const char *line, size_t len, char *out, size_t out_sz)
{
	const char *last_slash = NULL;
	size_t comp_len;

	if (len == 0 || line[0] != '/')
		return -1;
	if (line[len - 1] == '\n')
		len--;

	for (size_t i = 0; i < len; i++)
		if (line[i] == '/')
			last_slash = line + i + 1;
	if (!last_slash || last_slash == line + len)
		return -1;

	comp_len = (size_t)((line + len) - last_slash);
	if (comp_len == 0 || comp_len + 1 > out_sz)
		return -1;
	memcpy(out, last_slash, comp_len);
	out[comp_len] = '\0';
	return 0;
}

void cglabel_init(struct cglabel_state *s)
{
	memset(s, 0, sizeof(*s));
}

const char *cglabel_resolve(struct cglabel_state *s, unsigned int pid)
{
	unsigned int slot = cglabel_hash(pid) & (SENTINEL_CGLABEL_TABLE - 1);
	struct cglabel *e = &s->slots[slot];
	char path[32];
	char buf[CGROUP_BUF];
	char label[SENTINEL_CGLABEL_MAX];
	size_t off;
	ssize_t n;
	int fd;

	if (e->pid == pid)
		return e->label[0] ? e->label : NULL;

	snprintf(path, sizeof(path), "/proc/%u/cgroup", pid);
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		cglabel_put(s, pid, NULL);
		return NULL;
	}
	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0) {
		cglabel_put(s, pid, NULL);
		return NULL;
	}
	buf[n] = '\0';

	/* Walk lines, keeping the last that yields a label so a unified
	 * hierarchy entry (which appears after any controller lines) wins. */
	label[0] = '\0';
	off = 0;
	while (off < (size_t)n) {
		const char *line = buf + off;
		const char *nl = memchr(line, '\n', (size_t)n - off);

		if (!nl)
			break;
		/* controller prefix "ID:":path"; skip through the colon */
		{
			const char *colon = memchr(line, ':',
						   (size_t)(nl - line));
			const char *start = colon ? colon + 1 : line;
			size_t start_len = (size_t)(nl - start);
			char tmp[SENTINEL_CGLABEL_MAX];

			if (cglabel_parse_line(start, start_len, tmp,
					       sizeof(tmp)) == 0)
				snprintf(label, sizeof(label), "%s", tmp);
		}
		off = (size_t)((nl - buf) + 1);
	}

	cglabel_put(s, pid, label[0] ? label : NULL);
	e = &s->slots[slot];
	return e->label[0] ? e->label : NULL;
}
