// SPDX-License-Identifier: Apache-2.0
/*
 * ringmap_client.c -- userspace half of the mmap zero-copy export.
 *
 * Opens the misc device, reads the meta page to discover the data-ring
 * capacity (runtime-configurable via the kernel's ringmap_size knob), then
 * maps meta + capacity bytes. head advances with release semantics in the
 * kernel, tail the same way here, so both sides use the C11 __atomic
 * builtins for load-acquire / store-release.
 *
 * Protocol with the kernel:
 *   - only one consumer: a second open() gets -EBUSY from the device.
 *   - positions are absolute byte offsets; & mask maps into the ring.
 *   - meta.epoch is the incarnation the mapping belongs to; a mapping whose
 *     epoch no longer matches a freshly probed device is a stale ring from
 *     before a close/reload (re-open handshake).
 *   - records are self-describing (struct sentinel_ring_rec), so parse.c
 *     is shared with the netlink path.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stddef.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "ringmap_client.h"
#include "sentinel_proto.h"

#define RINGMAP_META_BYTES	4096	/* page 0 is the meta */
#define RINGMAP_DATA_BASE	RINGMAP_META_BYTES

static inline unsigned int
ringmap_meta_capacity(const struct sentinel_ringmap_meta *m)
{
	/* Trust the meta page; capacity is always written by the kernel and
	 * a phantom read happens only after magic/generation validated. */
	unsigned int cap = m->capacity;

	if (!cap || (cap & (cap - 1)))
		return m->mask + 1;
	return cap;
}

static inline int ringmap_capacity_ok(unsigned int cap)
{
	if (cap < (unsigned int)SENTINEL_RINGMAP_MIN_KIB * 1024 ||
	    cap > (unsigned int)SENTINEL_RINGMAP_MAX_KIB * 1024)
		return 0;
	return cap && !(cap & (cap - 1));
}

static inline unsigned int u32_acquire(const struct sentinel_ringmap_meta *m,
				       unsigned int off)
{
	/* Struct is packed; every u32 field sits at a 4-aligned offset inside
	 * the page-aligned mapping, so the cast is safe on x86_64. The void*
	 * intermediate silences -Waddress-of-packed-member. */
	return __atomic_load_n(
		(const unsigned int *)(const void *)((const char *)m + off),
		__ATOMIC_ACQUIRE);
}

static inline void u32_release(struct sentinel_ringmap_meta *m,
			       unsigned int off, unsigned int v)
{
	__atomic_store_n((unsigned int *)(void *)((char *)m + off), v,
			 __ATOMIC_RELEASE);
}

int ringmap_open(struct ringmap_client *c, const char *path)
{
	const struct sentinel_ringmap_meta *meta;
	size_t map_size;
	unsigned int cap;
	void *map;
	int fd, err;

	if (!path)
		path = "/dev/sentinel_ring";
	memset(c, 0, sizeof(*c));
	c->fd = -1;
	c->map = MAP_FAILED;

	fd = open(path, O_RDWR);
	if (fd < 0)
		return -errno;

	/* Step 1: map only the meta page to learn the runtime capacity. */
	map = mmap(NULL, RINGMAP_META_BYTES, PROT_READ | PROT_WRITE,
		   MAP_SHARED, fd, 0);
	if (map == MAP_FAILED) {
		err = -errno;
		goto fail;
	}
	meta = (const struct sentinel_ringmap_meta *)map;
	if (meta->magic != SENTINEL_RINGMAP_MAGIC) {
		err = -EPROTO;
		goto fail_unmap;
	}
	cap = ringmap_meta_capacity(meta);
	if (!ringmap_capacity_ok(cap)) {
		err = -EPROTO;
		goto fail_unmap;
	}
	munmap(map, RINGMAP_META_BYTES);

	/* Step 2: map the meta page plus the discovered data ring. */
	map_size = RINGMAP_META_BYTES + cap;
	map = mmap(NULL, map_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (map == MAP_FAILED) {
		err = -errno;
		goto fail;
	}
	c->fd = fd;
	c->map = map;
	c->map_size = map_size;
	c->meta = (struct sentinel_ringmap_meta *)map;
	c->capacity = cap;
	c->epoch = c->meta->epoch;
	return 0;

fail_unmap:
	munmap(map, RINGMAP_META_BYTES);
fail:
	close(fd);
	return err;
}

int ringmap_validate(const struct ringmap_client *c)
{
	const struct sentinel_ringmap_meta *m = c->meta;

	if (m->magic != SENTINEL_RINGMAP_MAGIC)
		return -1;
	if (m->epoch == 0)
		return -1;
	if (!ringmap_capacity_ok(m->capacity))
		return -1;
	if (m->mask != m->capacity - 1)
		return -1;
	return 0;
}

uint32_t ringmap_epoch(const struct ringmap_client *c)
{
	if (!c || c->meta == NULL)
		return 0;
	return c->meta->epoch;
}

uint32_t ringmap_capacity(const struct ringmap_client *c)
{
	if (!c || c->meta == NULL)
		return 0;
	return c->meta->capacity;
}

int ringmap_wait(const struct ringmap_client *c, int timeout_ms)
{
	struct pollfd pfd = { .fd = c->fd, .events = POLLIN };
	int n;

	do {
		n = poll(&pfd, 1, timeout_ms);
	} while (n < 0 && errno == EINTR);
	if (n < 0)
		return -errno;
	return n > 0 ? 1 : 0;
}

static void ring_fetch(const struct ringmap_client *c, unsigned int pos,
		       void *dst, size_t len)
{
	unsigned int p = pos & c->meta->mask;
	unsigned int cap = c->capacity;
	size_t avail;

	if (p + len <= cap) {
		memcpy(dst, (const unsigned char *)c->map + RINGMAP_DATA_BASE + p,
		       len);
		return;
	}

	/* Wraps past the end of the data pages: two non-overlapping chunks,
	 * the head at [p .. capacity) and the remainder from the base. */
	avail = cap - p;
	memcpy(dst, (const unsigned char *)c->map + RINGMAP_DATA_BASE + p, avail);
	memcpy((unsigned char *)dst + avail,
	       (const unsigned char *)c->map + RINGMAP_DATA_BASE, len - avail);
}

ssize_t ringmap_next(struct ringmap_client *c, void *out, size_t cap)
{
	struct sentinel_ringmap_meta *m = c->meta;
	unsigned int head = u32_acquire(m, offsetof(struct sentinel_ringmap_meta, head));
	unsigned int tail = u32_acquire(m, offsetof(struct sentinel_ringmap_meta, tail));
	unsigned int rec_len;

	if (head == tail)
		return 0;

	ring_fetch(c, tail, &rec_len, sizeof(rec_len));
	if (rec_len < SENTINEL_RING_REC_HDR_SIZE)
		return -EBADMSG;
	if ((size_t)rec_len > cap)
		return -ENOSPC;
	if (head - tail < rec_len)
		return -EBADMSG;	/* record spans unconsumed gap */

	ring_fetch(c, tail, out, rec_len);
	u32_release(m, offsetof(struct sentinel_ringmap_meta, tail),
		    tail + rec_len);
	return (ssize_t)rec_len;
}

void ringmap_close(struct ringmap_client *c)
{
	if (c->map && c->map != MAP_FAILED)
		munmap(c->map, c->map_size);
	if (c->fd >= 0)
		close(c->fd);
	c->map = MAP_FAILED;
	c->map_size = 0;
	c->fd = -1;
	c->meta = NULL;
}

/* ------------------------------------------------------------------ */
/* read(2) path: no mmap, one record per read()                       */
/* ------------------------------------------------------------------ */

/* Cheap magic/capacity check on the meta page without disturbing the
 * read() stream. */
static int ringmap_probe_fd(int fd)
{
	struct sentinel_ringmap_meta *m;
	int ok;

	m = mmap(NULL, RINGMAP_META_BYTES, PROT_READ, MAP_SHARED, fd, 0);
	if (m == MAP_FAILED)
		return -errno;
	ok = (m->magic == SENTINEL_RINGMAP_MAGIC && m->epoch != 0 &&
	      ringmap_capacity_ok(ringmap_meta_capacity(m))) ? 0 : -ENODEV;
	munmap(m, RINGMAP_META_BYTES);
	return ok;
}

int ringmap_ro_open(const char *path, int nonblock)
{
	int fd, err;

	if (!path)
		path = "/dev/sentinel_ring";
	fd = open(path, O_RDWR | (nonblock ? O_NONBLOCK : 0));
	if (fd < 0)
		return -errno;

	err = ringmap_probe_fd(fd);
	if (err < 0) {
		close(fd);
		return err;
	}
	return fd;
}

int ringmap_ro_wait(int fd, int timeout_ms)
{
	struct pollfd pfd = { .fd = fd, .events = POLLIN };
	int n;

	do {
		n = poll(&pfd, 1, timeout_ms);
	} while (n < 0 && errno == EINTR);
	if (n < 0)
		return -errno;
	return n > 0 ? 1 : 0;
}

ssize_t ringmap_ro_read(int fd, void *out, size_t cap)
{
	ssize_t n;

	do {
		n = read(fd, out, cap);
	} while (n < 0 && errno == EINTR);
	if (n < 0)
		return -errno;
	return n;
}
