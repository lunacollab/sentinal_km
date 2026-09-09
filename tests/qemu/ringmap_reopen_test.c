// SPDX-License-Identifier: GPL-2.0-only
/*
 * ringmap_reopen_test.c -- P2.3 mmap-ring contract harness. Runs inside the
 * test VM as root. Asserts:
 *   - a second consumer is refused (-EBUSY), both while mmap-held and for a
 *     stray re-open of the same device (dual-consumer refusal);
 *   - a capacity resize is refused while a consumer holds the mapping;
 *   - meta.epoch is a strictly increasing incarnation across re-opens (the
 *     re-open handshake) and never 0;
 *   - the runtime ringmap_size knob retargets the next open's capacity and
 *     the mask matches it; invalid sizes are rejected;
 *   - the read(2) backend stays coherent on a resized ring.
 *
 * Exits 0 on success, 1 with a diagnostic otherwise.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../../kernel/ipc/sentinel_proto.h"

#define RING	"/dev/sentinel_ring"
#define SIZE_FN	"/sys/kernel/sentinel_km/ringmap_size"
#define META	4096

static int fail(const char *what, int line)
{
	fprintf(stderr, "FAIL:%d %s (errno=%s)\n", line, what,
		strerror(errno));
	return 1;
}

static int set_size(unsigned int kib)
{
	char buf[16];
	int fd, n;

	fd = open(SIZE_FN, O_WRONLY);
	if (fd < 0)
		return -errno;
	n = snprintf(buf, sizeof(buf), "%u", kib);
	if (write(fd, buf, (size_t)n) != n) {
		close(fd);
		return -errno;
	}
	close(fd);
	return 0;
}

static int get_size(unsigned int *kib)
{
	char buf[16];
	int fd, n;

	fd = open(SIZE_FN, O_RDONLY);
	if (fd < 0)
		return -errno;
	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		return errno ? -errno : -EIO;
	buf[n] = '\0';
	*kib = (unsigned int)strtoul(buf, NULL, 10);
	return 0;
}

static int open_ring(void)
{
	int fd = open(RING, O_RDWR);

	if (fd < 0)
		return -errno;
	return fd;
}

int main(void)
{
	const struct sentinel_ringmap_meta *meta;
	unsigned char *map;
	uint32_t epoch1, epoch2, epoch3, ep;
	unsigned int cap, kib = 0;
	int fd, err, n, ok = 0;
	struct pollfd pfd;

	/* Defaults must hold before we start. */
	err = get_size(&kib);
	if (err < 0) {
		errno = -err;
		return fail("read ringmap_size (module loaded?)", __LINE__);
	}
	if (kib != SENTINEL_RINGMAP_DEFAULT_KIB) {
		fprintf(stderr, "FAIL:%d default ringmap_size=%u expected %u\n",
			__LINE__, kib, (unsigned int)SENTINEL_RINGMAP_DEFAULT_KIB);
		return 1;
	}

	/* First consumer. */
	fd = open_ring();
	if (fd < 0)
		return fail("open ring (first)", __LINE__);
	map = mmap(NULL, META, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (map == MAP_FAILED)
		return fail("mmap meta", __LINE__);
	meta = (const struct sentinel_ringmap_meta *)map;
	if (meta->magic != SENTINEL_RINGMAP_MAGIC)
		return fail("meta magic", __LINE__);
	epoch1 = meta->epoch;
	if (epoch1 == 0)
		return fail("epoch must never be 0", __LINE__);
	cap = meta->capacity;
	if (cap != SENTINEL_RINGMAP_DEFAULT_CAPACITY)
		return fail("capacity not default", __LINE__);
	if (meta->mask != cap - 1)
		return fail("mask != capacity-1", __LINE__);
	munmap(map, META);

	/* Full mapping sized from the discovered capacity. */
	map = mmap(NULL, META + cap, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (map == MAP_FAILED)
		return fail("mmap full ring", __LINE__);

	/* Dual-consumer refusal: a second open must be -EBUSY. */
	err = open_ring();
	if (err >= 0) {
		close(err);
		return fail("second consumer must be refused (EBUSY)", __LINE__);
	}
	if (err != -EBUSY) {
		fprintf(stderr, "FAIL:%d second open errno=%d expected EBUSY\n",
			__LINE__, -err);
		return 1;
	}

	/* A resize must be refused while a consumer holds the mapping. */
	err = set_size(SENTINEL_RINGMAP_DEFAULT_KIB / 2);
	if (err != -EBUSY) {
		fprintf(stderr, "FAIL:%d resize while busy errno=%d expected EBUSY\n",
			__LINE__, -err);
		return 1;
	}

	/* Empty ring: poll must time out, nonblocking read must -EAGAIN. */
	pfd.fd = fd;
	pfd.events = POLLIN;
	n = poll(&pfd, 1, 300);
	if (n != 0)
		return fail("empty ring must not be POLLIN", __LINE__);
	fcntl(fd, F_SETFL, O_NONBLOCK);
	errno = 0;
	n = (int)read(fd, map, META);
	if (n >= 0 || errno != EAGAIN)
		return fail("empty read side must -EAGAIN", __LINE__);
	fcntl(fd, F_SETFL, 0);

	munmap(map, META + cap);
	close(fd);

	/* Re-open handshake: next incarnation must carry a fresh epoch. */
	fd = open_ring();
	if (fd < 0)
		return fail("open ring (re-open)", __LINE__);
	map = mmap(NULL, META, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (map == MAP_FAILED)
		return fail("mmap meta (re-open)", __LINE__);
	meta = (const struct sentinel_ringmap_meta *)map;
	epoch2 = meta->epoch;
	if (epoch2 <= epoch1) {
		fprintf(stderr, "FAIL:%d epoch not increasing: %u -> %u\n",
			__LINE__, epoch1, epoch2);
		return 1;
	}
	cap = meta->capacity;
	if (cap != SENTINEL_RINGMAP_DEFAULT_CAPACITY)
		return fail("capacity changed across re-open", __LINE__);
	munmap(map, META);
	close(fd);

	/* Retarget capacity while idle, then re-open at the smaller size. */
	err = set_size(SENTINEL_RINGMAP_MIN_KIB);
	if (err < 0) {
		errno = -err;
		return fail("resize to min while idle", __LINE__);
	}
	err = set_size(SENTINEL_RINGMAP_MIN_KIB - 1);
	if (err != -EINVAL) {
		fprintf(stderr, "FAIL:%d undersized resize errno=%d expected EINVAL\n",
			__LINE__, -err);
		return 1;
	}
	err = set_size(SENTINEL_RINGMAP_MIN_KIB * 2 + 1);
	if (err != -EINVAL) {
		fprintf(stderr, "FAIL:%d non-power-of-two resize errno=%d expected EINVAL\n",
			__LINE__, -err);
		return 1;
	}

	fd = open_ring();
	if (fd < 0)
		return fail("open ring (small)", __LINE__);
	map = mmap(NULL, META, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (map == MAP_FAILED)
		return fail("mmap meta (small)", __LINE__);
	meta = (const struct sentinel_ringmap_meta *)map;
	epoch3 = meta->epoch;
	if (epoch3 <= epoch2)
		return fail("epoch must advance past re-open", __LINE__);
	cap = meta->capacity;
	if (cap != SENTINEL_RINGMAP_MIN_KIB * 1024)
		return fail("capacity not at min", __LINE__);
	if (meta->mask != cap - 1)
		return fail("mask != capacity-1 (small)", __LINE__);
	munmap(map, META);
	map = mmap(NULL, META + cap, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (map == MAP_FAILED)
		return fail("mmap small ring", __LINE__);
	fcntl(fd, F_SETFL, O_NONBLOCK);
	errno = 0;
	n = (int)read(fd, map, META);
	if (n >= 0 || errno != EAGAIN)
		return fail("small ring read side must -EAGAIN", __LINE__);
	munmap(map, META + cap);
	close(fd);

	/* Restore the default so the smoke suite's assumptions hold. */
	err = set_size(SENTINEL_RINGMAP_DEFAULT_KIB);
	if (err < 0) {
		errno = -err;
		return fail("resize back to default", __LINE__);
	}
	fd = open_ring();
	if (fd < 0)
		return fail("open ring (restore default)", __LINE__);
	map = mmap(NULL, META, PROT_READ, MAP_SHARED, fd, 0);
	if (map == MAP_FAILED)
		return fail("mmap meta (restore default)", __LINE__);
	meta = (const struct sentinel_ringmap_meta *)map;
	ep = meta->epoch;
	cap = meta->capacity;
	munmap(map, META);
	close(fd);
	if (ep <= epoch3)
		return fail("epoch must keep advancing", __LINE__);
	if (cap != SENTINEL_RINGMAP_DEFAULT_CAPACITY)
		return fail("default capacity not restored", __LINE__);

	(void)ok;
	printf("ringmap_reopen_test: OK (epoch %u -> %u -> %u -> %u)\n",
	       epoch1, epoch2, epoch3, ep);
	return 0;
}
