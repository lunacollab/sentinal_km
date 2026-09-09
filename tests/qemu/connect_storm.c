// SPDX-License-Identifier: Apache-2.0
/*
 * connect_storm.c -- fire connect(2) repeatedly so the smoke test's
 * "one event per type" assert can never miss it to a single ring-drop.
 *
 * The per-CPU ring is a bounded buffer (256 slots by default) with 100ms
 * drains; during the compile floods around this trigger a handful of the
 * earliest events are routinely overwritten. One lone connect() is exactly
 * the event that can be lost. This fires 128 direct syscalls to a closed
 * loopback port (ECONNREFUSED still counts: the kretprobe arms on entry)
 * with a 2ms pause between attempts, so >=1 event survives any plausible
 * drop window while still completing in ~0.3s.
 *
 * Direct syscall() instead of the libc wrapper keeps exactly one syscall
 * per iteration and works under any errno.
 */
#define _GNU_SOURCE
#include <netinet/in.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

#define SENTINEL_CONNECT_STORM	128
#define SENTINEL_CONNECT_GAP_US	2000

int main(void)
{
	struct sockaddr_in sa = { 0 };

	sa.sin_family = AF_INET;
	sa.sin_port = htons(1);
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	for (int i = 0; i < SENTINEL_CONNECT_STORM; i++) {
		int fd = (int)syscall(SYS_socket, AF_INET, SOCK_STREAM, 0);

		if (fd < 0)
			continue;
		(void)syscall(SYS_connect, fd, &sa, sizeof(sa));
		(void)syscall(SYS_close, fd);
		if (i < SENTINEL_CONNECT_STORM - 1)
			usleep(SENTINEL_CONNECT_GAP_US);
	}
	return 0;
}
