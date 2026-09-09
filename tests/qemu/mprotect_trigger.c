// SPDX-License-Identifier: Apache-2.0
/*
 * mprotect_trigger.c -- deterministic PROT_EXEC transition for the smoke
 * test. Maps anonymous PROT_READ|PROT_WRITE memory, then flips the whole
 * range to PROT_READ|PROT_EXEC with a single mprotect(2). The sentinel
 * mprotect hook must emit an event for that call. A libc that synthesizes
 * the call via its own wrapper is fine too -- the syscall number is what the
 * probe watches.
 */
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

int main(void)
{
	long ps = sysconf(_SC_PAGESIZE);
	void *p = mmap(NULL, (size_t)ps, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	if (p == MAP_FAILED) {
		perror("mmap");
		return 1;
	}
	if (mprotect(p, (size_t)ps, PROT_READ | PROT_EXEC) != 0) {
		perror("mprotect");
		return 1;
	}
	munmap(p, (size_t)ps);
	return 0;
}
