// SPDX-License-Identifier: Apache-2.0
/*
 * filter.c -- userspace event filtering.
 *
 * Semi-trusted kernel data defense: the daemon treats every header field as
 * untrusted input and revalidates before dispatching. proto_version and
 * payload_len are checked before any cast against the payload.
 */
#include <string.h>

#include "filter.h"
#include "sentinel_proto.h"

void filter_init(struct event_filter *f)
{
	memset(f, 0, sizeof(*f));
}

int filter_add_pid(struct event_filter *f, int pid)
{
	if (f->n_pid >= (int)(sizeof(f->pids) / sizeof(f->pids[0])))
		return -1;
	f->pids[f->n_pid++] = pid;
	return 0;
}

int filter_add_uid(struct event_filter *f, uint32_t uid)
{
	if (f->n_uid >= (int)(sizeof(f->uids) / sizeof(f->uids[0])))
		return -1;
	f->uids[f->n_uid++] = uid;
	return 0;
}

int filter_add_type(const char *name, unsigned int *mask)
{
	if (!strcmp(name, "execve"))
		*mask |= 1u << SENTINEL_EV_EXECVE;
	else if (!strcmp(name, "openat"))
		*mask |= 1u << SENTINEL_EV_OPENAT;
	else if (!strcmp(name, "connect"))
		*mask |= 1u << SENTINEL_EV_CONNECT;
	else if (!strcmp(name, "mmap") || !strcmp(name, "mmap_exec"))
		*mask |= 1u << SENTINEL_EV_MMAP_EXEC;
	else if (!strcmp(name, "mprotect"))
		*mask |= 1u << SENTINEL_EV_MPROTECT;
	else if (!strcmp(name, "execveat"))
		*mask |= 1u << SENTINEL_EV_EXECVEAT;
	else if (!strcmp(name, "memfd") || !strcmp(name, "memfd_create"))
		*mask |= 1u << SENTINEL_EV_MEMFD_CREATE;
	else if (!strcmp(name, "ptrace"))
		*mask |= 1u << SENTINEL_EV_PTRACE;
	else if (!strcmp(name, "clone3"))
		*mask |= 1u << SENTINEL_EV_CLONE3;
	else if (!strcmp(name, "io_uring_enter"))
		*mask |= 1u << SENTINEL_EV_IO_URING_ENTER;
	else if (!strcmp(name, "finit_module"))
		*mask |= 1u << SENTINEL_EV_FINIT_MODULE;
	else
		return -1;
	return 0;
}

int filter_apply(const struct event_filter *f, const struct sentinel_event_hdr *hdr)
{
	/* Semi-trusted kernel data: never let a bad event_type shift a mask
	 * out of range, regardless of what the caller pre-validated. */
	if (hdr->event_type <= 0 || hdr->event_type >= SENTINEL_EV__MAX)
		return 0;
	if (f->event_mask && !(f->event_mask & (1u << hdr->event_type)))
		return 0;

	if (f->n_pid) {
		int match = 0;
		for (int i = 0; i < f->n_pid; i++)
			if (f->pids[i] == (int)hdr->pid) {
				match = 1;
				break;
			}
		if (!match)
			return 0;
	}
	if (f->n_uid) {
		int match = 0;
		for (int i = 0; i < f->n_uid; i++)
			if (f->uids[i] == hdr->uid) {
				match = 1;
				break;
			}
		if (!match)
			return 0;
	}
	return 1;
}
