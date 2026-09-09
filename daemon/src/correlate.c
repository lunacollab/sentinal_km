// SPDX-License-Identifier: Apache-2.0
/*
 * correlate.c -- see correlate.h for the contract.
 *
 * The two tables are cut from the same open-addressing cloth: linear probe
 * from pid_hash(pid), first empty slot used, oldest sequence number evicted
 * when the table is full. Both tables share the global monotonic seq so
 * eviction is fair across the two. Everything is lock-free and heap-free:
 * the daemon is single-threaded.
 */
#include <string.h>
#include <sys/mman.h>

#include "correlate.h"
#include "parse.h"

/* Nonexistent index sentinel for "no empty slot found" / "no victim yet". */
#define SLOT_NONE	(~0u)

static unsigned int pid_hash(unsigned int pid)
{
	/* Knuth multiplicative hash; the low bits scramble pid well enough
	 * for a power-of-two table. */
	return pid * 2654435761u;
}

/* ------------------------------------------------------------------ */
/* exec image table                                                    */
/* ------------------------------------------------------------------ */

static const struct correlate_exec *exec_table_get(const struct correlate_state *c,
						   unsigned int pid)
{
	unsigned int start = pid_hash(pid) & (SENTINEL_CORR_EXEC_TABLE - 1);
	unsigned int i;

	for (i = 0; i < SENTINEL_CORR_EXEC_TABLE; i++) {
		const struct correlate_exec_slot *e = &c->exec_slots[
			(start + i) & (SENTINEL_CORR_EXEC_TABLE - 1)];

		if (e->pid == pid)
			return &e->exec;
		if (!e->pid)
			return NULL;	/* probe chain ends at an empty slot */
	}
	return NULL;
}

static void exec_table_put(struct correlate_state *c, unsigned int pid,
			   const char *path, const char *argv0)
{
	unsigned int start = pid_hash(pid) & (SENTINEL_CORR_EXEC_TABLE - 1);
	unsigned int empty = SLOT_NONE, victim = SLOT_NONE;
	unsigned int i;

	for (i = 0; i < SENTINEL_CORR_EXEC_TABLE; i++) {
		const struct correlate_exec_slot *e = &c->exec_slots[
			(start + i) & (SENTINEL_CORR_EXEC_TABLE - 1)];

		if (e->pid == pid) {
			victim = (unsigned int)(e - c->exec_slots);
			break;
		}
		if (!e->pid) {
			if (empty == SLOT_NONE)
				empty = (unsigned int)(e - c->exec_slots);
		} else if (victim == SLOT_NONE ||
			   e->seq < c->exec_slots[victim].seq) {
			victim = (unsigned int)(e - c->exec_slots);
		}
	}
	if (i == SENTINEL_CORR_EXEC_TABLE && empty != SLOT_NONE)
		victim = empty;

	{
		struct correlate_exec_slot *e = &c->exec_slots[victim];

		e->pid = pid;
		e->seq = ++c->seq;
		strncpy(e->exec.path, path, sizeof(e->exec.path) - 1);
		e->exec.path[sizeof(e->exec.path) - 1] = '\0';
		strncpy(e->exec.argv0, argv0, sizeof(e->exec.argv0) - 1);
		e->exec.argv0[sizeof(e->exec.argv0) - 1] = '\0';
	}
}

/* ------------------------------------------------------------------ */
/* memfd table                                                         */
/* ------------------------------------------------------------------ */

static bool memfd_matches(const struct correlate_state *c, unsigned int pid,
			  int fd, uint64_t now)
{
	unsigned int start = pid_hash(pid) & (SENTINEL_CORR_MEMFD_TABLE - 1);
	unsigned int i;

	for (i = 0; i < SENTINEL_CORR_MEMFD_TABLE; i++) {
		const struct correlate_memfd_slot *e = &c->memfd_slots[
			(start + i) & (SENTINEL_CORR_MEMFD_TABLE - 1)];

		if (e->pid == pid) {
			/* Identity match on the descriptor, not just the pid:
			 * ev->dirfd must be exactly the fd memfd_create handed
			 * back for this pid, inside the freshness window. */
			return e->fd == fd && now - e->ts <
			       SENTINEL_CORR_MEMFD_WINDOW_NS;
		}
		if (!e->pid)
			return false;
	}
	return false;
}

static void memfd_table_put(struct correlate_state *c, unsigned int pid,
			    int fd, uint64_t ts)
{
	unsigned int start = pid_hash(pid) & (SENTINEL_CORR_MEMFD_TABLE - 1);
	unsigned int empty = SLOT_NONE, victim = SLOT_NONE;
	unsigned int i;

	for (i = 0; i < SENTINEL_CORR_MEMFD_TABLE; i++) {
		const struct correlate_memfd_slot *e = &c->memfd_slots[
			(start + i) & (SENTINEL_CORR_MEMFD_TABLE - 1)];

		if (e->pid == pid) {
			victim = (unsigned int)(e - c->memfd_slots);
			break;
		}
		if (!e->pid) {
			if (empty == SLOT_NONE)
				empty = (unsigned int)(e - c->memfd_slots);
		} else if (victim == SLOT_NONE ||
			   e->seq < c->memfd_slots[victim].seq) {
			victim = (unsigned int)(e - c->memfd_slots);
		}
	}
	if (i == SENTINEL_CORR_MEMFD_TABLE && empty != SLOT_NONE)
		victim = empty;

	{
		struct correlate_memfd_slot *e = &c->memfd_slots[victim];

		e->pid = pid;
		e->seq = ++c->seq;
		e->fd = fd;
		e->ts = ts;
	}
}

/* ------------------------------------------------------------------ */
/* public entry points                                                 */
/* ------------------------------------------------------------------ */

void correlate_init(struct correlate_state *c, bool enabled)
{
	memset(c, 0, sizeof(*c));
	c->enabled = enabled;
}

void correlate_observe(struct correlate_state *c,
		       const struct sentinel_event_hdr *hdr,
		       const void *payload, struct correlate_annot *out)
{
	memset(out, 0, sizeof(*out));
	if (!c || !c->enabled)
		return;

	switch (hdr->event_type) {
	case SENTINEL_EV_EXECVE: {
		struct sentinel_execve_view v;

		if (!sentinel_execve_parse(payload, hdr->payload_len, &v))
			exec_table_put(c, hdr->pid, v.path, v.argv[0]);
		break;
	}
	case SENTINEL_EV_EXECVEAT: {
		const struct sentinel_ev_execveat *ev =
			(const struct sentinel_ev_execveat *)payload;
		struct sentinel_execve_view v;

		if (sentinel_execveat_parse(payload, hdr->payload_len, &v))
			break;
		exec_table_put(c, hdr->pid, v.path, v.argv[0]);
		/* An fd-relative exec with no path is inherently fileless.
		 * Identity correlation: dirfd must equal an fd this pid minted
		 * with memfd_create -- not merely "some memfd recently". A
		 * memfd is the only way to satisfy AT_EMPTY_PATH from an
		 * anonymous fd, so the empty-path + exact-dirfd match is the
		 * consuming half of that identity. */
		out->fileless = (ev->flags & SENTINEL_AT_EMPTY_PATH) &&
				memfd_matches(c, hdr->pid, ev->dirfd,
					      hdr->timestamp_ns);
		break;
	}
	case SENTINEL_EV_MEMFD_CREATE: {
		const struct sentinel_ev_memfd_create *ev =
			(const struct sentinel_ev_memfd_create *)payload;

		/* Only a live descriptor is an identity key: a failed memfd
		 * (fd < 0) proves intent but cannot be exec'd. */
		if (ev->fd >= 0)
			memfd_table_put(c, hdr->pid, ev->fd,
					hdr->timestamp_ns);
		break;
	}
	case SENTINEL_EV_MMAP_EXEC: {
		const struct sentinel_ev_mmap_exec *ev =
			(const struct sentinel_ev_mmap_exec *)payload;

		out->exec = exec_table_get(c, hdr->pid);
		out->exec_trans = out->exec &&
			(ev->prot & PROT_EXEC) && (ev->prot & PROT_WRITE);
		break;
	}
	case SENTINEL_EV_MPROTECT: {
		const struct sentinel_ev_mprotect *ev =
			(const struct sentinel_ev_mprotect *)payload;

		out->exec = exec_table_get(c, hdr->pid);
		out->exec_trans = out->exec &&
			(ev->prot & PROT_EXEC) && (ev->prot & PROT_WRITE);
		break;
	}
	default:
		break;
	}
}
