// SPDX-License-Identifier: Apache-2.0
#ifndef _FILTER_H
#define _FILTER_H

#include <stdint.h>
#include "sentinel_proto.h"

#define SENTINEL_FILTER_MAX_PIDS	64
#define SENTINEL_FILTER_MAX_UIDS	64

struct event_filter {
	int pids[SENTINEL_FILTER_MAX_PIDS];
	int n_pid;
	unsigned int event_mask;
	uint32_t uids[SENTINEL_FILTER_MAX_UIDS];
	int n_uid;
};

void filter_init(struct event_filter *f);
int filter_add_pid(struct event_filter *f, int pid);
int filter_add_uid(struct event_filter *f, uint32_t uid);
int filter_add_type(const char *name, unsigned int *mask);
int filter_apply(const struct event_filter *f,
		 const struct sentinel_event_hdr *hdr);

#endif /* _FILTER_H */
