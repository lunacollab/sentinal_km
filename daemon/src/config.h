// SPDX-License-Identifier: Apache-2.0
#ifndef _CONFIG_H
#define _CONFIG_H

#include "filter.h"

/*
 * cfg_opts -- merged daemon options, fed from the CLI and/or a config
 * file. The config file always applies first (it is a defaults file), so
 * every later CLI option overrides it.
 */
struct cfg_opts {
	struct event_filter filter;
	int had_filter;
	int json;		/* -j/--json */
	int reconnect;		/* -r/--reconnect (netlink) */
	int stats;		/* -s/--stats */
	int no_corr;		/* -C/--no-correlate */
	int labels;		/* -L/--container-labels */
	/* transport: 0 = netlink, 'm' = mmap ring, 'R' = ring read(2) */
	char transport;
	char *ring_path;	/* owned; set when transport != 0 */
	char *apply_spec;	/* owned; -a/--apply */
};

void cfg_init(struct cfg_opts *c);

/* Release owned strings (ring_path, apply_spec). */
void cfg_fini(struct cfg_opts *c);

/* Apply one option encoded as the getopt-long value character. Returns 0
 * on success or -1 after printing a diagnostic. */
int cfg_apply(struct cfg_opts *c, int opt, const char *arg);

/* Read a key=value config file (see docs/DESIGN.md). Returns 0 on success
 * or -1 after printing a diagnostic naming file:line. */
int cfg_read_file(struct cfg_opts *c, const char *path);

#endif /* _CONFIG_H */
