// SPDX-License-Identifier: Apache-2.0
#ifndef _GENL_CLIENT_H
#define _GENL_CLIENT_H

#include <stddef.h>
#include <stdint.h>

#include "genl_compat.h"

struct genl_client {
	int fd;
	u16 family_id;
};

/*
 * Open a raw NETLINK_GENERIC socket and bind an ephemeral local address.
 * Returns 0, or a negative errno.
 */
int genl_client_init(struct genl_client *c);

/*
 * Resolve the sentinel_km family ID and join its "events" multicast group.
 * Re-negotiation-safe: call again after the module is reloaded. Returns 0
 * or a negative errno.
 */
int genl_client_resolve(struct genl_client *c);

/*
 * Send a doit command to the kernel and receive the reply. cmd is one of
 * SENTINEL_CMD_*. attrs is an optional array of {type, data, len} pairs
 * terminated by {-1}. The reply attrs are returned via reply_buf/size.
 * Returns 0 on success, or a negative errno.
 */
struct genl_attr {
	int type;
	const void *data;
	size_t len;
};

int genl_client_doit(struct genl_client *c, int cmd,
		     const struct genl_attr *attrs,
		     void *reply_buf, size_t reply_size);

void genl_client_close(struct genl_client *c);

#endif /* _GENL_CLIENT_H */
