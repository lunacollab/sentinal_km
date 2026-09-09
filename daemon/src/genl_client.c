// SPDX-License-Identifier: Apache-2.0
/*
 * genl_client.c -- minimal generic netlink multicast client.
 *
 * Resolves the "sentinel_km" family ID and joins the "events" multicast
 * group. Emits nothing; only receives. If the kernel module is unloaded and
 * reloaded, the family ID may change, so the caller can re-negotiate.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <linux/rtnetlink.h>
#include <sys/socket.h>

#include "genl_client.h"
#include "genl_compat.h"

#define SENTINEL_GENL_NAME	"sentinel_km"
#define SENTINEL_GENL_MCGRP	"events"

static int genl_send_cmd(int fd, u16 type, const char *name)
{
	struct nlmsghdr *nlh;
	struct genlmsghdr *gh;
	struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
	char buf[256];
	int ret;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	nlh->nlmsg_type = type;
	nlh->nlmsg_flags = NLM_F_REQUEST;
	nlh->nlmsg_seq = 1;
	nlh->nlmsg_pid = 0;

	gh = (struct genlmsghdr *)NLMSG_DATA(nlh);
	gh->cmd = CTRL_CMD_GETFAMILY;

	if (name) {
		struct nlattr *na = (struct nlattr *)GENLMSG_DATA(gh);
		int len = strnlen(name, GENL_NAMSIZ - 1) + 1;

		nlh->nlmsg_len += NLA_ALIGN(NLA_HDRLEN + len);
		na->nla_type = CTRL_ATTR_FAMILY_NAME;
		na->nla_len = NLA_HDRLEN + len;
		memcpy((char *)na + NLA_HDRLEN, name, len - 1);
		((char *)na + NLA_HDRLEN)[len - 1] = '\0';
	}

	ret = sendto(fd, buf, nlh->nlmsg_len, 0, (struct sockaddr *)&sa,
		     sizeof(sa));
	if (ret < 0)
		return -errno;
	return 0;
}

static int genl_recv_ack(int fd, u16 *family_id, u32 *mcgrp_id)
{
	char buf[4096];
	struct nlmsghdr *nlh;
	int verified = 0;

	do {
		int ret;

		ret = recv(fd, buf, sizeof(buf), 0);
		if (ret < 0)
			return -errno;

		for (nlh = (struct nlmsghdr *)buf; NLMSG_OK(nlh, ret);
		     nlh = NLMSG_NEXT(nlh, ret)) {
			struct genlmsghdr *gh;
			struct nlattr *na;
			int rem;

			if (nlh->nlmsg_type == NLMSG_ERROR) {
				int err;

				/* An absent family answers GETFAMILY with
				 * NLMSG_ERROR(-ENOENT); the ACK variant
				 * (payload 0) may precede NEWFAMILY. */
				if (nlh->nlmsg_len < NLMSG_LENGTH(sizeof(int)))
					return -EBADMSG;
				memcpy(&err, NLMSG_DATA(nlh), sizeof(err));
				if (err < 0)
					return err;
				continue;
			}
			if (nlh->nlmsg_type != GENL_ID_CTRL)
				continue;
			gh = (struct genlmsghdr *)NLMSG_DATA(nlh);
			if (gh->cmd != CTRL_CMD_NEWFAMILY)
				continue;

			na = (struct nlattr *)GENLMSG_DATA(gh);
			rem = nlh->nlmsg_len - NLMSG_LENGTH(GENL_HDRLEN);
			for (; NLA_OK(na, rem); na = NLA_NEXT(na, rem)) {
				unsigned short type = na->nla_type & NLA_TYPE_MASK;

				if (type == CTRL_ATTR_FAMILY_ID)
					*family_id = *(u16 *)NLA_DATA(na);
				else if (type == CTRL_ATTR_MCAST_GROUPS) {
					struct nlattr *m = (struct nlattr *)NLA_DATA(na);
					int mrem = NLA_PAYLOAD(na);
					for (; NLA_OK(m, mrem); m = NLA_NEXT(m, mrem)) {
						struct nlattr *ma = (struct nlattr *)NLA_DATA(m);
						int arem = NLA_PAYLOAD(m);
						u32 id = 0;
						char mname[GENL_NAMSIZ] = {0};
						for (; NLA_OK(ma, arem); ma = NLA_NEXT(ma, arem)) {
							unsigned short mtype =
								ma->nla_type & NLA_TYPE_MASK;

							if (mtype == CTRL_ATTR_MCAST_GRP_ID)
								id = *(u32 *)NLA_DATA(ma);
							else if (mtype == CTRL_ATTR_MCAST_GRP_NAME)
								strncpy(mname, NLA_DATA(ma), NLA_PAYLOAD(ma));
						}
						if (!strcmp(mname, SENTINEL_GENL_MCGRP))
							*mcgrp_id = id;
					}
				}
			}
			verified = 1;
		}
	} while (!verified);
	return 0;
}

int genl_client_init(struct genl_client *c)
{
	struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
	int ret;

	memset(c, 0, sizeof(*c));
	c->fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
	if (c->fd < 0)
		return -errno;

	sa.nl_groups = 0;
	if (bind(c->fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		ret = -errno;
		goto fail;
	}
	return 0;
fail:
	close(c->fd);
	c->fd = -1;
	return ret;
}

int genl_client_resolve(struct genl_client *c)
{
	u32 group = 0;
	int group_id;
	int ret;

	if (c->fd < 0)
		return -EBADF;

	ret = genl_send_cmd(c->fd, GENL_ID_CTRL, SENTINEL_GENL_NAME);
	if (ret)
		return ret;
	ret = genl_recv_ack(c->fd, &c->family_id, &group);
	if (ret)
		return ret;
	if (!c->family_id || !group) {
		fprintf(stderr, "netlink family/group missing: family=%u group=%u\n",
			c->family_id, group);
		return -ENOENT;
	}
	group_id = (int)group;
	if (group_id <= 0) {
		fprintf(stderr, "netlink multicast group out of range: family=%u group=%u\n",
			c->family_id, group);
		return -EINVAL;
	}

	/* Local address was already bound in init(); joining a multicast group
	 * is done purely via setsockopt. A second bind() to the same socket
	 * fails with EADDRINUSE. */
	if (setsockopt(c->fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, &group_id,
		       sizeof(group_id)) < 0) {
		ret = -errno;
		fprintf(stderr, "NETLINK_ADD_MEMBERSHIP family=%u group=%d: %s\n",
			c->family_id, group_id, strerror(-ret));
		return ret;
	}
	return 0;
}

void genl_client_close(struct genl_client *c)
{
	if (c->fd >= 0)
		close(c->fd);
	c->fd = -1;
}

int genl_client_doit(struct genl_client *c, int cmd,
		     const struct genl_attr *attrs,
		     void *reply_buf, size_t reply_size)
{
	char buf[4096];
	struct nlmsghdr *nlh;
	struct genlmsghdr *gh;
	struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
	socklen_t salen = sizeof(sa);
	int ret;
	u16 seq = (u16)(uintptr_t)c;	/* unique per-client seq */
	const struct genl_attr *a;

	/* Build request */
	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	nlh->nlmsg_type = c->family_id;
	nlh->nlmsg_flags = NLM_F_REQUEST;
	nlh->nlmsg_seq = seq;
	nlh->nlmsg_pid = 0;

	gh = (struct genlmsghdr *)NLMSG_DATA(nlh);
	gh->cmd = cmd;
	gh->version = 0;

	/* Append attributes */
	if (attrs) {
		for (a = attrs; a->type >= 0; a++) {
			struct nlattr *na;
			size_t aligned_len = NLA_ALIGN(a->len);

			if (nlh->nlmsg_len + NLA_HDRLEN + aligned_len > sizeof(buf))
				return -EMSGSIZE;

			na = (struct nlattr *)((char *)nlh + nlh->nlmsg_len);
			na->nla_type = a->type;
			na->nla_len = NLA_HDRLEN + a->len;
			memcpy((char *)na + NLA_HDRLEN, a->data, a->len);

			nlh->nlmsg_len += NLA_HDRLEN + aligned_len;
		}
	}

	/* Send */
	ret = sendto(c->fd, buf, nlh->nlmsg_len, 0, (struct sockaddr *)&sa,
		     sizeof(sa));
	if (ret < 0)
		return -errno;

	/* Receive reply (skip multicast events) */
	for (;;) {
		struct nlmsghdr *rnh;

		ret = recvfrom(c->fd, reply_buf, reply_size, 0,
			       (struct sockaddr *)&sa, &salen);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}

		for (rnh = (struct nlmsghdr *)reply_buf;
		     NLMSG_OK(rnh, (size_t)ret);
		     rnh = NLMSG_NEXT(rnh, ret)) {
			if (rnh->nlmsg_seq != seq)
				continue;	/* another request's reply */

			/* ACK (set commands) or NLMSG_ERROR: cmd payload is int */
			if (rnh->nlmsg_type == NLMSG_ERROR) {
				if (rnh->nlmsg_len >= NLMSG_LENGTH(sizeof(int)))
					return *(int *)NLMSG_DATA(rnh);
				return -EBADMSG;
			}

			if (rnh->nlmsg_type != c->family_id)
				continue;	/* multicast event (seq 0) */
			gh = (struct genlmsghdr *)NLMSG_DATA(rnh);
			if (gh->cmd != cmd)
				continue;
			return 0;
		}
	}
}
