// SPDX-License-Identifier: Apache-2.0
/*
 * config.c -- daemon config file ("key=value" entries, "#" comments).
 *
 * The file is a defaults source: it is read before any CLI option, so a
 * value given on the command line always wins. Unknown keys and malformed
 * values are fatal (no optimistic parsing), mirroring the userspace
 * "parsed strictly, dropped never" rule from the design docs.
 */
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"

#define CONFIG_LINE_MAX	1024

static int cfg_apply_bool(struct cfg_opts *c, const char *key, int b);
static int set_str(char **dst, const char *s)
{
	char *copy = s ? strdup(s) : NULL;

	if (s && !copy)
		return -1;
	free(*dst);
	*dst = copy;
	return 0;
}

static int parse_bool(const char *v)
{
	if (!strcmp(v, "1") || !strcmp(v, "yes") || !strcmp(v, "true") ||
	    !strcmp(v, "on"))
		return 1;
	if (!strcmp(v, "0") || !strcmp(v, "no") || !strcmp(v, "false") ||
	    !strcmp(v, "off"))
		return 0;
	return -1;
}

static char *ltrim(char *s)
{
	while (*s && isspace((unsigned char)*s))
		s++;
	return s;
}

static void rtrim(char *s)
{
	size_t n = strlen(s);

	while (n && isspace((unsigned char)s[n - 1]))
		s[--n] = '\0';
}

void cfg_init(struct cfg_opts *c)
{
	memset(c, 0, sizeof(*c));
	filter_init(&c->filter);
}

void cfg_fini(struct cfg_opts *c)
{
	free(c->ring_path);
	free(c->apply_spec);
}

int cfg_apply_bool(struct cfg_opts *c, const char *key, int b)
{
	if (!strcmp(key, "json"))
		c->json = b;
	else if (!strcmp(key, "reconnect"))
		c->reconnect = b;
	else if (!strcmp(key, "stats"))
		c->stats = b;
	else if (!strcmp(key, "no-correlate"))
		c->no_corr = b;
	else if (!strcmp(key, "container-labels"))
		c->labels = b;
	else
		return -1;
	return 0;
}

int cfg_apply(struct cfg_opts *c, int opt, const char *arg)
{
	char *end;

	switch (opt) {
	case 'p':
		if (strspn(arg, "0123456789") != strlen(arg) ||
		    filter_add_pid(&c->filter, atoi(arg)) != 0)
			return -1;
		c->had_filter = 1;
		return 0;
	case 'u':
		strtoul(arg, &end, 0);
		if (end == arg || filter_add_uid(&c->filter,
						 (uint32_t)strtoul(arg, NULL, 0)))
			return -1;
		c->had_filter = 1;
		return 0;
	case 't':
		if (filter_add_type(arg, &c->filter.event_mask) != 0)
			return -1;
		c->had_filter = 1;
		return 0;
	case 'j':
		c->json = 1;
		return 0;
	case 'r':
		c->reconnect = 1;
		return 0;
	case 's':
		c->stats = 1;
		return 0;
	case 'a':
		return set_str(&c->apply_spec, arg);
	case 'C':
		c->no_corr = 1;
		return 0;
	case 'L':
		c->labels = 1;
		return 0;
	case 'm':
	case 'R':
		if (set_str(&c->ring_path, (arg && arg[0]) ? arg : NULL) != 0)
			return -1;
		c->transport = (char)opt;
		return 0;
	default:
		return -1;
	}
}

static int cfg_file_key(struct cfg_opts *c, const char *key, const char *val,
			char *err, size_t errsz)
{
	if (!strcmp(key, "pid"))
		return cfg_apply(c, 'p', val);
	if (!strcmp(key, "uid"))
		return cfg_apply(c, 'u', val);
	if (!strcmp(key, "type"))
		return cfg_apply(c, 't', val);
	if (!strcmp(key, "json") || !strcmp(key, "reconnect") ||
	    !strcmp(key, "stats") || !strcmp(key, "no-correlate") ||
	    !strcmp(key, "container-labels")) {
		int b = parse_bool(val);
		if (b < 0) {
			snprintf(err, errsz, "bad boolean value");
			return -1;
		}
		return cfg_apply_bool(c, key, b);
	}
	if (!strcmp(key, "mmap") || !strcmp(key, "ring-read")) {
		/* Strict within a file: one transport only. */
		if (c->transport) {
			snprintf(err, errsz, "conflicting transport");
			return -1;
		}
		return cfg_apply(c, key[0] == 'm' ? 'm' : 'R',
				 val[0] ? val : NULL);
	}
	if (!strcmp(key, "apply"))
		return cfg_apply(c, 'a', val);
	snprintf(err, errsz, "unknown key");
	return -1;
}

int cfg_read_file(struct cfg_opts *c, const char *path)
{
	FILE *fp;
	char line[CONFIG_LINE_MAX];
	unsigned long lineno = 0;

	fp = fopen(path, "r");
	if (!fp) {
		fprintf(stderr, "config: cannot open %s\n", path);
		return -1;
	}
	while (fgets(line, sizeof(line), fp)) {
		char *eq, *key, *val, *hash;
		char err[64];

		lineno++;
		hash = strchr(line, '#');
		if (hash)
			*hash = '\0';
		key = ltrim(line);
		rtrim(key);
		if (!*key)
			continue;
		eq = strchr(key, '=');
		if (!eq) {
			fprintf(stderr, "config: %s:%lu: expected key=value\n",
				path, lineno);
			fclose(fp);
			return -1;
		}
		*eq = '\0';
		key = ltrim(key);
		rtrim(key);
		val = ltrim(eq + 1);
		rtrim(val);
		if (cfg_file_key(c, key, val, err, sizeof(err)) != 0) {
			fprintf(stderr, "config: %s:%lu: %s (%s)\n", path,
				lineno, err[0] ? err : "invalid value", key);
			fclose(fp);
			return -1;
		}
	}
	fclose(fp);
	return 0;
}
