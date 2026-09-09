/*
 * cglabel_test.c -- container-label resolver unit test.
 *
 * Compiles src/cglabel.c with CGLABEL_TEST so the line parser is exposed;
 * exercises both the parser and the pid->label cache via the public API
 * through a real (loopback-trivial) /proc path is not possible in the unit
 * harness, so the cache path is checked with a synthetic table.
 */
#define CGLABEL_TEST
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "../src/cglabel.c"

static void test_parse_line(void)
{
	char out[64];
	const char *s;

	/* unified hierarchy, docker-style scope */
	s = "/system.slice/docker-abc123.scope\n";
	assert(cglabel_parse_line(s, strlen(s), out, sizeof(out)) == 0);
	assert(!strcmp(out, "docker-abc123.scope"));

	/* kubepods pod scope: last component wins */
	s = "/kubepods.slice/kubepods-burstable.slice/"
	    "kubepods-burstable-pod1234.scope\n";
	assert(cglabel_parse_line(s, strlen(s), out, sizeof(out)) == 0);
	assert(!strcmp(out, "kubepods-burstable-pod1234.scope"));

	/* root cgroup: not a container */
	s = "/\n";
	assert(cglabel_parse_line(s, strlen(s), out, sizeof(out)) != 0);

	/* nested scope: last component is the label */
	s = "/init.scope/child\n";
	assert(cglabel_parse_line(s, strlen(s), out, sizeof(out)) == 0);
	assert(!strcmp(out, "child"));

	/* too-long component -> refuse (small output buffer) */
	s = "/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n";
	assert(cglabel_parse_line(s, strlen(s), out, 8) != 0);
	assert(cglabel_parse_line(s, strlen(s), out, 0) != 0);

	/* empty / malformed */
	assert(cglabel_parse_line("", 0, out, sizeof(out)) != 0);
	assert(cglabel_parse_line("0:", 2, out, sizeof(out)) != 0);
}

static unsigned int slot_for(unsigned int pid)
{
	unsigned int h = (pid * 2654435761u) ^ ((pid * 2654435761u) >> 16);
	return h & (SENTINEL_CGLABEL_TABLE - 1);
}

static void test_cache_hit(void)
{
	struct cglabel_state s;
	unsigned int slot = slot_for(7);

	cglabel_init(&s);
	assert(s.slots[slot].pid == 0);	/* empty */
	cglabel_put(&s, 7, "docker-x");
	assert(s.slots[slot].pid == 7);
	assert(!strcmp(s.slots[slot].label, "docker-x"));

	/* update for same pid replaces the label in place */
	cglabel_put(&s, 7, "docker-y");
	assert(s.slots[slot].pid == 7);
	assert(!strcmp(s.slots[slot].label, "docker-y"));

	/* clearing a label keeps the pid cached but makes resolve() bail */
	cglabel_put(&s, 7, NULL);
	assert(s.slots[slot].pid == 7);
	assert(s.slots[slot].label[0] == '\0');
}

int main(void)
{
	test_parse_line();
	test_cache_hit();
	puts("cglabel_test: OK");
	return 0;
}
