// SPDX-License-Identifier: Apache-2.0
/*
 * trace_triggers.c -- fire every hooked syscall exactly once, deterministically.
 *
 * Drives: execve, execveat (both an ordinary AT_FDCWD call in a child and a
 * genuinely fileless one via memfd_execveat below), openat, connect, mmap of
 * executable memory, mprotect RW->R|X, ptrace, memfd_create, clone3, and
 * io_uring_enter. finit_module is exercised in syscall form: a real memfd
 * image refeed plus a bare -1 descriptor, both failing as the probe wants
 * (an EPERM'd/ENOEXEC'd finit_module still emits).
 *
 * The memfd_execveat() tail is the payoff for the wire v5 work: it mints a
 * memfd, writes this vendor-neutral 131-byte static ELF into it, then
 * execveate()s the anonymous fd. The daemon must annotate that single event
 * "fileless" because memfd_create and the AT_EMPTY_PATH exec happen in the
 * same pid inside the 30 s window. The tiny program just exits 0.
 *
 * x86_64-only (the memfd ELF and the 322/319/435/426/313 syscall numbers
 * assume it).
 */
#include <errno.h>
#include <fcntl.h>
#include <linux/sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <arpa/inet.h>

#ifndef SYS_execveat
#define SYS_execveat	322
#endif
#ifndef SYS_memfd_create
#define SYS_memfd_create 319
#endif
#ifndef SYS_clone3
#define SYS_clone3	435
#endif
#ifndef SYS_io_uring_setup
#define SYS_io_uring_setup 425
#endif
#ifndef SYS_io_uring_enter
#define SYS_io_uring_enter 426
#endif
#ifndef SYS_finit_module
#define SYS_finit_module 313
#endif
#ifndef SYS_close
#define SYS_close	3
#endif
#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH	0x1000
#endif
#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC	0x0001U
#endif
#ifndef IORING_ENTER_GETEVENTS
#define IORING_ENTER_GETEVENTS (1U << 0)
#endif

/* ET_EXEC, one R|X PT_LOAD at 0x400000, entry 0x400078, exits(0). */
static const unsigned char exit0_elf[0x83] = {
	/* e_ident */
	0x7f, 'E', 'L', 'F', 0x02, 0x01, 0x01, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	/* e_type, e_machine, e_version */
	0x02, 0x00, 0x3e, 0x00, 0x01, 0x00, 0x00, 0x00,
	/* e_entry = 0x400078 */
	0x78, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
	/* e_phoff = 0x40 */
	0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	/* e_shoff = 0 */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	/* e_flags = 0 */
	0x00, 0x00, 0x00, 0x00,
	/* e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx */
	0x40, 0x00, 0x38, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	/* phdr at 0x40: PT_LOAD, R|X, offset 0, vaddr 0x400000 */
	0x01, 0x00, 0x00, 0x00,	/* p_type */
	0x05, 0x00, 0x00, 0x00,	/* p_flags */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* p_offset */
	0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, /* p_vaddr */
	0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, /* p_paddr */
	0x83, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* p_filesz */
	0x83, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* p_memsz */
	0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* p_align */
	/* entry at 0x78: xor rdi,rdi; mov eax,60; syscall */
	0x48, 0x31, 0xff,
	0xb8, 0x3c, 0x00, 0x00, 0x00,
	0x0f, 0x05,
};

static void run_execve(void)
{
	pid_t p = fork();

	if (p == 0) {
		execl("/bin/true", "true", (char *)NULL);
		_exit(127);
	}
	waitpid(p, NULL, 0);
}

static void run_execveat(void)
{
	pid_t p = fork();

	if (p == 0) {
		char *const av[] = { "true", NULL };
		char *const ev[] = { NULL };

		/* AT_FDCWD + absolute path: the ordinary execveat flavour. */
		syscall(SYS_execveat, AT_FDCWD, "/bin/true", av, ev, 0);
		_exit(127);
	}
	waitpid(p, NULL, 0);
}

static void run_openat(void)
{
	openat(AT_FDCWD, "/etc/hostname", O_RDONLY);
}

static void run_connect(void)
{
	struct sockaddr_in sa;
	int fd = socket(AF_INET, SOCK_STREAM, 0);

	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(1);
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	/* The connect fails (nothing listens), but the syscall still fires. */
	(void)connect(fd, (struct sockaddr *)&sa, sizeof(sa));
	close(fd);
}

static void run_mmap_exec(void)
{
	long ps = sysconf(_SC_PAGESIZE);
	void *p = mmap(NULL, (size_t)ps, PROT_READ | PROT_EXEC,
		       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	if (p != MAP_FAILED)
		munmap(p, (size_t)ps);
}

static void run_mprotect(void)
{
	long ps = sysconf(_SC_PAGESIZE);
	void *p = mmap(NULL, (size_t)ps, PROT_READ | PROT_WRITE,
		       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	if (p == MAP_FAILED)
		return;
	mprotect(p, (size_t)ps, PROT_READ | PROT_EXEC);
	munmap(p, (size_t)ps);
}

static void run_ptrace(void)
{
	pid_t p = fork();

	if (p == 0) {
		/* PT_TRACEME is EPERM when nobody can trace us (normal VM) but
		 * 0 under a supervisor (e.g. running inside WSL). Either way
		 * the syscall fires -- ptrace events are emitted
		 * unconditionally. Forked so a nonzero return can never trap
		 * the main thread's later execs. */
		ptrace(PTRACE_TRACEME, 0, 0, 0);
		_exit(0);
	}
	waitpid(p, NULL, 0);
}

/* Executes ourselves from a memfd. Only returns on failure; on success the
 * process is replaced by the tiny "exit 0" image above. */
static void run_fileless_execveat(void)
{
	char *const av[] = { "flexec", NULL };
	char *const ev[] = { NULL };
	int fd = syscall(SYS_memfd_create, "flexec", MFD_CLOEXEC);
	ssize_t n;

	if (fd < 0) {
		perror("memfd_create");
		exit(1);
	}
	n = write(fd, exit0_elf, sizeof(exit0_elf));
	if (n != (ssize_t)sizeof(exit0_elf)) {
		perror("write(memfd)");
		exit(1);
	}
	if (syscall(SYS_execveat, fd, "", av, ev, AT_EMPTY_PATH) != 0) {
		perror("execveat(AT_EMPTY_PATH)");
		exit(1);
	}
	exit(0);	/* not reached when the exec succeeds */
}

/* Real clone3 with an exit_signal: the kernel mints a child, the kretprobe
 * fires for parent and child. Reaped below, so no zombies. */
static void run_clone3(void)
{
	struct clone_args ca;

	memset(&ca, 0, sizeof(ca));
	ca.exit_signal = SIGCHLD;
	{
		long child = syscall(SYS_clone3, &ca, sizeof(ca), 0, 0, 0, 0, 0);

		if (child == 0) {
			/* child side: leave immediately, do not recurse */
			_exit(0);
		}
		if (child > 0)
			waitpid((pid_t)child, NULL, 0);
	}
	/* Degenerate shape: NULL uargs still charges the entry hook (the kernel
	 * fails it with EFAULT), exercising the args_size=0 clamp path. */
	(void)syscall(SYS_clone3, NULL, 0, 0, 0, 0, 0, 0);
}

/* io_uring_enter pairs submitted/completed on the ret side. The ring is
 * created with zero SQEs and never has work, so both calls return
 * immediately -- the pair is (0, X) which is exactly the observables the
 * hook is for. */
static void run_io_uring_enter(void)
{
	long fd = syscall(SYS_io_uring_setup, 1, NULL);

	if (fd < 0)
		return;	/* io_uring unavailable; nothing to trigger */
	(void)syscall(SYS_io_uring_enter, fd, 0, 0, 0, NULL);
	(void)syscall(SYS_io_uring_enter, fd, 0, 1, IORING_ENTER_GETEVENTS,
		      NULL);
	syscall(SYS_close, fd);
}

/* finit_module never succeeds here, but the hook emits on both outcomes.
 * The memfd refeed gives the daemon an fd it saw minted by memfd_create in
 * the same pid, i.e. a load attempt from a sealable descriptor. */
static void run_finit_module(void)
{
	int fd = syscall(SYS_memfd_create, "fmod", MFD_CLOEXEC);

	if (fd >= 0) {
		ssize_t n = write(fd, "not-a-module", 12);

		if (n < 0)
			n = 0;	/* content is irrelevant; only the attempt is */
		(void)syscall(SYS_finit_module, fd, 0);
		syscall(SYS_close, fd);
	}
	(void)syscall(SYS_finit_module, -1, 0);
}

int main(void)
{
	run_openat();
	run_connect();
	run_mmap_exec();
	run_mprotect();
	run_ptrace();
	run_execve();
	run_execveat();
	run_clone3();
	run_io_uring_enter();
	run_finit_module();
	run_fileless_execveat();
	return 1;	/* unreached: the fileless exec replaces us */
}
