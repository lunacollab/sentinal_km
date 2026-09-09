# SPDX-License-Identifier: GPL-2.0-only
# sentinel_km: kprobe/kretprobe syscall activity monitor.
#
# Usage:  make            # build against the running kernel
#         make KDIR=...   # build against an explicit kernel build tree
#         make checkpatch # static style check on kernel sources

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

modules_install:
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

checkpatch:
	$(KDIR)/scripts/checkpatch.pl --no-tree -f \
		core/*.c hooks/*.c ipc/*.c 2>/dev/null || true

checkpatch-strict:
	$(KDIR)/scripts/checkpatch.pl --no-tree -f --strict \
		core/*.c hooks/*.c ipc/*.c 2>/dev/null || true

# Research/CI artifact: prove whether this toolchain can ship an __ex_table
# fixup as an out-of-tree object (see arch/x86_64/sentinel_fixup_probe.S).
probe-fixup:
	@echo "== assembling the canonical .fixup/__ex_table idiom in .text format fails (gas): =="; \
	if $(CC) -x assembler-with-cpp -c -o /tmp/sentinel_fixup_probe.o \
		arch/x86_64/sentinel_fixup_probe.S 2>/tmp/sentinel_fixup_probe.log; then \
		echo "PROBE PASS: gas accepted the cross-section fixup on this toolchain"; \
	else \
		echo "PROBE FAIL: expected on 6.x/7.x toolchains -- gas cannot resolve .fixup - .text"; \
		head -3 /tmp/sentinel_fixup_probe.log; \
	fi

.PHONY: all modules_install clean checkpatch probe-fixup
