CLANG ?= clang
CC ?= cc
MULTIARCH ?= $(shell $(CC) -dumpmachine 2>/dev/null)
BPF_CFLAGS ?= -O2 -g -Wall -Wextra -Werror -target bpf $(if $(MULTIARCH),-I/usr/include/$(MULTIARCH)) -D__TARGET_ARCH_x86
CTL_CFLAGS ?= -O2 -Wall -Wextra -Werror

all: tayga_tc_fastpath.o tayga-tc-ctl

tayga_tc_fastpath.o: tayga_tc_fastpath.c tayga_tc_maps.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

tayga-tc-ctl: tayga_tc_ctl.c tayga_tc_maps.h
	$(CC) $(CTL_CFLAGS) $< -o $@

test: all
	./tayga-tc-ctl --self-test

clean:
	rm -f tayga_tc_fastpath.o tayga-tc-ctl

.PHONY: all test clean
