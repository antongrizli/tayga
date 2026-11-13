CLANG ?= clang
MULTIARCH ?= $(shell $(CC) -dumpmachine 2>/dev/null)
BPF_CFLAGS ?= -O2 -g -Wall -Wextra -Werror -target bpf $(if $(MULTIARCH),-I/usr/include/$(MULTIARCH)) -D__TARGET_ARCH_x86

all: tayga_tc_fastpath.o

tayga_tc_fastpath.o: tayga_tc_fastpath.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

clean:
	rm -f tayga_tc_fastpath.o

.PHONY: all clean
