# Unit objects, libraries, binaries and fixtures are isolated per BUILDDIR.
UNIT_TESTS := unit_addrmap unit_mapping unit_netlink unit_dispatch unit_conffile unit_checksum \
              unit_udp_checksum unit_ip4_id unit_tun unit_gso unit_pref64 unit_stats \
              unit_packet_io unit_packet_io_lifetime unit_icmp_rate_limit
TEST_BINS := $(addprefix $(TESTBINDIR)/,$(UNIT_TESTS))
TEST_LIB := $(BUILDDIR)/libtayga_test.a
TEST_SOURCES := $(filter-out src/tayga.c,$(SOURCES))
TEST_OBJS := $(patsubst src/%.c,$(TESTOBJDIR)/lib/%.o,$(TEST_SOURCES))

$(TESTOBJDIR)/lib/%.o: src/%.c $(GENDIR)/version.h $(BUILDDIR)/build.flags
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(TEST_CFLAGS) -MMD -MP -c -o $@ $<

$(TEST_LIB): $(TEST_OBJS)
	$(AR) rcs $@ $^

$(TESTOBJDIR)/%.o: test/unit/%.c $(GENDIR)/version.h $(BUILDDIR)/build.flags | $(TESTOBJDIR)
	$(CC) $(CPPFLAGS) $(TEST_CFLAGS) -DTAYGA_TEST_ROOT=\"$(TOPDIR)\" -Itest/unit -MMD -MP -c -o $@ $<

$(TESTOBJDIR)/addrmap-hook.o: src/addrmap.c $(GENDIR)/version.h $(BUILDDIR)/build.flags | $(TESTOBJDIR)
	$(CC) $(CPPFLAGS) $(TEST_CFLAGS) -DADDRMAP_TEST_HOOK -MMD -MP -c -o $@ $<

$(TESTOBJDIR)/dispatch-clock.o: src/experimental_io.c $(GENDIR)/version.h $(BUILDDIR)/build.flags | $(TESTOBJDIR)
	$(CC) $(CPPFLAGS) $(TEST_CFLAGS) -DDISPATCH_TEST_CLOCK -MMD -MP -c -o $@ $<

$(TESTOBJDIR)/pref64.o: src/helpers/pref64-discover.c $(GENDIR)/version.h $(BUILDDIR)/build.flags | $(TESTOBJDIR)
	$(CC) $(CPPFLAGS) $(TEST_CFLAGS) -DPREF64_NO_MAIN -MMD -MP -c -o $@ $<

$(TESTBINDIR)/unit_addrmap: $(TESTOBJDIR)/unit_addrmap.o $(TESTOBJDIR)/addrmap-hook.o $(TEST_LIB) | $(TESTBINDIR)
	$(CC) -o $@ $^ $(TEST_LDFLAGS) $(LDLIBS)
$(TESTBINDIR)/unit_dispatch: $(TESTOBJDIR)/unit_dispatch.o $(TESTOBJDIR)/dispatch-clock.o $(TEST_LIB) | $(TESTBINDIR)
	$(CC) -o $@ $^ $(TEST_LDFLAGS) $(LDLIBS)
$(TESTBINDIR)/unit_conffile: $(TESTOBJDIR)/unit_conffile.o $(TESTOBJDIR)/unit.o $(TEST_LIB) | $(TESTBINDIR)
	$(CC) -o $@ $^ $(TEST_LDFLAGS) $(LDLIBS)
$(TESTBINDIR)/unit_tun: $(TESTOBJDIR)/unit_tun.o $(TEST_LIB) | $(TESTBINDIR)
	$(CC) -o $@ $^ -Wl,--wrap=write -Wl,--wrap=writev $(TEST_LDFLAGS) $(LDLIBS)

STANDALONE_TESTS := unit_icmp_rate_limit unit_packet_io unit_packet_io_lifetime unit_netlink unit_checksum
$(addprefix $(TESTBINDIR)/,$(STANDALONE_TESTS)): $(TESTBINDIR)/%: $(TESTOBJDIR)/%.o | $(TESTBINDIR)
	$(CC) -o $@ $< $(TEST_LDFLAGS)
$(TESTBINDIR)/unit_pref64: $(TESTOBJDIR)/unit_pref64.o $(TESTOBJDIR)/pref64.o | $(TESTBINDIR)
	$(CC) -o $@ $^ $(TEST_LDFLAGS)

$(TESTBINDIR)/%: $(TESTOBJDIR)/%.o $(TEST_LIB) | $(TESTBINDIR)
	$(CC) -o $@ $^ $(TEST_LDFLAGS) $(LDLIBS)

# Compatibility entrypoints for documented commands and existing CI.
.PHONY: $(UNIT_TESTS) unit_async_tun
$(UNIT_TESTS) unit_async_tun: %: $(TESTBINDIR)/%
	@cp $< $@

.PHONY: test test-portable test-linux-tools test-uring integration system-test
# Run in the output directory: legacy fixture filenames cannot dirty sources.
test: $(TEST_BINS)
	@mkdir -p $(TESTOUTDIR)/unit
	@set -eu; for binary in $(abspath $(TEST_BINS)); do (cd $(TESTOUTDIR)/unit && "$$binary"); done

test-portable: $(BUILDDIR)/pref64-discover
	TAYGA_PREF64_DISCOVER="$(abspath $(BUILDDIR)/pref64-discover)" python3 test/portable/run_portable.py

test-linux-tools: bench-tools
	python3 -m unittest discover -s bench/tests -p 'test_*.py'

ifeq ($(WITH_URING),1)
test: test-uring
test-uring: $(TESTBINDIR)/unit_async_tun
	$(TESTBINDIR)/unit_async_tun
endif

integration: tayga
	TAYGA_BIN="$(abspath $(BUILDDIR)/tayga)" TAYGA_TEST_OUT="$(abspath $(TESTOUTDIR)/integration)" IP="$(IP)" python3 test/run-integration.py $(if $(WITH_BIG_ENDIAN),--big-endian,)

system-test: tayga pref64-discover fault-shims
	python3 test/run-system.py --binary "$(abspath $(BUILDDIR)/tayga)" --output "$(abspath $(TESTOUTDIR)/system)"

-include $(wildcard $(TESTOBJDIR)/*.d) $(TEST_OBJS:.o=.d)

.SECONDARY: $(TEST_OBJS) $(addprefix $(TESTOBJDIR)/,$(addsuffix .o,$(UNIT_TESTS)))

# On-demand fixture for the independent TCP checksum-completion wire gate.
$(TESTOBJDIR)/tcp_split_tail.o: test/system/tcp_split_tail.c $(GENDIR)/version.h $(BUILDDIR)/build.flags | $(TESTOBJDIR)
	$(CC) $(CPPFLAGS) $(TEST_CFLAGS) -MMD -MP -c -o $@ $<
$(TESTBINDIR)/tcp_split_tail: $(TESTOBJDIR)/tcp_split_tail.o $(TEST_LIB) | $(TESTBINDIR)
	$(CC) -o $@ $^ $(TEST_LDFLAGS) $(LDLIBS)

# libFuzzer smoke run (needs clang): `make fuzz-check` builds every harness in
# test/fuzz with ASan+UBSan and runs it for FUZZ_TIME seconds.
FUZZ_TIME ?= 10
FUZZ_TARGETS := fuzz_pkt4 fuzz_pkt6 fuzz_gso fuzz_pref64 fuzz_conffile fuzz_flow fuzz_maps
FUZZ_FLAGS := -O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined -fno-sanitize-recover=all
.PHONY: fuzz-check
fuzz-check:
	@command -v clang >/dev/null || { echo 'fuzz-check requires clang'; exit 1; }
	$(MAKE) CC=clang BUILDDIR=$(BUILDDIR)/fuzz CFLAGS='$(FUZZ_FLAGS) -fsanitize=fuzzer-no-link' LDFLAGS='' fuzz-run

.PHONY: fuzz-run
fuzz-run: $(TEST_LIB) $(TESTOBJDIR)/pref64.o
	@mkdir -p $(BUILDDIR)/fuzz-bin $(BUILDDIR)/fuzz-run
	@set -eu; for t in fuzz_pkt4 fuzz_pkt6 fuzz_gso fuzz_conffile fuzz_flow fuzz_maps; do \
	  $(CC) $(FUZZ_FLAGS) -fsanitize=fuzzer -Isrc -I$(GENDIR) -Itest/fuzz -o $(BUILDDIR)/fuzz-bin/$$t test/fuzz/$$t.c $(TEST_LIB) $(LDLIBS); \
	done
	@$(CC) $(FUZZ_FLAGS) -fsanitize=fuzzer -o $(BUILDDIR)/fuzz-bin/fuzz_pref64 test/fuzz/fuzz_pref64.c $(TESTOBJDIR)/pref64.o
	@python3 test/fuzz/make_seeds.py $(BUILDDIR)/fuzz-seeds >/dev/null
	@set -eu; for t in $(FUZZ_TARGETS); do \
	  echo "== $$t ($(FUZZ_TIME)s)"; mkdir -p $(BUILDDIR)/fuzz-run/$$t; seeds=; \
	  [ -d $(BUILDDIR)/fuzz-seeds/$$t ] && seeds=$(abspath $(BUILDDIR))/fuzz-seeds/$$t; \
	  [ -d test/fuzz/regress/$$t ] && seeds="$$seeds $(abspath test/fuzz/regress)/$$t"; \
	  (cd $(BUILDDIR)/fuzz-run/$$t && ASAN_OPTIONS=detect_leaks=1 $(abspath $(BUILDDIR))/fuzz-bin/$$t -max_total_time=$(FUZZ_TIME) -max_len=4096 -print_final_stats=0 -close_fd_mask=3 . $$seeds >/dev/null); \
	done; echo 'fuzz-check passed'
