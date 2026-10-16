# Test targets
UNIT_TESTS := unit_addrmap unit_netlink unit_dispatch unit_conffile unit_checksum \
              unit_udp_checksum unit_ip4_id unit_tun unit_gso unit_pref64 unit_stats \
              unit_packet_io unit_packet_io_lifetime

.PHONY: test
test: $(UNIT_TESTS)
	./unit_addrmap
	./unit_netlink
	./unit_dispatch
	./unit_conffile
	./unit_checksum
	./unit_udp_checksum
	./unit_ip4_id
	./unit_tun
	./unit_packet_io
	./unit_packet_io_lifetime
	./unit_gso
	./unit_pref64
	./unit_stats

TEST_CFLAGS := $(CFLAGS) -Werror
ifeq ($(CC),gcc)
TEST_CFLAGS += -coverage -DCOVERAGE_TESTING
endif

TEST_FILES := test/unit/unit.c

unit_conffile: $(TEST_FILES) test/unit/unit_conffile.c src/conffile.c src/addrmap.c src/tayga.h src/list.h $(GENDIR)/version.h
	$(CC) $(TEST_CFLAGS) -Isrc -I$(GENDIR) -Itest/unit -o $@ $(TEST_FILES) test/unit/unit_conffile.c src/conffile.c src/addrmap.c $(LDFLAGS)

unit_checksum: test/unit/unit_checksum.c src/tayga.h $(GENDIR)/version.h
	$(CC) $(CFLAGS) -Isrc -I$(GENDIR) -o $@ test/unit/unit_checksum.c $(LDFLAGS)

unit_udp_checksum: test/unit/unit_udp_checksum.c src/nat64.c src/addrmap.c src/dynamic.c src/gso.c src/tun.c src/experimental_io.c src/log.c src/stats.c src/tayga.h src/gso.h src/stats.h $(GENDIR)/version.h
	$(CC) $(CFLAGS) -Isrc -I$(GENDIR) -pthread -o $@ test/unit/unit_udp_checksum.c src/nat64.c src/addrmap.c src/dynamic.c src/gso.c src/tun.c src/experimental_io.c src/log.c src/stats.c $(LDFLAGS) -lpthread

unit_ip4_id: test/unit/unit_ip4_id.c src/nat64.c src/addrmap.c src/dynamic.c src/gso.c src/tun.c src/experimental_io.c src/log.c src/stats.c src/tayga.h src/gso.h src/stats.h $(GENDIR)/version.h
	$(CC) $(CFLAGS) -Isrc -I$(GENDIR) -pthread -o $@ test/unit/unit_ip4_id.c src/nat64.c src/addrmap.c src/dynamic.c src/gso.c src/tun.c src/experimental_io.c src/log.c src/stats.c $(LDFLAGS) -lpthread

unit_tun: test/unit/unit_tun.c src/tun.c src/experimental_io.c src/log.c src/stats.c src/tayga.h src/stats.h $(GENDIR)/version.h
	$(CC) $(CFLAGS) -Isrc -I$(GENDIR) -pthread -o $@ test/unit/unit_tun.c src/tun.c src/experimental_io.c src/log.c src/stats.c -Wl,--wrap=write -Wl,--wrap=writev $(LDFLAGS) -lpthread

unit_dispatch: test/unit/unit_dispatch.c src/experimental_io.c src/flow_dispatch.h src/experimental_io.h src/packet_io_lifetime.h $(GENDIR)/version.h
	$(CC) $(CFLAGS) -DDISPATCH_TEST_CLOCK -Isrc -I$(GENDIR) -o $@ test/unit/unit_dispatch.c src/experimental_io.c src/stats.c src/log.c $(LDFLAGS) -pthread

unit_async_tun: test/unit/unit_async_tun.c src/experimental_io.c src/experimental_io.h src/packet_io_lifetime.h $(GENDIR)/version.h
	$(CC) $(CFLAGS) -Isrc -I$(GENDIR) -o $@ test/unit/unit_async_tun.c src/experimental_io.c src/stats.c src/log.c $(LDFLAGS) -pthread

unit_packet_io_lifetime: test/unit/unit_packet_io_lifetime.c src/packet_io_lifetime.h
	$(CC) $(CFLAGS) -Isrc -o $@ test/unit/unit_packet_io_lifetime.c

unit_packet_io: test/unit/unit_packet_io.c src/packet_io.h
	$(CC) $(CFLAGS) -Isrc -o $@ test/unit/unit_packet_io.c

unit_gso: test/unit/unit_gso.c src/gso.c src/addrmap.c src/dynamic.c src/nat64.c src/tun.c src/experimental_io.c src/log.c src/stats.c src/tayga.h src/gso.h src/stats.h $(GENDIR)/version.h
	$(CC) $(CFLAGS) -Isrc -I$(GENDIR) -pthread -o $@ test/unit/unit_gso.c src/gso.c src/addrmap.c src/dynamic.c src/nat64.c src/tun.c src/experimental_io.c src/log.c src/stats.c $(LDFLAGS) -lpthread

unit_pref64: test/unit/unit_pref64.c src/helpers/pref64-discover.c $(GENDIR)/version.h
	$(CC) $(CFLAGS) -DPREF64_NO_MAIN -Isrc -I$(GENDIR) -o $@ test/unit/unit_pref64.c src/helpers/pref64-discover.c $(LDFLAGS)

unit_stats: test/unit/unit_stats.c src/stats.c src/stats_exporter.c src/experimental_io.c src/log.c src/tayga.h src/stats.h $(GENDIR)/version.h
	$(CC) $(CFLAGS) -Isrc -I$(GENDIR) -pthread -o $@ test/unit/unit_stats.c src/stats.c src/stats_exporter.c src/experimental_io.c src/log.c $(LDFLAGS) -lpthread

unit_addrmap: test/unit/unit_addrmap.c src/addrmap.c src/dynamic.c src/conffile.c src/log.c src/tayga.h src/list.h $(GENDIR)/version.h
	$(CC) $(CFLAGS) -DADDRMAP_TEST_HOOK -Isrc -I$(GENDIR) -pthread -o $@ test/unit/unit_addrmap.c src/addrmap.c src/dynamic.c src/conffile.c src/log.c $(LDFLAGS)

unit_netlink: test/unit/unit_netlink.c src/netlink_io.h
	$(CC) $(CFLAGS) -Isrc -o $@ test/unit/unit_netlink.c $(LDFLAGS)

.PHONY: integration
integration: tayga
	-$(IP) netns add tayga-test
	$(IP) netns exec tayga-test python3 test/integration/mapfile.py
	$(IP) netns exec tayga-test python3 test/integration/addressing.py
	$(IP) netns exec tayga-test python3 test/integration/mapping.py
	$(IP) netns exec tayga-test python3 test/integration/translate.py
	$(IP) netns exec tayga-test python3 test/integration/segment.py
ifdef WITH_BIG_ENDIAN
	$(IP) netns exec tayga-test python3 test/integration/bigendian.py
endif
	$(IP) netns del tayga-test

.PHONY: test-portable
test-portable:
	python3 test/portable/run_portable.py

ifeq ($(WITH_URING),1)
test: test-uring
.PHONY: test-uring
test-uring: unit_async_tun
	./unit_async_tun
endif
