# Native helpers have one authoritative location per build variant.
.PHONY: bench-tools fault-shims udp-drain-tools iperf-start-tools
BENCH_TOOLS := udp-drain-guard.so udp-drain-control iperf-start-gate.so iperf-start-control udp-batch-endpoint
FAULT_SHIMS := napi_ioctl_fault offload_ioctl_fault startup_fault udp_endpoint_fault
bench-tools: $(addprefix $(SHIMDIR)/,$(BENCH_TOOLS)) fault-shims
fault-shims: $(addprefix $(SHIMDIR)/,$(addsuffix .so,$(FAULT_SHIMS)))

$(SHIMDIR)/%_fault.so: test/fault/%_fault.c $(BUILDDIR)/build.flags | $(SHIMDIR)
	$(CC) $(CFLAGS) -shared -fPIC -o $@ $< -ldl
$(SHIMDIR)/udp-drain-guard.so: bench/shims/udp-drain-guard.c $(BUILDDIR)/build.flags | $(SHIMDIR)
	$(CC) $(CFLAGS) -shared -fPIC -o $@ $< -ldl
$(SHIMDIR)/udp-drain-control: bench/shims/udp-drain-guard.c $(BUILDDIR)/build.flags | $(SHIMDIR)
	$(CC) $(CFLAGS) -DUDP_DRAIN_CONTROLLER -o $@ $<
$(SHIMDIR)/iperf-start-gate.so: bench/shims/iperf-start-gate.c $(BUILDDIR)/build.flags | $(SHIMDIR)
	$(CC) $(CFLAGS) -shared -fPIC -o $@ $< -ldl
$(SHIMDIR)/iperf-start-control: bench/shims/iperf-start-gate.c $(BUILDDIR)/build.flags | $(SHIMDIR)
	$(CC) $(CFLAGS) -DIPERF_GATE_CONTROLLER -o $@ $<
$(SHIMDIR)/udp-batch-endpoint: bench/shims/udp-batch-endpoint.c $(BUILDDIR)/build.flags | $(SHIMDIR)
	$(CC) $(CFLAGS) -o $@ $<

# Retain old explicit build targets for existing external scripts.
udp-drain-tools: tools/udp-drain-guard.so tools/udp-drain-control
iperf-start-tools: tools/iperf-start-gate.so tools/iperf-start-control
.PHONY: $(addprefix tools/,$(BENCH_TOOLS))
$(addprefix tools/,$(BENCH_TOOLS)): tools/%: $(SHIMDIR)/%
	@cp $< $@

.PHONY: benchmark-script
benchmark-script: $(BUILDDIR)/benchmark-clat.sh
$(BUILDDIR)/benchmark-clat.sh: bench/clat/benchmark-clat.sh $(wildcard bench/clat/lib/*.sh) scripts/assemble-benchmark.py bench/taygabench/common.py | $(BUILDDIR)
	python3 scripts/assemble-benchmark.py > $@.tmp
	chmod +x $@.tmp
	mv $@.tmp $@
