# Benchmark tooling and shims
.PHONY: udp-drain-tools
udp-drain-tools: tools/udp-drain-guard.so tools/udp-drain-control

tools/udp-drain-guard.so: bench/shims/udp-drain-guard.c
	$(CC) -O2 -Wall -Wextra -fPIC -shared -o $@ $< -ldl

tools/udp-drain-control: bench/shims/udp-drain-guard.c
	$(CC) -O2 -Wall -Wextra -DUDP_DRAIN_CONTROLLER -o $@ $<

.PHONY: iperf-start-tools
iperf-start-tools: tools/iperf-start-gate.so tools/iperf-start-control

tools/iperf-start-gate.so: bench/shims/iperf-start-gate.c
	$(CC) $(CFLAGS) -shared -fPIC -o $@ $< -ldl

tools/iperf-start-control: bench/shims/iperf-start-gate.c
	$(CC) $(CFLAGS) -DIPERF_GATE_CONTROLLER -o $@ $<
