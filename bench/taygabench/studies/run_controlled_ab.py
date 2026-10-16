#!/usr/bin/env python3
import subprocess
import json
import time
import sys

RUNS = 4
DURATION = 30
WARMUP = 5
CLIENTS = 20
WORKERS = 3
RATE = "15M"
DIRECTION = "download"

candidates = [
    ("Atomic-1", "/tmp/ab-benchmark/tayga-atomic-1"),
    ("Block-64", "/tmp/ab-benchmark/tayga-block-64"),
]

print(f"=== Starting Controlled A/B Benchmark ({RUNS} interleaved runs per candidate) ===")
print(f"Config: workers={WORKERS}, clients={CLIENTS}, rate={RATE} per client (300M total), duration={DURATION}s, warmup={WARMUP}s, direction={DIRECTION}")
print(f"{'Candidate':<12} {'Run':<5} {'Throughput (Mbps)':<18} {'CPU Cores':<12} {'Cores/Gbps':<12} {'TUN Drops':<10} {'Retrans':<10}")

results = {"Atomic-1": [], "Block-64": []}

for r in range(1, RUNS + 1):
    for name, bin_path in candidates:
        # Install candidate binary
        subprocess.run(["sudo", "cp", bin_path, "/usr/sbin/tayga"], check=True)
        art_dir = f"/tmp/ab-benchmark/{name.lower()}-run-{r}"
        cmd = [
            "sudo", "env",
            f"DURATION={DURATION}",
            f"WARMUP={WARMUP}",
            f"CLIENTS={CLIENTS}",
            f"WORKERS={WORKERS}",
            "PROTOCOL=tcp",
            f"RATE={RATE}",
            f"DIRECTIONS={DIRECTION}",
            "PERF_MODE=none",
            f"ARTIFACT_DIR={art_dir}",
            "/usr/local/sbin/benchmark-clat.sh"
        ]
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if proc.returncode != 0:
            print(f"Error in {name} run {r}: {proc.stderr}", file=sys.stderr)
            continue
        
        # Parse result.json
        res_file = f"{art_dir}/{DIRECTION}/result.json"
        try:
            with open(res_file) as f:
                data = json.load(f)
            mbps = data.get("received_mbps", 0.0)
            cpu = data.get("tayga_cpu_cores", 0.0)
            cpg = data.get("tayga_core_per_gbps", 0.0)
            drops = data.get("tun_drops", 0)
            retr = data.get("retransmits", 0)
            print(f"{name:<12} {r:<5} {mbps:<18.3f} {cpu:<12.4f} {cpg:<12.4f} {drops:<10} {retr:<10}")
            results[name].append({"mbps": mbps, "cpu": cpu, "cpg": cpg, "drops": drops, "retr": retr})
        except Exception as e:
            print(f"Failed to parse {res_file}: {e}", file=sys.stderr)
        
        time.sleep(2)

print("\n=== SUMMARY STATISTICS ===")
for name in ["Atomic-1", "Block-64"]:
    cpus = [x["cpu"] for x in results[name]]
    mbps = [x["mbps"] for x in results[name]]
    cpgs = [x["cpg"] for x in results[name]]
    avg_cpu = sum(cpus) / len(cpus) if cpus else 0
    avg_mbps = sum(mbps) / len(mbps) if mbps else 0
    avg_cpg = sum(cpgs) / len(cpgs) if cpgs else 0
    min_cpu = min(cpus) if cpus else 0
    max_cpu = max(cpus) if cpus else 0
    print(f"{name}: CPU avg={avg_cpu:.4f} (min={min_cpu:.4f}, max={max_cpu:.4f}), Cores/Gbps={avg_cpg:.4f}, Throughput={avg_mbps:.2f} Mbps")

