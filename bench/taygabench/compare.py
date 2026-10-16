#!/usr/bin/env python3
"""Compare matching workload groups without pooling incompatible runs."""
from __future__ import annotations

import argparse
import json
import math
import statistics
from pathlib import Path

WORKLOAD_KEYS = ("direction", "clients", "expected_clients", "workload_protocol",
                 "flows_per_client", "rate_per_flow", "duration_seconds",
                 "warmup_seconds", "datagram_size", "block_size", "offlink_mtu",
                 "kernel", "guest_cpu_count", "perf_mode", "perf_scope", "socket_sample_interval",
                 "receiver_drain_seconds", "receiver_drain_method", "receiver_drain_guard_sha256")
BUILD_KEYS = ("git_revision", "source_tree_sha256", "clat_start_sha256", "tayga_sha256")
IDENTITY_KEYS = WORKLOAD_KEYS + BUILD_KEYS
TREATMENT_KEYS = ("offload_requested", "offload_effective", "workers", "tun_txqlen", "forwarding_gro",
                  "pacing_timer_us", "fq_rate", "socket_buffer_bytes", "sender_fq", "sender_fq_flow_limit", "sender_fq_limit", "veth_queues", "sender_fq_topology",
                  "tayga_cpuset", "client_cpuset", "server_cpuset")
METRICS = ("received_mbps", "tayga_cpu_cores", "tayga_core_per_gbps",
           "system_busy_cores", "system_softirq_cores", "tun_drops",
           "tun_tx_drop_percent", "udp_loss_percent", "udp_sender_receiver_gap_percent", "ping_loss_percent",
           "retransmits", "retransmits_per_gbyte", "ping_avg_ms",
           "ping_p95_ms", "ping_p99_ms", "elapsed_s")
OPTIONAL_IDENTITY_KEYS = {"datagram_size", "block_size", "receiver_drain_guard_sha256"}


def results(root: Path):
    out = []
    for path in sorted(set(root.rglob("result.json"))):
        try:
            doc = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            out.append({"path": str(path), "valid": False, "error": str(exc)})
            continue
        doc["path"] = str(path)
        if "guest_cpu_count" not in doc:
            # Earlier captures already saved the guest's /proc/cpuinfo beside
            # the directional results. Do not assume a CPU count if absent.
            try:
                cpuinfo = (path.parent.parent / "cpuinfo.txt").read_text()
                count = sum(line.split(":", 1)[0].strip() == "processor"
                            for line in cpuinfo.splitlines() if ":" in line)
                doc["guest_cpu_count"] = count if count else None
            except OSError:
                doc["guest_cpu_count"] = None
        # Earlier harness versions had no forwarding GRO treatment and never
        # enabled it. Preserve comparisons with those saved results.
        doc.setdefault("perf_scope", "process")
        doc.setdefault("forwarding_gro", "off")
        for key, default in (("pacing_timer_us", 1000), ("fq_rate", "0"),
                             ("socket_buffer_bytes", 0), ("sender_fq", "off"), ("sender_fq_flow_limit", 100),
                             ("sender_fq_limit", 10000), ("veth_queues", 0), ("sender_fq_topology", "single"),
                             ("tayga_cpuset", "all"), ("client_cpuset", "all"), ("server_cpuset", "all"),
                             ("socket_sample_interval", 0), ("receiver_drain_seconds", 0.0)):
            doc.setdefault(key, default)
        doc.setdefault("receiver_drain_method", "legacy" if doc["receiver_drain_seconds"] else "none")
        doc["valid"] = bool(doc.get("capture_valid", False) and doc.get("workload_valid", False))
        if doc["receiver_drain_method"] == "udp-write-eagain-v1" and not doc.get("receiver_drain_guard_sha256"):
            doc["valid"] = False
            doc["degraded_reasons"] = list(doc.get("degraded_reasons", [])) + ["UDP drain guard binary identity is missing"]
        if not doc["valid"]:
            doc["invalid_reason"] = "; ".join(doc.get("degraded_reasons", [])) or "capture/workload validity flag is false or missing"
        out.append(doc)
    return out


def signature(item):
    return tuple(item.get(key) for key in IDENTITY_KEYS)


def treatment(item):
    return tuple(item.get(key) for key in TREATMENT_KEYS)


def display(values, keys):
    return dict(zip(keys, values))


def summarize(items):
    result = {}
    for key in METRICS:
        values = []
        for item in items:
            if key == "udp_loss_percent" and item.get("workload_protocol") == "udp" and item.get("udp_accounting_version") not in (2, 3):
                continue
            value = item.get(key)
            if not item.get("valid") or value is None:
                continue
            try:
                numeric = float(value)
            except (TypeError, ValueError):
                continue
            if math.isfinite(numeric):
                values.append(numeric)
        if values:
            result[key] = {"n": len(values), "median": statistics.median(values),
                           "min": min(values), "max": max(values)}
    return result


def percent_change(old, new):
    if old in (None, 0) or new is None:
        return None
    return (new - old) / old * 100.0


def compare(base, candidate, mode="configuration"):
    if mode not in ("configuration", "build"):
        raise ValueError("mode must be 'configuration' or 'build'")
    base_valid = [item for item in base if item.get("valid")]
    candidate_valid = [item for item in candidate if item.get("valid")]
    warnings = []
    if any(item.get("workload_protocol") == "udp" and item.get("udp_accounting_version") not in (2, 3)
           for item in base_valid + candidate_valid):
        warnings.append("Legacy UDP loss accounting is unsupported; UDP loss metrics are excluded. Reprocess raw iperf reports or rerun with schema 3.")
    if not base_valid or not candidate_valid:
        warnings.append("one side has no valid result.json")

    comparable = {}
    for label, items in (("baseline", base_valid), ("candidate", candidate_valid)):
        missing = set()
        comparable_items = []
        for item in items:
            problems = []
            required_keys = IDENTITY_KEYS if mode == "configuration" else WORKLOAD_KEYS + BUILD_KEYS
            for key in required_keys:
                value = item.get(key)
                if ((value is None and key not in OPTIONAL_IDENTITY_KEYS) or
                    (isinstance(value, str) and value.strip().lower() in ("", "unknown", "n/a"))):
                    problems.append(key + (" (unknown)" if value is not None else ""))
            if item.get("workload_protocol") == "udp" and item.get("datagram_size") is None:
                problems.append("datagram_size")
            if problems:
                missing.update(problems)
            else:
                comparable_items.append(item)
        comparable[label] = comparable_items
        missing = sorted(missing)
        if missing:
            warnings.append(f"{label} has results with incomplete identity; groups skipped: {', '.join(missing)}")

    identity_keys = IDENTITY_KEYS if mode == "configuration" else WORKLOAD_KEYS
    base_groups = {}
    candidate_groups = {}
    for item in comparable["baseline"]:
        base_groups.setdefault(tuple(item.get(key) for key in identity_keys), []).append(item)
    for item in comparable["candidate"]:
        candidate_groups.setdefault(tuple(item.get(key) for key in identity_keys), []).append(item)

    comparisons = []
    for key in sorted(set(base_groups) | set(candidate_groups), key=repr):
        bitems = base_groups.get(key, [])
        citems = candidate_groups.get(key, [])
        label = display(key, identity_keys)
        if not bitems or not citems:
            missing_side = "baseline" if not bitems else "candidate"
            warnings.append(f"workload has no matching {missing_side} group: {label}")
            continue

        btreatments = {treatment(item) for item in bitems}
        ctreatments = {treatment(item) for item in citems}
        missing_treatment = any(
            any(item.get(field) is None or
                (isinstance(item.get(field), str) and
                 item[field].strip().lower() in ("", "unknown", "n/a"))
                for field in TREATMENT_KEYS)
            for item in bitems + citems)
        if missing_treatment:
            warnings.append(f"workload lacks complete treatment identity; group skipped: {label}")
            continue
        if len(btreatments) != 1 or len(ctreatments) != 1:
            warnings.append(f"workload has mixed treatment settings; group skipped: {label}")
            continue

        # A build comparison permits different build identities between arms,
        # but each arm must contain exactly one identified build.
        build_ids = []
        for arm_name, arm in (("baseline", bitems), ("candidate", citems)):
            identities = {tuple(item.get(field) for field in BUILD_KEYS) for item in arm}
            if len(identities) != 1:
                warnings.append(f"{arm_name} has mixed build identities; group skipped: {label}")
                build_ids = []
                break
            build_ids.append(display(next(iter(identities)), BUILD_KEYS))
        if not build_ids:
            continue
        if mode == "configuration" and build_ids[0] != build_ids[1]:
            warnings.append(f"configuration comparison has different builds; use --mode build: {label}")
            continue

        bsummary = summarize(bitems)
        csummary = summarize(citems)
        changes = {}
        for metric in sorted(set(bsummary) & set(csummary)):
            changes[metric + "_percent"] = percent_change(
                bsummary[metric]["median"], csummary[metric]["median"])
        comparisons.append({
            "comparison_mode": mode,
            "workload": label,
            "baseline_build": build_ids[0],
            "candidate_build": build_ids[1],
            "baseline_treatment": display(next(iter(btreatments)), TREATMENT_KEYS),
            "candidate_treatment": display(next(iter(ctreatments)), TREATMENT_KEYS),
            "baseline_summary": bsummary,
            "candidate_summary": csummary,
            "changes_percent": changes,
        })

    if not comparisons and base_valid and candidate_valid:
        warnings.append("no matching, comparable workload groups")
    report = {
        "baseline": None,
        "candidate": None,
        "comparisons": comparisons,
        # Keep the former top-level fields for a single comparable workload.
        "baseline_summary": comparisons[0]["baseline_summary"] if len(comparisons) == 1 else None,
        "candidate_summary": comparisons[0]["candidate_summary"] if len(comparisons) == 1 else None,
        "changes_percent": comparisons[0]["changes_percent"] if len(comparisons) == 1 else None,
        "baseline_treatment": comparisons[0]["baseline_treatment"] if len(comparisons) == 1 else None,
        "candidate_treatment": comparisons[0]["candidate_treatment"] if len(comparisons) == 1 else None,
        "warnings": warnings,
        "baseline_invalid": [item for item in base if not item.get("valid")],
        "candidate_invalid": [item for item in candidate if not item.get("valid")],
    }
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("baseline", type=Path)
    parser.add_argument("candidate", type=Path)
    parser.add_argument("--mode", choices=("configuration", "build"), default="configuration",
                        help="configuration A/B requires identical builds; build A/B permits one distinct build per arm")
    parser.add_argument("--json", type=Path, help="write machine-readable comparison")
    parser.add_argument("--markdown", type=Path, help="write Markdown comparison")
    args = parser.parse_args()
    report = compare(results(args.baseline), results(args.candidate), args.mode)
    report["comparison_mode"] = args.mode
    report["baseline"] = str(args.baseline)
    report["candidate"] = str(args.candidate)
    payload = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.json:
        args.json.write_text(payload)

    rows = ["# Perf session comparison", ""]
    for index, group in enumerate(report["comparisons"], start=1):
        rows.extend([f"## Workload {index}", "", "```json",
                     json.dumps(group["workload"], indent=2, sort_keys=True), "```", "",
                     "| Metric | Baseline median | Candidate median | Change |",
                     "|---|---:|---:|---:|"])
        for metric in sorted(set(group["baseline_summary"]) & set(group["candidate_summary"])):
            b = group["baseline_summary"][metric]["median"]
            c = group["candidate_summary"][metric]["median"]
            change = group["changes_percent"].get(metric + "_percent")
            rendered = "n/a" if change is None or not math.isfinite(change) else f"{change:.3f}%"
            rows.append(f"| {metric} | {b:.6g} | {c:.6g} | {rendered} |")
        rows.extend(["", f"Baseline treatment: `{group['baseline_treatment']}`  ",
                     f"Candidate treatment: `{group['candidate_treatment']}`", ""])
    rows.append("Warnings: " + ("; ".join(report["warnings"]) if report["warnings"] else "none"))
    markdown = "\n".join(rows) + "\n"
    if args.markdown:
        args.markdown.write_text(markdown)
    print(payload, end="")
    return 2 if report["warnings"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
